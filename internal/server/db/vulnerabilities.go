package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
)

// UpsertVulnerability writes a freshly-fetched vuln record. fetchedAt stamps
// when we last pulled it from OSV; it drives the freshness check in GetFreshVulns.
func (s *DB) UpsertVulnerability(ctx context.Context, v matcher.Vulnerability, canonicalID string, severityScore float64, severitySource string, fetchedAt time.Time) error {
	aliases, _ := json.Marshal(v.Aliases)
	upstream, _ := json.Marshal(v.Upstream)

	var publishedAt, modifiedAt string
	if !v.PublishedAt.IsZero() {
		publishedAt = v.PublishedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !v.ModifiedAt.IsZero() {
		modifiedAt = v.ModifiedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	fetched := fetchedAt.UTC().Format("2006-01-02T15:04:05Z")

	_, err := s.conn.ExecContext(ctx, `
		INSERT INTO vulnerabilities
			(id, canonical_id, aliases, upstream, summary, details, published_at, modified_at, source, raw, severity_score, severity_source, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			canonical_id    = excluded.canonical_id,
			aliases         = excluded.aliases,
			upstream        = excluded.upstream,
			summary         = excluded.summary,
			details         = excluded.details,
			published_at    = excluded.published_at,
			modified_at     = excluded.modified_at,
			source          = excluded.source,
			raw             = excluded.raw,
			severity_score  = excluded.severity_score,
			severity_source = excluded.severity_source,
			fetched_at      = excluded.fetched_at`,
		v.ID, canonicalID, string(aliases), string(upstream),
		v.Summary, v.Details, publishedAt, modifiedAt, v.Source, string(v.Raw),
		severityScore, severitySource, fetched,
	)
	return err
}

// GetFreshVulns splits ids into cached (stored and fetched within maxAge) and
// stale (missing or older). The vulnerabilities table is the cache: anything
// fetched recently is reused instead of hitting OSV again.
func (s *DB) GetFreshVulns(ctx context.Context, ids []string, maxAge time.Duration) (map[string]matcher.Vulnerability, []string, error) {
	cached := make(map[string]matcher.Vulnerability)
	if len(ids) == 0 {
		return cached, nil, nil
	}

	cutoff := time.Now().UTC().Add(-maxAge).Format("2006-01-02T15:04:05Z")
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, cutoff)

	query := `SELECT id, aliases, upstream, summary, details, published_at, modified_at, source, raw
		FROM vulnerabilities
		WHERE id IN (` + strings.Join(placeholders, ",") + `) AND fetched_at <> '' AND fetched_at >= ?`

	rows, err := s.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("reading cached vulns: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v matcher.Vulnerability
		var aliasesJSON, upstreamJSON, publishedAt, modifiedAt, raw string
		if err := rows.Scan(&v.ID, &aliasesJSON, &upstreamJSON, &v.Summary, &v.Details,
			&publishedAt, &modifiedAt, &v.Source, &raw); err != nil {
			return nil, nil, err
		}
		json.Unmarshal([]byte(aliasesJSON), &v.Aliases)
		json.Unmarshal([]byte(upstreamJSON), &v.Upstream)
		if publishedAt != "" {
			v.PublishedAt, _ = time.Parse("2006-01-02T15:04:05Z", publishedAt)
		}
		if modifiedAt != "" {
			v.ModifiedAt, _ = time.Parse("2006-01-02T15:04:05Z", modifiedAt)
		}
		v.Raw = json.RawMessage(raw)
		cached[v.ID] = v
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	var stale []string
	for _, id := range ids {
		if _, ok := cached[id]; !ok {
			stale = append(stale, id)
		}
	}
	return cached, stale, nil
}

func (s *DB) ReplaceEndpointVulnerabilities(ctx context.Context, endpointID string, matches []matcher.Match, now time.Time) error {
	// Upsert keeps the original discovery date: every column is overwritten on
	// conflict except discovered_at, so a vuln keeps the timestamp from when it
	// was first seen on this endpoint. New rows get `now`.
	nowStr := now.UTC().Format("2006-01-02T15:04:05Z")
	for _, m := range matches {
		dirs, _ := json.Marshal(m.Dirs)
		_, err := s.conn.ExecContext(ctx, `
			INSERT INTO endpoint_vulnerabilities
				(endpoint_id, purl, vulnerability_id, package_name, package_version, package_ecosystem, dirs,
				 exposure_score, package_scope, package_kind, discovered_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(endpoint_id, purl, vulnerability_id) DO UPDATE SET
				package_name      = excluded.package_name,
				package_version   = excluded.package_version,
				package_ecosystem = excluded.package_ecosystem,
				dirs              = excluded.dirs,
				exposure_score    = excluded.exposure_score,
				package_scope     = excluded.package_scope,
				package_kind      = excluded.package_kind,
				discovered_at     = CASE
					WHEN endpoint_vulnerabilities.discovered_at = ''
					THEN excluded.discovered_at
					ELSE endpoint_vulnerabilities.discovered_at END`,
			endpointID, m.Purl, m.Vulnerability.ID,
			m.PackageName, m.PackageVersion, m.PackageEcosystem, string(dirs),
			m.ExposureScore, m.PackageScope, m.PackageKind, nowStr,
		)
		if err != nil {
			return fmt.Errorf("upserting endpoint vuln: %w", err)
		}
	}

	// Remove vulns no longer present in this scan (e.g. the package was upgraded).
	if len(matches) == 0 {
		if _, err := s.conn.ExecContext(ctx,
			`DELETE FROM endpoint_vulnerabilities WHERE endpoint_id = ?`, endpointID); err != nil {
			return fmt.Errorf("clearing endpoint vulns: %w", err)
		}
		return nil
	}

	args := make([]any, 0, 1+2*len(matches))
	args = append(args, endpointID)
	var values strings.Builder
	for idx, m := range matches {
		if idx > 0 {
			values.WriteString(",")
		}
		values.WriteString("(?,?)")
		args = append(args, m.Purl, m.Vulnerability.ID)
	}
	query := `DELETE FROM endpoint_vulnerabilities
		WHERE endpoint_id = ? AND (purl, vulnerability_id) NOT IN (VALUES ` + values.String() + `)`
	if _, err := s.conn.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("removing stale endpoint vulns: %w", err)
	}
	return nil
}

func (s *DB) GetPreviousCanonicalIDs(ctx context.Context, endpointID string) ([]string, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT DISTINCT v.canonical_id
		FROM endpoint_vulnerabilities ev
		JOIN vulnerabilities v ON v.id = ev.vulnerability_id
		WHERE ev.endpoint_id = ?`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("getting previous canonical IDs: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
