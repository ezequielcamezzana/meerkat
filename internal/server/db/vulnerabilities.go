package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/scoring"
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
				 exposure_score, package_scope, package_kind, discovered_at, fixed_version)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(endpoint_id, purl, vulnerability_id) DO UPDATE SET
				package_name      = excluded.package_name,
				package_version   = excluded.package_version,
				package_ecosystem = excluded.package_ecosystem,
				dirs              = excluded.dirs,
				exposure_score    = excluded.exposure_score,
				package_scope     = excluded.package_scope,
				package_kind      = excluded.package_kind,
				fixed_version     = excluded.fixed_version,
				discovered_at     = CASE
					WHEN endpoint_vulnerabilities.discovered_at = ''
					THEN excluded.discovered_at
					ELSE endpoint_vulnerabilities.discovered_at END`,
			endpointID, m.Purl, m.Vulnerability.ID,
			m.PackageName, m.PackageVersion, m.PackageEcosystem, string(dirs),
			m.ExposureScore, m.PackageScope, m.PackageKind, nowStr, m.FixedVersion,
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

// VulnListQuery filters the tenant-wide vuln listing. Sort is "discovered"
// (default) or "exposure"; an empty/unknown value falls back to "discovered".
type VulnListQuery struct {
	Search string
	Sort   string
	Limit  int
	Offset int
}

// VulnSummary is one row of the vuln-centric listing: a vuln grouped by
// canonical_id and aggregated across every affected endpoint of the tenant.
// It omits the advisory body — that's loaded lazily via GetTenantVulnDetail.
type VulnSummary struct {
	CanonicalID    string   `json:"canonical_id"`
	Aliases        []string `json:"aliases,omitempty"`
	SeverityScore  float64  `json:"severity_score"`
	ExposureScore  float64  `json:"exposure_score"`
	ExposureBucket string   `json:"exposure_bucket"`
	DiscoveredAt   string   `json:"discovered_at,omitempty"`
	ModifiedAt     string   `json:"modified_at,omitempty"`
	AffectedCount  int      `json:"affected_count"`
}

// ListTenantVulns lists the vulns present across the tenant's endpoints,
// grouped by canonical_id, paginated/searched/sorted. The returned int is the
// total number of matching groups, independent of Limit/Offset.
func (s *DB) ListTenantVulns(ctx context.Context, tenantID string, q VulnListQuery) ([]VulnSummary, int, error) {
	orderBy := "discovered_at DESC, exposure_score DESC"
	if q.Sort == "exposure" {
		orderBy = "exposure_score DESC, discovered_at DESC"
	}

	// COMPLEX: search matches the group when ANY of its vuln rows matches, so we
	// filter by canonical_id IN (matching ids) instead of a row-level WHERE —
	// otherwise dropping non-matching rows would skew affected_count.
	args := []any{tenantID}
	searchClause := ""
	if q.Search != "" {
		like := "%" + q.Search + "%"
		searchClause = `
			AND v.canonical_id IN (
				SELECT canonical_id FROM vulnerabilities
				WHERE id LIKE ? OR canonical_id LIKE ? OR aliases LIKE ?
			)`
		args = append(args, like, like, like)
	}

	var total int
	countQuery := `
		SELECT COUNT(DISTINCT v.canonical_id)
		FROM endpoint_vulnerabilities ev
		JOIN vulnerabilities v ON v.id = ev.vulnerability_id
		JOIN endpoints e ON e.id = ev.endpoint_id
		WHERE e.tenant_id = ?` + searchClause
	if err := s.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting tenant vulns: %w", err)
	}

	listQuery := `
		SELECT
			v.canonical_id,
			MIN(v.aliases)                    AS aliases,
			MAX(v.severity_score)             AS severity_score,
			MAX(ev.exposure_score)            AS exposure_score,
			MIN(NULLIF(ev.discovered_at, '')) AS discovered_at,
			MAX(v.modified_at)                AS modified_at,
			COUNT(DISTINCT ev.endpoint_id)    AS affected_count
		FROM endpoint_vulnerabilities ev
		JOIN vulnerabilities v ON v.id = ev.vulnerability_id
		JOIN endpoints e ON e.id = ev.endpoint_id
		WHERE e.tenant_id = ?` + searchClause + `
		GROUP BY v.canonical_id
		ORDER BY ` + orderBy
	if q.Limit > 0 {
		listQuery += " LIMIT ? OFFSET ?"
		args = append(args, q.Limit, q.Offset)
	}

	rows, err := s.conn.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing tenant vulns: %w", err)
	}
	defer rows.Close()

	var result []VulnSummary
	for rows.Next() {
		var v VulnSummary
		var aliasesJSON string
		var discoveredAt, modifiedAt sql.NullString
		if err := rows.Scan(
			&v.CanonicalID, &aliasesJSON, &v.SeverityScore, &v.ExposureScore,
			&discoveredAt, &modifiedAt, &v.AffectedCount,
		); err != nil {
			return nil, 0, err
		}
		v.DiscoveredAt = discoveredAt.String
		v.ModifiedAt = modifiedAt.String
		v.ExposureBucket = scoring.Bucket(v.ExposureScore)
		json.Unmarshal([]byte(aliasesJSON), &v.Aliases)
		result = append(result, v)
	}
	return result, total, rows.Err()
}

// AffectedEndpoint is one endpoint of the tenant where a vuln is present, with
// the vulnerable package and that endpoint's exposure for the vuln.
type AffectedEndpoint struct {
	EndpointID     string  `json:"endpoint_id"`
	Hostname       string  `json:"hostname"`
	OS             string  `json:"os"`
	ExposureScore  float64 `json:"exposure_score"`
	Purl           string  `json:"purl"`
	PackageName    string  `json:"package_name"`
	PackageVersion string  `json:"package_version"`
	FixedVersion   string  `json:"fixed_version,omitempty"`
}

// VulnDetail is the lazily-loaded body of a vuln card: the advisory plus every
// affected endpoint of the tenant.
type VulnDetail struct {
	CanonicalID       string             `json:"canonical_id"`
	Aliases           []string           `json:"aliases,omitempty"`
	Summary           string             `json:"summary"`
	Details           string             `json:"details"`
	PublishedAt       string             `json:"published_at,omitempty"`
	ModifiedAt        string             `json:"modified_at,omitempty"`
	AffectedEndpoints []AffectedEndpoint `json:"affected_endpoints"`
}

// GetTenantVulnDetail returns the advisory for a canonical_id plus the tenant's
// affected endpoints, or nil if the vuln isn't present in the tenant.
func (s *DB) GetTenantVulnDetail(ctx context.Context, tenantID, canonicalID string) (*VulnDetail, error) {
	// Advisory fields collapsed across the vuln ids sharing this canonical_id,
	// scoped to the tenant via the affected endpoints. COUNT tells us whether the
	// vuln is present at all (the aggregates would otherwise be NULL).
	var count int
	var aliasesJSON, summary, details sql.NullString
	var publishedAt, modifiedAt sql.NullString
	err := s.conn.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			MIN(v.aliases),
			MIN(v.summary),
			MIN(v.details),
			MIN(v.published_at),
			MAX(v.modified_at)
		FROM endpoint_vulnerabilities ev
		JOIN vulnerabilities v ON v.id = ev.vulnerability_id
		JOIN endpoints e ON e.id = ev.endpoint_id
		WHERE v.canonical_id = ? AND e.tenant_id = ?`,
		canonicalID, tenantID,
	).Scan(&count, &aliasesJSON, &summary, &details, &publishedAt, &modifiedAt)
	if err != nil {
		return nil, fmt.Errorf("reading vuln advisory: %w", err)
	}
	if count == 0 {
		return nil, nil
	}

	detail := &VulnDetail{
		CanonicalID: canonicalID,
		Summary:     summary.String,
		Details:     details.String,
		PublishedAt: publishedAt.String,
		ModifiedAt:  modifiedAt.String,
	}
	json.Unmarshal([]byte(aliasesJSON.String), &detail.Aliases)

	rows, err := s.conn.QueryContext(ctx, `
		SELECT e.id, e.hostname, e.os, ev.exposure_score,
		       ev.purl, ev.package_name, ev.package_version, ev.fixed_version
		FROM endpoint_vulnerabilities ev
		JOIN vulnerabilities v ON v.id = ev.vulnerability_id
		JOIN endpoints e ON e.id = ev.endpoint_id
		WHERE v.canonical_id = ? AND e.tenant_id = ?
		ORDER BY ev.exposure_score DESC`,
		canonicalID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing affected endpoints: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a AffectedEndpoint
		if err := rows.Scan(
			&a.EndpointID, &a.Hostname, &a.OS, &a.ExposureScore,
			&a.Purl, &a.PackageName, &a.PackageVersion, &a.FixedVersion,
		); err != nil {
			return nil, err
		}
		detail.AffectedEndpoints = append(detail.AffectedEndpoints, a)
	}
	return detail, rows.Err()
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
