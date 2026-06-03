package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type EndpointWithStatus struct {
	api.Endpoint
	FirstSeen   time.Time
	LastSeen    time.Time
	LastMatched time.Time
	Status      string
	VulnCount   int
}

func (s *DB) UpsertEndpoint(ctx context.Context, e api.Endpoint, tenantID string, now time.Time) error {
	tags, err := json.Marshal(e.Tags)
	if err != nil {
		return fmt.Errorf("marshaling tags: %w", err)
	}
	ts := now.UTC().Format(time.RFC3339)
	_, err = s.conn.ExecContext(ctx, `
		INSERT INTO endpoints (id, hostname, os, arch, user, tags, tenant_id, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname   = excluded.hostname,
			os         = excluded.os,
			arch       = excluded.arch,
			user       = excluded.user,
			tags       = excluded.tags,
			tenant_id  = excluded.tenant_id,
			last_seen  = excluded.last_seen`,
		e.ID, e.Hostname, e.OS, e.Arch, e.User, string(tags), nullableStr(tenantID), ts, ts,
	)
	return err
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type EndpointFilter struct {
	TenantID string
	Tag      string
	Status   string
	Q        string
	Limit    int
	Offset   int
}

func (s *DB) ListEndpoints(ctx context.Context, f EndpointFilter) ([]EndpointWithStatus, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}

	rows, err := s.conn.QueryContext(ctx, `
		SELECT
			e.id, e.hostname, e.os, e.arch, e.tags, e.first_seen, e.last_seen, e.last_matched_at,
			CASE
				WHEN datetime(e.last_seen) < datetime('now', '-24 hours') THEN 'stale'
				WHEN COALESCE(ev.max_exposure, 0) >= 7.0 THEN 'critical'
				WHEN COALESCE(ev.max_exposure, 0) >= 4.0 THEN 'high'
				WHEN COALESCE(ev.max_exposure, 0) >= 2.0 THEN 'medium'
				WHEN COALESCE(ev.max_exposure, 0) > 0    THEN 'low'
				ELSE 'clean'
			END AS status,
			COALESCE(ev.canonical_count, 0) AS vuln_count
		FROM endpoints e
		LEFT JOIN (
			SELECT ev.endpoint_id,
			       COUNT(DISTINCT v.canonical_id) AS canonical_count,
			       MAX(ev.exposure_score) AS max_exposure
			FROM endpoint_vulnerabilities ev
			JOIN vulnerabilities v ON v.id = ev.vulnerability_id
			GROUP BY ev.endpoint_id
		) ev ON ev.endpoint_id = e.id
		WHERE e.tenant_id = ?
		ORDER BY e.last_seen DESC
		LIMIT ? OFFSET ?`, f.TenantID, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing endpoints: %w", err)
	}
	defer rows.Close()

	var results []EndpointWithStatus
	for rows.Next() {
		var e EndpointWithStatus
		var tagsJSON, firstSeen, lastSeen, lastMatched string
		if err := rows.Scan(&e.ID, &e.Hostname, &e.OS, &e.Arch, &tagsJSON,
			&firstSeen, &lastSeen, &lastMatched, &e.Status, &e.VulnCount); err != nil {
			return nil, 0, err
		}
		json.Unmarshal([]byte(tagsJSON), &e.Tags)
		e.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		e.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		e.LastMatched, _ = time.Parse(time.RFC3339, lastMatched)
		results = append(results, e)
	}

	var total int
	s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM endpoints WHERE tenant_id = ?`, f.TenantID).Scan(&total)

	return results, total, rows.Err()
}

func (s *DB) GetEndpointRow(ctx context.Context, id, tenantID string) (*EndpointWithStatus, error) {
	var e EndpointWithStatus
	var tagsJSON, firstSeen, lastSeen, lastMatched string

	err := s.conn.QueryRowContext(ctx, `
		SELECT
			e.id, e.hostname, e.os, e.arch, e.tags, e.first_seen, e.last_seen, e.last_matched_at,
			CASE
				WHEN datetime(e.last_seen) < datetime('now', '-24 hours') THEN 'stale'
				WHEN COALESCE(ev.max_exposure, 0) >= 7.0 THEN 'critical'
				WHEN COALESCE(ev.max_exposure, 0) >= 4.0 THEN 'high'
				WHEN COALESCE(ev.max_exposure, 0) >= 2.0 THEN 'medium'
				WHEN COALESCE(ev.max_exposure, 0) > 0    THEN 'low'
				ELSE 'clean'
			END AS status,
			COALESCE(ev.canonical_count, 0) AS vuln_count
		FROM endpoints e
		LEFT JOIN (
			SELECT ev.endpoint_id,
			       COUNT(DISTINCT v.canonical_id) AS canonical_count,
			       MAX(ev.exposure_score) AS max_exposure
			FROM endpoint_vulnerabilities ev
			JOIN vulnerabilities v ON v.id = ev.vulnerability_id
			GROUP BY ev.endpoint_id
		) ev ON ev.endpoint_id = e.id
		WHERE e.id = ? AND e.tenant_id = ?`, id, tenantID).
		Scan(&e.ID, &e.Hostname, &e.OS, &e.Arch, &tagsJSON,
			&firstSeen, &lastSeen, &lastMatched, &e.Status, &e.VulnCount)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting endpoint: %w", err)
	}
	json.Unmarshal([]byte(tagsJSON), &e.Tags)
	e.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	e.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	e.LastMatched, _ = time.Parse(time.RFC3339, lastMatched)
	return &e, nil
}
