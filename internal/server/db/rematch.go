package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

func (s *DB) SetLastMatched(ctx context.Context, endpointID string, now time.Time) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE endpoints SET last_matched_at = ? WHERE id = ?`,
		now.UTC().Format(time.RFC3339), endpointID)
	return err
}

type RematchTarget struct {
	Endpoint api.Endpoint
	TenantID string
	Packages []api.Package
}

// ListRematchTargets returns endpoints whose active scan is stale (last_seen
// older than staleHours) and whose vuln data hasn't been re-evaluated within
// rematchHours — candidates for a passive re-match against fresh OSV data.
// Bounded by limit, oldest re-match first.
func (s *DB) ListRematchTargets(ctx context.Context, staleHours, rematchHours, limit int) ([]RematchTarget, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT e.id, e.hostname, e.os, e.arch, e.user, e.tags, COALESCE(e.tenant_id, ''), i.raw
		FROM endpoints e
		JOIN inventories i ON i.endpoint_id = e.id
		WHERE datetime(e.last_seen) < datetime('now', ?)
		  AND (e.last_matched_at = '' OR datetime(e.last_matched_at) < datetime('now', ?))
		ORDER BY e.last_matched_at ASC
		LIMIT ?`,
		fmt.Sprintf("-%d hours", staleHours),
		fmt.Sprintf("-%d hours", rematchHours),
		limit)
	if err != nil {
		return nil, fmt.Errorf("listing rematch targets: %w", err)
	}
	defer rows.Close()

	var out []RematchTarget
	for rows.Next() {
		var t RematchTarget
		var tagsJSON, raw string
		if err := rows.Scan(&t.Endpoint.ID, &t.Endpoint.Hostname, &t.Endpoint.OS,
			&t.Endpoint.Arch, &t.Endpoint.User, &tagsJSON, &t.TenantID, &raw); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(tagsJSON), &t.Endpoint.Tags)
		var inv api.Inventory
		if err := json.Unmarshal([]byte(raw), &inv); err != nil {
			continue // skip a malformed stored inventory rather than abort the pass
		}
		t.Packages = inv.Packages
		out = append(out, t)
	}
	return out, rows.Err()
}
