package db

import (
	"context"
	"encoding/json"
	"fmt"
)

type HistoryEntry struct {
	Date      string `json:"date"`
	Status    string `json:"status"`
	VulnCount int    `json:"vuln_count"`
}

func (s *DB) UpsertHistory(ctx context.Context, endpointID, date, status string, vulnCount int, canonicalIDs []string) error {
	ids, _ := json.Marshal(canonicalIDs)
	_, err := s.conn.ExecContext(ctx, `
		INSERT INTO endpoint_history (endpoint_id, date, status, vuln_count, canonical_ids)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(endpoint_id, date) DO UPDATE SET
			status        = excluded.status,
			vuln_count    = excluded.vuln_count,
			canonical_ids = excluded.canonical_ids`,
		endpointID, date, status, vulnCount, string(ids),
	)
	return err
}

func (s *DB) GetHistory(ctx context.Context, endpointID string, days int) ([]HistoryEntry, error) {
	if days <= 0 || days > 90 {
		days = 30
	}
	rows, err := s.conn.QueryContext(ctx, `
		SELECT date, status, vuln_count
		FROM endpoint_history
		WHERE endpoint_id = ?
		  AND date >= DATE('now', ? || ' days')
		ORDER BY date ASC`,
		endpointID, fmt.Sprintf("-%d", days))
	if err != nil {
		return nil, fmt.Errorf("getting history: %w", err)
	}
	defer rows.Close()

	var entries []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if err := rows.Scan(&e.Date, &e.Status, &e.VulnCount); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *DB) CleanupHistory(ctx context.Context, retentionDays int) (int, error) {
	res, err := s.conn.ExecContext(ctx,
		`DELETE FROM endpoint_history WHERE date < DATE('now', ? || ' days')`,
		fmt.Sprintf("-%d", retentionDays))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
