package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

func (s *DB) InsertInventory(ctx context.Context, inv api.Inventory) error {
	raw, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("marshaling inventory: %w", err)
	}
	_, err = s.conn.ExecContext(ctx, `
		INSERT OR REPLACE INTO inventories (endpoint_id, scan_id, received_at, raw)
		VALUES (?, ?, ?, ?)`,
		inv.Endpoint.ID,
		inv.Scan.ID,
		time.Now().UTC().Format(time.RFC3339),
		string(raw),
	)
	return err
}

func (s *DB) GetLastScanID(ctx context.Context, endpointID string) (string, error) {
	var scanID string
	err := s.conn.QueryRowContext(ctx,
		`SELECT scan_id FROM inventories WHERE endpoint_id = ?`, endpointID).
		Scan(&scanID)
	if err != nil {
		return "", nil // not found is fine
	}
	return scanID, nil
}
