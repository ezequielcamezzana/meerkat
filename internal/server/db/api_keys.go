package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type APIKey struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

var ErrKeyNotFound = errors.New("api key not found")

func (s *DB) CreateAPIKey(ctx context.Context, id, tenantID, name, hash, createdAt string) (*APIKey, error) {
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO api_keys (id, tenant_id, name, hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, tenantID, name, hash, createdAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating api key: %w", err)
	}
	return &APIKey{ID: id, TenantID: tenantID, Name: name, CreatedAt: createdAt}, nil
}

// GetAPIKeyByHash returns the key and its tenant for a given token hash.
func (s *DB) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	var k APIKey
	err := s.conn.QueryRowContext(ctx,
		`SELECT id, tenant_id, name, created_at FROM api_keys WHERE hash = ?`, hash,
	).Scan(&k.ID, &k.TenantID, &k.Name, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up api key: %w", err)
	}
	return &k, nil
}

func (s *DB) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT id, tenant_id, name, created_at FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Name, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning api key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *DB) RevokeAPIKey(ctx context.Context, id string) error {
	res, err := s.conn.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("revoking api key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrKeyNotFound
	}
	return nil
}
