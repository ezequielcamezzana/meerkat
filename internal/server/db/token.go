package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *DB) GetTokenHash(ctx context.Context) (string, error) {
	var hash string
	err := s.conn.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'api_token_hash'`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading token hash: %w", err)
	}
	return hash, nil
}

func (s *DB) ReplaceTokenHash(ctx context.Context, hash string) error {
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('api_token_hash', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		hash,
	)
	if err != nil {
		return fmt.Errorf("storing token hash: %w", err)
	}
	return nil
}
