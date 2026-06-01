package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GetOrCreateSessionSecret returns the persistent HMAC secret, generating it on first call.
func (s *DB) GetOrCreateSessionSecret(ctx context.Context) (string, error) {
	var secret string
	err := s.conn.QueryRowContext(ctx,
		`SELECT value FROM meta WHERE key = 'session_secret'`).Scan(&secret)
	if err != nil {
		return "", fmt.Errorf("reading session secret: %w", err)
	}
	if secret != "" {
		return secret, nil
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session secret: %w", err)
	}
	secret = hex.EncodeToString(b)

	_, err = s.conn.ExecContext(ctx,
		`UPDATE meta SET value = ? WHERE key = 'session_secret'`, secret)
	if err != nil {
		return "", fmt.Errorf("storing session secret: %w", err)
	}
	return secret, nil
}
