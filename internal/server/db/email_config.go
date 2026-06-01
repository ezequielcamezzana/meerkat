package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type EmailConfig struct {
	Enabled    bool
	Recipients []string
}

func (s *DB) GetEmailConfig(ctx context.Context) (EmailConfig, error) {
	cfg := EmailConfig{Enabled: true, Recipients: []string{}}

	var enabled string
	err := s.conn.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'notifications.email.enabled'`).Scan(&enabled)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return cfg, err
	}
	if enabled == "false" {
		cfg.Enabled = false
	}

	var recipients string
	err = s.conn.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'notifications.email.recipients'`).Scan(&recipients)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return cfg, err
	}
	if recipients != "" {
		for _, r := range strings.Split(recipients, ",") {
			if t := strings.TrimSpace(r); t != "" {
				cfg.Recipients = append(cfg.Recipients, t)
			}
		}
	}

	return cfg, nil
}

func (s *DB) SetEmailConfig(ctx context.Context, cfg EmailConfig) error {
	enabled := "true"
	if !cfg.Enabled {
		enabled = "false"
	}

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('notifications.email.enabled', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, enabled)
	if err != nil {
		return err
	}

	_, err = s.conn.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('notifications.email.recipients', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strings.Join(cfg.Recipients, ","))
	return err
}
