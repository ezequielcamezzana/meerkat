package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

type Tenant struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	CreatedAt     string   `json:"created_at"`
	NotifyEnabled bool     `json:"notify_enabled"`
	Recipients    []string `json:"recipients"`
}

var ErrTenantNotFound = errors.New("tenant not found")

func (s *DB) CreateTenant(ctx context.Context, id, name, createdAt string) (*Tenant, error) {
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO tenants (id, name, created_at, notify_enabled, recipients)
		 VALUES (?, ?, ?, 1, '[]')`,
		id, name, createdAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating tenant: %w", err)
	}
	return &Tenant{ID: id, Name: name, CreatedAt: createdAt, NotifyEnabled: true, Recipients: []string{}}, nil
}

func (s *DB) GetTenantByID(ctx context.Context, id string) (*Tenant, error) {
	return s.scanTenant(s.conn.QueryRowContext(ctx,
		`SELECT id, name, created_at, notify_enabled, recipients FROM tenants WHERE id = ?`, id,
	))
}

func (s *DB) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	return s.scanTenant(s.conn.QueryRowContext(ctx,
		`SELECT id, name, created_at, notify_enabled, recipients FROM tenants WHERE name = ?`, name,
	))
}

func (s *DB) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT id, name, created_at, notify_enabled, recipients FROM tenants ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		t, err := s.scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, *t)
	}
	return tenants, rows.Err()
}

func (s *DB) UpdateTenantNotifications(ctx context.Context, tenantID string, enabled bool, recipients []string) error {
	raw, err := json.Marshal(recipients)
	if err != nil {
		return fmt.Errorf("marshaling recipients: %w", err)
	}
	notifyEnabled := 0
	if enabled {
		notifyEnabled = 1
	}
	res, err := s.conn.ExecContext(ctx,
		`UPDATE tenants SET notify_enabled = ?, recipients = ? WHERE id = ?`,
		notifyEnabled, string(raw), tenantID,
	)
	if err != nil {
		return fmt.Errorf("updating tenant notifications: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrTenantNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *DB) scanTenant(row rowScanner) (*Tenant, error) {
	var t Tenant
	var notifyEnabled int
	var recipientsRaw string
	err := row.Scan(&t.ID, &t.Name, &t.CreatedAt, &notifyEnabled, &recipientsRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTenantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanning tenant: %w", err)
	}
	t.NotifyEnabled = notifyEnabled == 1
	t.Recipients = []string{}
	_ = json.Unmarshal([]byte(recipientsRaw), &t.Recipients)
	return &t, nil
}
