// Package db owns the SQLite store: schema migrations and all query access for
// the server.
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type DB struct {
	conn *sql.DB
}

func Open(path string) (*DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("creating db directory: %w", err)
		}
	}
	conn, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	conn.SetMaxOpenConns(1)
	// Force actual file creation before caller uses the connection.
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("connecting to db: %w", err)
	}
	return &DB{conn: conn}, nil
}

func (s *DB) Migrate(ctx context.Context) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}

	driver, err := migratesqlite.WithInstance(s.conn, &migratesqlite.Config{})
	if err != nil {
		return fmt.Errorf("creating migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

func (s *DB) Ping(ctx context.Context) error {
	return s.conn.PingContext(ctx)
}

func (s *DB) Close() error {
	return s.conn.Close()
}
