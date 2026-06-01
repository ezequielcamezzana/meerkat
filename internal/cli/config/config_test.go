package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoad_roundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := Defaults()
	cfg.Endpoint.Tags = []string{"eng", "test"}
	cfg.Server.URL = "https://meerkat.example.com"

	require.NoError(t, Save(cfg))

	// verify permissions
	info, err := os.Stat(filepath.Join(dir, ".meerkat", "config.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	loaded, err := Load()
	require.NoError(t, err)
	require.Equal(t, cfg.Endpoint.ID, loaded.Endpoint.ID)
	require.Equal(t, cfg.Endpoint.Tags, loaded.Endpoint.Tags)
	require.Equal(t, cfg.Scan.Interval, loaded.Scan.Interval)
	require.Equal(t, cfg.Server.URL, loaded.Server.URL)
	require.Equal(t, SchemaVersion, loaded.SchemaVersion)
}

func TestLoad_notConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, err := Load()
	require.ErrorIs(t, err, ErrNotConfigured)
}

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	require.NotEmpty(t, cfg.Endpoint.ID)
	require.Equal(t, "1h", cfg.Scan.Interval)
	require.Equal(t, "/", cfg.Scan.Root)
	require.Contains(t, cfg.Scan.Excludes, "node_modules")
	require.Contains(t, cfg.Scan.Excludes, ".git")
	require.Contains(t, cfg.Scan.Excludes, "vendor")
}

func TestValidate(t *testing.T) {
	cfg := Defaults()
	require.NoError(t, Validate(cfg))

	cfg.Endpoint.ID = ""
	require.Error(t, Validate(cfg))

	cfg2 := Defaults()
	cfg2.Scan.Interval = "notaduration"
	require.Error(t, Validate(cfg2))
}
