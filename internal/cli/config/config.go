// Package config loads and persists the CLI agent's local configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = "0.1.0"

var ErrNotConfigured = errors.New("meerkat is not configured; run `meerkat config init`")

type Config struct {
	SchemaVersion string              `yaml:"schema_version"`
	Endpoint      EndpointConfig      `yaml:"endpoint"`
	Scan          ScanConfig          `yaml:"scan"`
	Server        ServerConfig        `yaml:"server"`
	Notifications NotificationsConfig `yaml:"notifications"`
}

type EndpointConfig struct {
	ID   string   `yaml:"id"`
	Tags []string `yaml:"tags"`
}

type ScanConfig struct {
	Interval string   `yaml:"interval"`
	Root     string   `yaml:"root"`
	Excludes []string `yaml:"excludes"`
}

type ServerConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

type NotificationsConfig struct {
	Local bool `yaml:"local"`
}

func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".meerkat")
}

func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.yaml")
}

func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotConfigured
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

func Save(cfg *Config) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serializing config: %w", err)
	}

	if err := os.WriteFile(ConfigPath(), data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

func Validate(cfg *Config) error {
	if cfg.Endpoint.ID == "" {
		return errors.New("endpoint.id is required")
	}
	if cfg.Scan.Interval == "" {
		return errors.New("scan.interval is required")
	}
	if _, err := time.ParseDuration(cfg.Scan.Interval); err != nil {
		return fmt.Errorf("scan.interval %q is not a valid duration: %w", cfg.Scan.Interval, err)
	}
	return nil
}
