// Package config loads the server's configuration from the environment.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen               string
	DBPath               string
	LogFormat            string
	LogLevel             string
	BaseURL              string
	OSVBaseURL           string
	OSVTimeout           time.Duration
	SMTPHost             string
	SMTPPort             int
	SMTPUser             string
	SMTPPass             string
	BrevoAPIKey          string
	BrevoBaseURL         string
	NotifyFrom           string
	NotifyFromName       string
	NotifyTo             []string
	HistoryRetentionDays int
	CORSAllowedOrigins   []string
	RematchInterval      time.Duration
	RematchBatch         int
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:               envOr("MEERKAT_LISTEN", ":8080"),
		DBPath:               envOr("MEERKAT_DB_PATH", defaultDBPath()),
		LogFormat:            envOr("MEERKAT_LOG_FORMAT", "text"),
		LogLevel:             envOr("MEERKAT_LOG_LEVEL", "info"),
		BaseURL:              os.Getenv("MEERKAT_BASE_URL"),
		OSVBaseURL:           envOr("MEERKAT_OSV_BASE_URL", "https://api.osv.dev"),
		SMTPHost:             os.Getenv("MEERKAT_SMTP_HOST"),
		SMTPPort:             envInt("MEERKAT_SMTP_PORT", 587),
		SMTPUser:             os.Getenv("MEERKAT_SMTP_USER"),
		SMTPPass:             os.Getenv("MEERKAT_SMTP_PASS"),
		BrevoAPIKey:          os.Getenv("MEERKAT_BREVO_API_KEY"),
		BrevoBaseURL:         envOr("MEERKAT_BREVO_BASE_URL", "https://api.brevo.com"),
		NotifyFrom:           os.Getenv("MEERKAT_NOTIFY_FROM"),
		NotifyFromName:       envOr("MEERKAT_NOTIFY_FROM_NAME", "meerkat"),
		HistoryRetentionDays: envInt("MEERKAT_HISTORY_RETENTION_DAYS", 30),
	}

	cfg.OSVTimeout = envDuration("MEERKAT_OSV_TIMEOUT", 30*time.Second)
	cfg.RematchInterval = envDuration("MEERKAT_REMATCH_INTERVAL", time.Hour)
	cfg.RematchBatch = envInt("MEERKAT_REMATCH_BATCH", 100)

	if raw := os.Getenv("MEERKAT_NOTIFY_TO"); raw != "" {
		cfg.NotifyTo = splitComma(raw)
	}

	origins := envOr("MEERKAT_CORS_ALLOWED_ORIGINS", "*")
	cfg.CORSAllowedOrigins = splitComma(origins)

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	// Brevo takes precedence; it only needs a verified sender address.
	if c.BrevoAPIKey != "" {
		if c.NotifyFrom == "" {
			return fmt.Errorf("MEERKAT_BREVO_API_KEY set but MEERKAT_NOTIFY_FROM is missing")
		}
		return nil
	}
	// SMTP is the fallback transport; require all its fields together or none.
	smtpFields := []string{c.SMTPHost, c.SMTPUser, c.SMTPPass, c.NotifyFrom}
	set := 0
	for _, f := range smtpFields {
		if f != "" {
			set++
		}
	}
	if set > 0 && set < len(smtpFields) {
		return fmt.Errorf("SMTP partially configured: set all of MEERKAT_SMTP_HOST, MEERKAT_SMTP_USER, MEERKAT_SMTP_PASS, MEERKAT_NOTIFY_FROM or none")
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".meerkat", "server.db")
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
