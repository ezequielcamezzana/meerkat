// Package service installs and removes the CLI agent as a recurring background
// job (cron on unix, no-op elsewhere).
package service

import (
	"log/slog"
	"time"
)

type Installer interface {
	Install(binaryPath string, interval time.Duration, logPath string) error
	Uninstall() error
	IsInstalled() bool
}

type noopInstaller struct{}

func (n *noopInstaller) Install(binaryPath string, interval time.Duration, logPath string) error {
	slog.Warn("service installation not supported on this OS")
	return nil
}

func (n *noopInstaller) Uninstall() error {
	slog.Warn("service uninstallation not supported on this OS")
	return nil
}

func (n *noopInstaller) IsInstalled() bool { return false }
