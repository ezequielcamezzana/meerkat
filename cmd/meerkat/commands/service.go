package commands

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/cli/config"
	"github.com/ezequielcamezzana/meerkat/internal/cli/service"
	"github.com/spf13/cobra"
)

func NewServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage the meerkat background scan service",
	}
	cmd.AddCommand(
		newServiceStartCmd(),
		newServiceStopCmd(),
		newServiceStatusCmd(),
	)
	return cmd
}

func newServiceStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Install crontab entry for automatic scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			interval, err := time.ParseDuration(cfg.Scan.Interval)
			if err != nil {
				return fmt.Errorf("invalid scan interval %q: %w", cfg.Scan.Interval, err)
			}
			binaryPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolving binary path: %w", err)
			}
			logPath := filepath.Join(config.ConfigDir(), "meerkat.log")
			inst := service.NewInstaller()
			if err := inst.Install(binaryPath, interval, logPath); err != nil {
				return fmt.Errorf("installing service: %w", err)
			}
			slog.Info("service started", "interval", cfg.Scan.Interval, "log", logPath)
			fmt.Fprintf(os.Stderr, "Automatic scanning enabled (interval: %s)\n", cfg.Scan.Interval)
			return nil
		},
	}
}

func newServiceStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Remove crontab entry and stop automatic scanning",
		RunE: func(cmd *cobra.Command, args []string) error {
			inst := service.NewInstaller()
			if !inst.IsInstalled() {
				fmt.Fprintln(os.Stderr, "Service is not running.")
				return nil
			}
			if err := inst.Uninstall(); err != nil {
				return fmt.Errorf("removing service: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Automatic scanning disabled.")
			return nil
		},
	}
}

func newServiceStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether automatic scanning is enabled",
		RunE: func(cmd *cobra.Command, args []string) error {
			inst := service.NewInstaller()
			if inst.IsInstalled() {
				cfg, err := config.Load()
				if err != nil {
					fmt.Fprintln(os.Stdout, "active")
					return nil
				}
				fmt.Fprintf(os.Stdout, "active (interval: %s)\n", cfg.Scan.Interval)
			} else {
				fmt.Fprintln(os.Stdout, "inactive")
			}
			return nil
		},
	}
}
