package commands

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ezequielcamezzana/meerkat/internal/cli/config"
	"github.com/ezequielcamezzana/meerkat/internal/cli/service"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage meerkat configuration",
	}

	cmd.AddCommand(
		newConfigInitCmd(),
		newConfigShowCmd(),
		newConfigSetCmd(),
		newConfigGetCmd(),
		newConfigResetCmd(),
	)

	return cmd
}

// --- init ---

func newConfigInitCmd() *cobra.Command {
	var (
		nonInteractive bool
		tags           string
		serverURL      string
		token          string
		interval       string
		root           string
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize meerkat configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := config.Load()
			if err == nil {
				return fmt.Errorf("config already exists; use `meerkat config reset` first")
			}
			if !errors.Is(err, config.ErrNotConfigured) {
				return err
			}

			cfg := config.Defaults()

			if nonInteractive {
				if v := orEnv(tags, "MEERKAT_TAGS"); v != "" {
					cfg.Endpoint.Tags = splitComma(v)
				}
				if v := orEnv(serverURL, "MEERKAT_SERVER"); v != "" {
					cfg.Server.URL = v
				}
				if v := orEnv(token, "MEERKAT_TOKEN"); v != "" {
					cfg.Server.Token = v
				}
				if v := orEnv(interval, "MEERKAT_INTERVAL"); v != "" {
					cfg.Scan.Interval = v
				}
				if root != "" {
					cfg.Scan.Root = root
				}
			} else {
				r := bufio.NewReader(os.Stdin)
				cfg.Endpoint.Tags = promptSlice(r, "Tags (comma-separated, e.g. eng,test)")
				cfg.Server.URL = promptString(r, "Server URL (leave empty for offline mode)")
				cfg.Server.Token = promptString(r, "Server token (leave empty to set later)")
				cfg.Scan.Interval = promptStringDefault(r, "Scan interval (e.g. 1h, 30m)", cfg.Scan.Interval)
			}

			if err := config.Validate(cfg); err != nil {
				return err
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Config written to %s\n", config.ConfigPath())
			fmt.Fprintln(os.Stderr, "Run `meerkat service start` to enable automatic scanning.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Read all values from flags or env vars")
	cmd.Flags().StringVar(&tags, "tags", "", "Comma-separated tags (e.g. eng,test)")
	cmd.Flags().StringVar(&serverURL, "server-url", "", "Server URL")
	cmd.Flags().StringVar(&token, "token", "", "Server auth token")
	cmd.Flags().StringVar(&interval, "interval", "", "Scan interval (e.g. 1h)")
	cmd.Flags().StringVar(&root, "root", "", "Scan root path")

	return cmd
}

// --- show ---

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// redact token
			display := *cfg
			if display.Server.Token != "" {
				display.Server.Token = "<set>"
			} else {
				display.Server.Token = "<unset>"
			}

			out, err := yaml.Marshal(&display)
			if err != nil {
				return err
			}
			fmt.Print(string(out))
			return nil
		},
	}
}

// --- set ---

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			switch key {
			case "tags":
				cfg.Endpoint.Tags = splitComma(value)
			case "interval", "scan.interval":
				cfg.Scan.Interval = value
			case "server.url":
				cfg.Server.URL = value
			case "server.token":
				cfg.Server.Token = value
			case "scan.root", "root":
				cfg.Scan.Root = value
			case "scan.excludes", "excludes":
				cfg.Scan.Excludes = splitComma(value)
			case "excludes-add":
				if !contains(cfg.Scan.Excludes, value) {
					cfg.Scan.Excludes = append(cfg.Scan.Excludes, value)
				}
			case "excludes-remove":
				cfg.Scan.Excludes = without(cfg.Scan.Excludes, value)
			case "notifications.local":
				cfg.Notifications.Local = value == "true"
			default:
				return fmt.Errorf("unknown config key %q", key)
			}

			if err := config.Validate(cfg); err != nil {
				return err
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			return nil
		},
	}
}

// --- get ---

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			key := args[0]
			switch key {
			case "tags":
				fmt.Println(strings.Join(cfg.Endpoint.Tags, ","))
			case "interval", "scan.interval":
				fmt.Println(cfg.Scan.Interval)
			case "server.url":
				fmt.Println(cfg.Server.URL)
			case "server.token":
				if cfg.Server.Token != "" {
					fmt.Println("<set>")
				} else {
					fmt.Println("<unset>")
				}
			case "scan.root", "root":
				fmt.Println(cfg.Scan.Root)
			case "scan.excludes", "excludes":
				fmt.Println(strings.Join(cfg.Scan.Excludes, ","))
			case "notifications.local":
				fmt.Println(cfg.Notifications.Local)
			default:
				return fmt.Errorf("unknown config key %q", key)
			}
			return nil
		},
	}
}

// --- reset ---

func newConfigResetCmd() *cobra.Command {
	var (
		yes bool
		all bool
	)

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset configuration and remove OS service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				fmt.Print("This will remove your meerkat configuration. Continue? [y/N] ")
				r := bufio.NewReader(os.Stdin)
				answer, _ := r.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			inst := service.NewInstaller()
			if inst.IsInstalled() {
				if err := inst.Uninstall(); err != nil {
					slog.Warn("service uninstall failed", "err", err)
				}
			}

			if err := os.Remove(config.ConfigPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("removing config: %w", err)
			}

			if all {
				cacheDir := fmt.Sprintf("%s/cache", config.ConfigDir())
				logsDir := fmt.Sprintf("%s/logs", config.ConfigDir())
				_ = os.RemoveAll(cacheDir)
				_ = os.RemoveAll(logsDir)
			}

			fmt.Fprintln(os.Stderr, "Configuration reset.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&yes, "yes", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&all, "all", false, "Also delete cache and logs")

	return cmd
}

// --- helpers ---

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func orEnv(flagVal, envKey string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envKey)
}

func promptString(r *bufio.Reader, label string) string {
	fmt.Printf("%s: ", label)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptStringDefault(r *bufio.Reader, label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptSlice(r *bufio.Reader, label string) []string {
	val := promptString(r, label)
	if val == "" {
		return []string{}
	}
	return splitComma(val)
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func without(slice []string, s string) []string {
	out := make([]string, 0, len(slice))
	for _, v := range slice {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
