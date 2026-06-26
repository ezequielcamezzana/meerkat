package commands

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	serverapi "github.com/ezequielcamezzana/meerkat/internal/server/api"
	"github.com/ezequielcamezzana/meerkat/internal/server/config"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/notifier"
	"github.com/ezequielcamezzana/meerkat/internal/server/rematch"
	"github.com/spf13/cobra"
)

func NewServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Start the meerkat HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			database, err := db.Open(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer database.Close()

			if err := database.Migrate(cmd.Context()); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}

			keys, err := database.ListAPIKeys(cmd.Context())
			if err != nil {
				return fmt.Errorf("checking api keys: %w", err)
			}
			if len(keys) == 0 {
				slog.Warn("no API keys configured — run `meerkat key create --tenant <name>` before sending inventories")
			}

			osv := matcher.NewOSVMatcher(matcher.OSVConfig{
				BaseURL: cfg.OSVBaseURL,
				Timeout: cfg.OSVTimeout,
			})
			// Prefer Brevo's HTTP API when an API key is set; otherwise SMTP.
			var emailNotifier notifier.Notifier
			if cfg.BrevoAPIKey != "" {
				emailNotifier = notifier.NewBrevoNotifier(
					cfg.BrevoAPIKey, cfg.NotifyFrom, cfg.NotifyFromName, cfg.BrevoBaseURL, nil,
				)
			} else {
				emailNotifier = notifier.NewEmailNotifier(notifier.SMTPConfig{
					Host: cfg.SMTPHost,
					Port: cfg.SMTPPort,
					User: cfg.SMTPUser,
					Pass: cfg.SMTPPass,
					From: cfg.NotifyFrom,
				})
			}
			ing := ingest.New(database, osv, emailNotifier, cfg.BaseURL)
			router := serverapi.NewRouter(database, ing, cfg, Version)

			// Passive scanning: re-match stale endpoints against fresh OSV data.
			rematcher := rematch.New(database, ing, cfg.RematchInterval, cfg.RematchBatch)
			go rematcher.Start(context.Background())

			slog.Info("server starting", "listen", cfg.Listen)
			if err := http.ListenAndServe(cfg.Listen, router); err != nil {
				return fmt.Errorf("server error: %w", err)
			}
			return nil
		},
	}
}
