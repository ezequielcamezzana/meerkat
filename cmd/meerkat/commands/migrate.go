package commands

import (
	"fmt"
	"log/slog"

	"github.com/ezequielcamezzana/meerkat/internal/server/config"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/spf13/cobra"
)

func NewMigrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
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

			slog.Info("migrations applied", "db", cfg.DBPath)
			return nil
		},
	}
}
