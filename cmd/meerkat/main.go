package main

import (
	"log/slog"
	"os"

	"github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands"
	clilog "github.com/ezequielcamezzana/meerkat/internal/cli/log"
	"github.com/spf13/cobra"
)

func main() {
	var verbose bool

	root := &cobra.Command{
		Use:          "meerkat",
		Short:        "SBOM-as-fingerprint scanner and vulnerability tracker",
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			slog.SetDefault(clilog.Setup(verbose))
		},
	}

	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable debug logging")

	root.AddCommand(
		commands.NewVersionCmd(),
		commands.NewScanCmd(),
		commands.NewConfigCmd(),
		commands.NewServiceCmd(),
		commands.NewCacheCmd(),
		commands.NewServerCmd(),
		commands.NewMigrateCmd(),
		commands.NewKeyCmd(),
		commands.NewUpdateCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
