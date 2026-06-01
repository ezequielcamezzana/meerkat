package commands

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ezequielcamezzana/meerkat/internal/cli/cache"
	"github.com/ezequielcamezzana/meerkat/internal/cli/config"
	"github.com/spf13/cobra"
)

func NewCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the scan cache",
	}

	cmd.AddCommand(
		newCacheInfoCmd(),
		newCacheClearCmd(),
	)

	return cmd
}

func newCacheInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show cache statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := cache.New(filepath.Join(config.ConfigDir(), "cache"))
			info := c.Info()
			fmt.Printf("entries:    %d\n", info.Entries)
			fmt.Printf("total size: %s\n", formatBytes(info.TotalSize))
			return nil
		},
	}
}

func newCacheClearCmd() *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete all cache entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				fmt.Print("This will delete all cached scan results. Continue? [y/N] ")
				r := bufio.NewReader(os.Stdin)
				answer, _ := r.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			c := cache.New(filepath.Join(config.ConfigDir(), "cache"))
			if err := c.Clear(); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("clearing cache: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Cache cleared.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&yes, "yes", false, "Skip confirmation prompt")
	return cmd
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
