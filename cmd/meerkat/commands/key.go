package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func NewKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage API keys and tenants",
	}
	cmd.AddCommand(
		newKeyCreateCmd(),
		newKeyListCmd(),
		newKeyRevokeCmd(),
	)
	return cmd
}

func newKeyCreateCmd() *cobra.Command {
	var (
		tenantName string
		keyName    string
		dbPath     string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key for a tenant (creates tenant if it does not exist)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantName == "" {
				return fmt.Errorf("--tenant is required")
			}

			database, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening db: %w", err)
			}
			defer database.Close()

			ctx := cmd.Context()

			// Get or create tenant.
			tenant, err := database.GetTenantByName(ctx, tenantName)
			if err == db.ErrTenantNotFound {
				tenant, err = database.CreateTenant(ctx, uuid.NewString(), tenantName, time.Now().UTC().Format(time.RFC3339))
				if err != nil {
					return fmt.Errorf("creating tenant: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Tenant %q created (id: %s)\n", tenant.Name, tenant.ID)
			} else if err != nil {
				return fmt.Errorf("looking up tenant: %w", err)
			}

			token, hash, err := auth.Generate()
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}

			if keyName == "" {
				keyName = tenantName + "-key"
			}

			key, err := database.CreateAPIKey(ctx, uuid.NewString(), tenant.ID, keyName, hash, time.Now().UTC().Format(time.RFC3339))
			if err != nil {
				return fmt.Errorf("saving key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "API key created (id: %s, tenant: %s, name: %s)\n", key.ID, tenant.Name, key.Name)
			fmt.Fprintf(os.Stderr, "Store this key securely — it will not be shown again:\n\n")
			fmt.Println(token)
			return nil
		},
	}

	cmd.Flags().StringVar(&tenantName, "tenant", "", "Tenant name (created if it does not exist)")
	cmd.Flags().StringVar(&keyName, "name", "", "Human label for this key (default: <tenant>-key)")
	cmd.Flags().StringVar(&dbPath, "db", defaultServerDBPath(), "Path to server database")
	return cmd
}

func newKeyListCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening db: %w", err)
			}
			defer database.Close()

			ctx := cmd.Context()
			keys, err := database.ListAPIKeys(ctx)
			if err != nil {
				return err
			}
			tenants, err := database.ListTenants(ctx)
			if err != nil {
				return err
			}
			tenantByID := make(map[string]string, len(tenants))
			for _, t := range tenants {
				tenantByID[t.ID] = t.Name
			}

			if len(keys) == 0 {
				fmt.Println("No API keys found.")
				return nil
			}

			fmt.Printf("%-36s  %-20s  %-20s  %s\n", "ID", "Tenant", "Name", "Created")
			fmt.Printf("%-36s  %-20s  %-20s  %s\n", "----", "------", "----", "-------")
			for _, k := range keys {
				fmt.Printf("%-36s  %-20s  %-20s  %s\n",
					k.ID, tenantByID[k.TenantID], k.Name, k.CreatedAt)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", defaultServerDBPath(), "Path to server database")
	return cmd
}

func newKeyRevokeCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "revoke <key-id>",
		Short: "Revoke an API key by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := db.Open(dbPath)
			if err != nil {
				return fmt.Errorf("opening db: %w", err)
			}
			defer database.Close()

			if err := database.RevokeAPIKey(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Key %s revoked.\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", defaultServerDBPath(), "Path to server database")
	return cmd
}

func defaultServerDBPath() string {
	home, _ := os.UserHomeDir()
	return home + "/.meerkat/server.db"
}
