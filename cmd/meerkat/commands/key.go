package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	clicfg "github.com/ezequielcamezzana/meerkat/internal/cli/config"
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
		newKeyGuestCmd(),
		newKeyListCmd(),
		newKeyRevokeCmd(),
	)
	return cmd
}

// newKeyGuestCmd mints a read-only (guest) key. Unlike `create`, it talks to the
// server over HTTP using the complete key already in config, and the server scopes
// the guest key to that key's tenant — you can't target an arbitrary tenant.
func newKeyGuestCmd() *cobra.Command {
	var (
		keyName     string
		serverURL   string
		serverToken string
	)

	cmd := &cobra.Command{
		Use:   "guest",
		Short: "Create a read-only (guest) API key for your tenant",
		Long: "Creates a read-only key scoped to the tenant of the complete key in\n" +
			"your config. Requires a configured server URL and (complete) token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverURL == "" || serverToken == "" {
				cfg, err := clicfg.Load()
				if err != nil {
					return fmt.Errorf("loading config: %w", err)
				}
				if serverURL == "" {
					serverURL = cfg.Server.URL
				}
				if serverToken == "" {
					serverToken = cfg.Server.Token
				}
			}
			if serverURL == "" || serverToken == "" {
				return fmt.Errorf("a server URL and a complete API key are required (run `meerkat config init`)")
			}

			token, err := requestGuestKey(cmd.Context(), serverURL, serverToken, keyName)
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Guest (read-only) key created.\n")
			fmt.Fprintf(os.Stderr, "Store this key securely — it will not be shown again:\n\n")
			fmt.Println(token)
			return nil
		},
	}

	cmd.Flags().StringVar(&keyName, "name", "", "Human label for this key (default: guest-key)")
	cmd.Flags().StringVar(&serverURL, "server", "", "Server URL (default: from config)")
	cmd.Flags().StringVar(&serverToken, "token", "", "Complete API key to authenticate with (default: from config)")
	return cmd
}

// requestGuestKey POSTs to the guest-key endpoint and returns the new token.
func requestGuestKey(ctx context.Context, serverURL, token, name string) (string, error) {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/keys/guest", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("reaching server: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", fmt.Errorf("your API key is not valid")
	case resp.StatusCode == http.StatusForbidden:
		return "", fmt.Errorf("your API key is read-only and cannot create guest keys")
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		msg, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, string(msg))
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil || parsed.Token == "" {
		return "", fmt.Errorf("server response missing token")
	}
	return parsed.Token, nil
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

			key, err := database.CreateAPIKey(ctx, uuid.NewString(), tenant.ID, keyName, db.RoleComplete, hash, time.Now().UTC().Format(time.RFC3339))
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

			fmt.Printf("%-36s  %-20s  %-20s  %-9s  %s\n", "ID", "Tenant", "Name", "Role", "Created")
			fmt.Printf("%-36s  %-20s  %-20s  %-9s  %s\n", "----", "------", "----", "----", "-------")
			for _, k := range keys {
				fmt.Printf("%-36s  %-20s  %-20s  %-9s  %s\n",
					k.ID, tenantByID[k.TenantID], k.Name, k.Role, k.CreatedAt)
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
