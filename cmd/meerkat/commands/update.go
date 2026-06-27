// Package-local: the `meerkat update` command. It reuses the published
// install.sh (same path as a fresh install) to pull the latest release binary,
// gating on a version check so an up-to-date install is a no-op.
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"
)

const (
	updateRepo = "ezequielcamezzana/meerkat"
	installURL = "https://raw.githubusercontent.com/" + updateRepo + "/main/install.sh"
	latestAPI  = "https://api.github.com/repos/" + updateRepo + "/releases/latest"
)

func NewUpdateCmd() *cobra.Command {
	var check, force bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update meerkat to the latest release",
		RunE: func(cmd *cobra.Command, args []string) error {
			latest, err := latestVersion(cmd.Context())
			if err != nil {
				return fmt.Errorf("checking latest release: %w", err)
			}

			newer, err := isNewer(latest, Version)
			if err != nil && !force {
				return err
			}

			if !newer && !force {
				fmt.Printf("Already up to date (%s).\n", Version)
				return nil
			}

			fmt.Printf("Update available: %s -> %s\n", Version, latest)
			if check {
				return nil
			}
			return runInstaller()
		},
	}

	cmd.Flags().BoolVar(&check, "check", false, "Only report whether an update is available")
	cmd.Flags().BoolVar(&force, "force", false, "Reinstall the latest release even if already current")
	return cmd
}

// latestVersion reads the latest release tag from the GitHub API.
func latestVersion(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github returned %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("no tag in latest release")
	}
	return release.TagName, nil
}

// isNewer reports whether latest is a newer release than the running binary.
// A source build (Version == "dev") never parses as semver, so callers must
// pass --force to update it — there's no version to compare against.
func isNewer(latest, current string) (bool, error) {
	latestV, err := semver.NewVersion(latest)
	if err != nil {
		return false, fmt.Errorf("parsing latest version %q: %w", latest, err)
	}
	currentV, err := semver.NewVersion(current)
	if err != nil {
		return false, fmt.Errorf("this build has no release version (%q); use --force to reinstall", current)
	}
	return latestV.GreaterThan(currentV), nil
}

// runInstaller pipes the published install.sh through sh, inheriting INSTALL_DIR
// and streaming its progress straight to the user.
func runInstaller() error {
	// WHY: shelling out to the same installer keeps one source of truth for
	// os/arch detection, download, and the sudo fallback — no duplicated logic.
	script := fmt.Sprintf("curl -fsSL %s | sh", installURL)
	c := exec.Command("sh", "-c", script)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("running installer: %w", err)
	}
	return nil
}
