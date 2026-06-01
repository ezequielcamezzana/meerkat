package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/cli/cache"
	"github.com/ezequielcamezzana/meerkat/internal/cli/cataloger"
	"github.com/ezequielcamezzana/meerkat/internal/cli/config"
	"github.com/ezequielcamezzana/meerkat/internal/cli/grouper"
	"github.com/ezequielcamezzana/meerkat/internal/cli/inventory"
	localnotifier "github.com/ezequielcamezzana/meerkat/internal/cli/notifier"
	"github.com/ezequielcamezzana/meerkat/internal/cli/scanner"
	"github.com/ezequielcamezzana/meerkat/internal/cli/uploader"
	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func NewScanCmd() *cobra.Command {
	var (
		root     string
		output   string
		noCache  bool
		noUpload bool
		workers  int
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan this machine for software dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), root, output, noCache, noUpload, workers)
		},
	}

	cmd.Flags().StringVar(&root, "root", "", "Override scan root path from config")
	cmd.Flags().StringVar(&output, "output", "", "Write inventory to this path instead of uploading")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "Bypass cache reads (still writes to cache)")
	cmd.Flags().BoolVar(&noUpload, "no-upload", false, "Skip upload step")
	cmd.Flags().IntVar(&workers, "workers", runtime.NumCPU(), "Number of parallel cataloger workers")

	return cmd
}

func runScan(ctx context.Context, rootOverride, output string, noCache, noUpload bool, workers int) error {
	cfg, err := config.Load()
	if err != nil {
		if errors.Is(err, config.ErrNotConfigured) {
			return fmt.Errorf("meerkat is not configured; run `meerkat config init`")
		}
		return err
	}

	scanRoot := cfg.Scan.Root
	if rootOverride != "" {
		scanRoot = rootOverride
	}
	if output != "" {
		noUpload = true
	}

	// build scanner
	cacheDir := filepath.Join(config.ConfigDir(), "cache")
	c := cache.New(cacheDir)

	var s scanner.Scanner = scanner.NewSyftScanner()
	var cached *scanner.CachedScanner
	if !noCache {
		cached = scanner.NewCachedScanner(s, c)
		s = cached
	}

	startedAt := time.Now()
	scanID := uuid.NewString()

	// walk — drain eagerly so we can measure walker time and count projects
	// per ecosystem separately from cataloging.
	w := walker.NewFSWalker()
	walkStart := time.Now()
	projectsByEcosystem := map[string]int{}
	var projectList []walker.Project
	for p := range w.Walk(ctx, scanRoot, cfg.Scan.Excludes) {
		projectList = append(projectList, p)
		projectsByEcosystem[p.Ecosystem]++
	}
	walkMillis := time.Since(walkStart).Milliseconds()

	// catalog
	catalogStart := time.Now()
	projects := make(chan walker.Project)
	go func() {
		defer close(projects)
		for _, p := range projectList {
			select {
			case projects <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	cat := cataloger.New(s, workers)
	packages, errs := cat.Catalog(ctx, projects)

	// collect errors concurrently while grouper drains packages
	var scanErrors []api.ScanError
	errsDone := make(chan struct{})
	go func() {
		defer close(errsDone)
		for pe := range errs {
			slog.Warn("project scan error", "dir", pe.Project.Dir, "ecosystem", pe.Project.Ecosystem, "err", pe.Err)
			scanErrors = append(scanErrors, api.ScanError{
				ProjectDir: pe.Project.Dir,
				Ecosystem:  pe.Project.Ecosystem,
				Message:    pe.Err.Error(),
			})
		}
	}()

	grouped := grouper.Group(packages)
	<-errsDone

	catalogMillis := time.Since(catalogStart).Milliseconds()
	scanMillis := time.Since(startedAt).Milliseconds()

	// count cache stats
	var hits, misses int
	if cached != nil {
		hits = int(cached.Hits())
		misses = int(cached.Misses())
	} else {
		misses = len(grouped)
	}

	hostname, _ := os.Hostname()
	inv := api.Inventory{
		SchemaVersion: "0.1.0",
		Scanner: api.Scanner{
			Name:    "meerkat",
			Version: Version,
		},
		Endpoint: api.Endpoint{
			ID:       cfg.Endpoint.ID,
			Hostname: hostname,
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
			User:     os.Getenv("USER"),
			Tags:     cfg.Endpoint.Tags,
		},
		Scan: api.Scan{
			ID:                  scanID,
			StartedAt:           startedAt,
			Root:                scanRoot,
			ProjectsScanned:     len(projectList),
			ProjectsByEcosystem: projectsByEcosystem,
			WalkMillis:          walkMillis,
			CatalogMillis:       catalogMillis,
			ScanMillis:          scanMillis,
			CacheHits:           hits,
			CacheMisses:         misses,
			Errors:              scanErrors,
		},
		Packages: grouped,
	}

	if len(scanErrors) > 0 {
		slog.Warn("scan completed with errors", "count", len(scanErrors))
	}

	// write to file if --output given
	if output != "" {
		if err := inventory.WriteFile(output, inv); err != nil {
			return fmt.Errorf("writing inventory: %w", err)
		}
		slog.Info("inventory written", "path", output, "packages", len(grouped))
		return nil
	}

	// upload
	if !noUpload {
		local := localnotifier.New(cfg.Notifications.Local)
		pendingDir := filepath.Join(config.ConfigDir(), "pending")
		u := uploader.New(cfg.Server.URL, cfg.Server.Token, pendingDir)

		uploadResult, uploadErr := u.Upload(ctx, inv)
		if uploadErr != nil {
			slog.Warn("upload failed", "err", uploadErr)
		}
		slog.Info("upload result", "new_vulns", len(uploadResult.NewVulnerabilities), "endpoint_url", uploadResult.EndpointURL)

		if len(uploadResult.NewVulnerabilities) > 0 {
			endpointURL := uploadResult.EndpointURL
			if endpointURL == "" && cfg.Server.URL != "" {
				endpointURL = cfg.Server.URL + "/endpoints/" + cfg.Endpoint.ID
			}
			if err := local.Notify(inv.Endpoint, uploadResult.NewVulnerabilities, endpointURL); err != nil {
				slog.Warn("local notification failed", "err", err)
			}
		}

		if n, err := u.DrainPending(ctx); err != nil {
			slog.Warn("drain pending failed", "err", err)
		} else if n > 0 {
			slog.Info("drained pending inventories", "count", n)
		}
	}

	// evict stale cache entries
	if !noCache {
		if err := c.Evict(); err != nil {
			slog.Warn("cache eviction failed", "err", err)
		}
	}

	return nil
}
