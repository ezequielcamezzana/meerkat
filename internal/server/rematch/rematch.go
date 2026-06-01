// Package rematch implements passive scanning: periodically re-evaluating the
// stored inventories of stale endpoints against fresh OSV data, so a machine
// that's offline still gets flagged when a new CVE hits a package it had.
package rematch

import (
	"context"
	"log/slog"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
)

type Rematcher struct {
	db           *db.DB
	ingest       *ingest.Ingest
	interval     time.Duration
	batch        int
	staleHours   int
	rematchHours int
}

func New(database *db.DB, ing *ingest.Ingest, interval time.Duration, batch int) *Rematcher {
	if batch <= 0 {
		batch = 100
	}
	return &Rematcher{
		db:           database,
		ingest:       ing,
		interval:     interval,
		batch:        batch,
		staleHours:   24,
		rematchHours: 24,
	}
}

// Start runs the passive re-match loop until ctx is cancelled. A non-positive
// interval disables it.
func (r *Rematcher) Start(ctx context.Context) {
	if r.interval <= 0 {
		slog.Info("passive re-matching disabled")
		return
	}
	slog.Info("passive re-matching enabled", "interval", r.interval.String(), "batch", r.batch)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := r.RunOnce(ctx); err != nil {
				slog.Warn("passive re-match pass failed", "err", err)
			} else if n > 0 {
				slog.Info("passive re-match pass done", "endpoints", n)
			}
		}
	}
}

// RunOnce re-evaluates one batch of stale endpoints whose vuln data is overdue.
// One bad endpoint is logged and skipped, not fatal to the pass.
func (r *Rematcher) RunOnce(ctx context.Context) (int, error) {
	targets, err := r.db.ListRematchTargets(ctx, r.staleHours, r.rematchHours, r.batch)
	if err != nil {
		return 0, err
	}
	for _, t := range targets {
		if _, err := r.ingest.Rematch(ctx, t.Endpoint, t.Packages, t.TenantID); err != nil {
			slog.Warn("re-match failed", "endpoint", t.Endpoint.ID, "err", err)
		}
	}
	return len(targets), nil
}
