package scanner

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/ezequielcamezzana/meerkat/internal/cli/cache"
	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

// syftVersion is the version of the Syft library bundled with this build.
// Used as part of the cache key so a scanner upgrade invalidates stale entries.
const syftVersion = "1.44.0"

type CachedScanner struct {
	inner  Scanner
	cache  *cache.Cache
	hits   atomic.Int64
	misses atomic.Int64
}

func NewCachedScanner(inner Scanner, c *cache.Cache) *CachedScanner {
	return &CachedScanner{inner: inner, cache: c}
}

func (cs *CachedScanner) Scan(ctx context.Context, p walker.Project) ([]api.Package, error) {
	key, err := cs.cache.Key(p, "syft", syftVersion, cache.SchemaVersion)
	if err != nil {
		// key computation failed (e.g. lock file unreadable) — fall through to scanner
		slog.Warn("cache key error, falling through to scanner", "dir", p.Dir, "err", err)
		cs.misses.Add(1)
		return cs.inner.Scan(ctx, p)
	}

	if packages, ok := cs.cache.Get(key); ok {
		cs.hits.Add(1)
		// inject the current project dir — not stored in cache entries
		for i := range packages {
			packages[i].Dirs = []string{p.Dir}
		}
		return packages, nil
	}

	cs.misses.Add(1)
	packages, err := cs.inner.Scan(ctx, p)
	if err != nil {
		return nil, err
	}

	if err := cs.cache.Put(key, packages); err != nil {
		slog.Warn("cache write failed", "dir", p.Dir, "err", err)
	}

	return packages, nil
}

func (cs *CachedScanner) Hits() int64   { return cs.hits.Load() }
func (cs *CachedScanner) Misses() int64 { return cs.misses.Load() }
