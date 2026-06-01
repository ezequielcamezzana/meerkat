package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

const SchemaVersion = "0.1.0"

type CacheInfo struct {
	Entries   int
	TotalSize int64
}

type Cache struct {
	dir string
}

func New(dir string) *Cache {
	return &Cache{dir: dir}
}

func (c *Cache) projectsDir() string {
	return filepath.Join(c.dir, "projects")
}

func (c *Cache) entryPath(key string) string {
	return filepath.Join(c.projectsDir(), key+".json")
}

// Key computes a content-addressed cache key from the project's lock file contents
// plus scanner identity. Two projects with identical lock files share one cache entry.
func (c *Cache) Key(p walker.Project, scannerName, scannerVersion, schemaVersion string) (string, error) {
	var fileHashes []string
	for _, lf := range p.LockFiles {
		data, err := os.ReadFile(lf)
		if err != nil {
			return "", fmt.Errorf("reading lock file %s: %w", lf, err)
		}
		h := sha256.Sum256(data)
		fileHashes = append(fileHashes, hex.EncodeToString(h[:]))
	}
	sort.Strings(fileHashes)

	combined := ""
	for _, h := range fileHashes {
		combined += h
	}
	combined += scannerName + scannerVersion + schemaVersion

	final := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(final[:]), nil
}

func (c *Cache) Get(key string) ([]api.Package, bool) {
	path := c.entryPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	// touch for LRU tracking
	now := time.Now()
	_ = os.Chtimes(path, now, now)

	return entry.Packages, true
}

func (c *Cache) Put(key string, packages []api.Package) error {
	if err := os.MkdirAll(c.projectsDir(), 0700); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}

	// strip Dirs before storing — injected at hit time by CachedScanner
	stripped := make([]api.Package, len(packages))
	for i, p := range packages {
		stripped[i] = p
		stripped[i].Dirs = nil
	}

	entry := cacheEntry{
		SchemaVersion: SchemaVersion,
		Scanner:       cacheScanner{Name: "syft"},
		CachedAt:      time.Now().UTC(),
		Packages:      stripped,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling cache entry: %w", err)
	}

	return os.WriteFile(c.entryPath(key), data, 0600)
}

func (c *Cache) Clear() error {
	return os.RemoveAll(c.projectsDir())
}

func (c *Cache) Info() CacheInfo {
	var info CacheInfo
	_ = filepath.WalkDir(c.projectsDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		info.Entries++
		info.TotalSize += fi.Size()
		return nil
	})
	return info
}

func (c *Cache) Evict() error {
	dir := c.projectsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	type entry struct {
		path     string
		accessed time.Time
	}

	var all []entry
	cutoff := time.Now().AddDate(0, 0, -30)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		accessed := fi.ModTime()
		if accessed.Before(cutoff) {
			_ = os.Remove(path)
			continue
		}
		all = append(all, entry{path: path, accessed: accessed})
	}

	// LRU cap: keep at most 10_000 entries
	if len(all) > 50_000 {
		sort.Slice(all, func(i, j int) bool {
			return all[i].accessed.Before(all[j].accessed)
		})
		for _, e := range all[:len(all)-50_000] {
			_ = os.Remove(e.path)
		}
	}

	return nil
}

// --- internal types ---

type cacheScanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cacheEntry struct {
	SchemaVersion string        `json:"schema_version"`
	Scanner       cacheScanner  `json:"scanner"`
	CachedAt      time.Time     `json:"cached_at"`
	Packages      []api.Package `json:"packages"`
}
