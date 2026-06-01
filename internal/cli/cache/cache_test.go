package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/require"
)

func makeProject(t *testing.T, lockContent string) walker.Project {
	t.Helper()
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	require.NoError(t, os.WriteFile(lockPath, []byte(lockContent), 0644))
	return walker.Project{
		Ecosystem:  "npm",
		Dir:        dir,
		LockFiles:  []string{lockPath},
	}
}

func TestPutGet_roundtrip(t *testing.T) {
	c := New(t.TempDir())
	p := makeProject(t, `{"lockfileVersion":3}`)

	key, err := c.Key(p, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, err)

	pkgs := []api.Package{
		{Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21", Dirs: []string{"/some/dir"}},
	}

	require.NoError(t, c.Put(key, pkgs))

	got, ok := c.Get(key)
	require.True(t, ok)
	require.Len(t, got, 1)
	require.Equal(t, "lodash", got[0].Name)
	// Dirs must be stripped in the stored entry
	require.Empty(t, got[0].Dirs)
}

func TestGet_miss(t *testing.T) {
	c := New(t.TempDir())
	_, ok := c.Get("nonexistentkey")
	require.False(t, ok)
}

func TestKey_deterministic(t *testing.T) {
	c := New(t.TempDir())
	p := makeProject(t, `{"lockfileVersion":3,"packages":{}}`)

	k1, err := c.Key(p, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, err)
	k2, err := c.Key(p, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, err)

	require.Equal(t, k1, k2)
}

func TestKey_changesWithContent(t *testing.T) {
	c := New(t.TempDir())
	p1 := makeProject(t, `{"lockfileVersion":3,"packages":{}}`)
	p2 := makeProject(t, `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`)

	k1, err := c.Key(p1, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, err)
	k2, err := c.Key(p2, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, err)

	require.NotEqual(t, k1, k2)
}

func TestKey_changesWithScannerVersion(t *testing.T) {
	c := New(t.TempDir())
	p := makeProject(t, `{"lockfileVersion":3}`)

	k1, err := c.Key(p, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, err)
	k2, err := c.Key(p, "syft", "1.45.0", SchemaVersion)
	require.NoError(t, err)

	require.NotEqual(t, k1, k2)
}

func TestClear(t *testing.T) {
	c := New(t.TempDir())
	p := makeProject(t, `{"lockfileVersion":3}`)
	key, _ := c.Key(p, "syft", "1.44.0", SchemaVersion)
	require.NoError(t, c.Put(key, []api.Package{{Name: "a", Purl: "pkg:npm/a@1"}}))

	require.Equal(t, 1, c.Info().Entries)
	require.NoError(t, c.Clear())
	require.Equal(t, 0, c.Info().Entries)
}
