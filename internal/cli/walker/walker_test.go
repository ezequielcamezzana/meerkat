package walker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func collect(ctx context.Context, ch <-chan Project) []Project {
	var projects []Project
	for p := range ch {
		projects = append(projects, p)
	}
	return projects
}

func touch(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, []byte{}, 0644))
}

func TestWalk_detectsLockFiles(t *testing.T) {
	dir := t.TempDir()
	touch(t, filepath.Join(dir, "package-lock.json"))
	touch(t, filepath.Join(dir, "sub", "nested", "Cargo.lock"))

	w := NewFSWalker()
	projects := collect(context.Background(), w.Walk(context.Background(), dir, nil))

	require.Len(t, projects, 2)
}

func TestWalk_excludesDirectories(t *testing.T) {
	dir := t.TempDir()
	touch(t, filepath.Join(dir, "node_modules", "package-lock.json"))

	w := NewFSWalker()
	projects := collect(context.Background(), w.Walk(context.Background(), dir, []string{"node_modules"}))

	require.Empty(t, projects)
}

func TestWalk_multipleLockFilesInSameDir(t *testing.T) {
	dir := t.TempDir()
	touch(t, filepath.Join(dir, "package-lock.json"))
	touch(t, filepath.Join(dir, "yarn.lock"))

	w := NewFSWalker()
	projects := collect(context.Background(), w.Walk(context.Background(), dir, nil))

	require.Len(t, projects, 2)
	require.Equal(t, dir, projects[0].Dir)
	require.Equal(t, dir, projects[1].Dir)
}

func TestWalk_contextCancel(t *testing.T) {
	dir := t.TempDir()
	// create many lock files to ensure the walker is still running when we cancel
	for i := 0; i < 20; i++ {
		touch(t, filepath.Join(dir, "sub"+string(rune('a'+i)), "package-lock.json"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := NewFSWalker()
	ch := w.Walk(ctx, dir, nil)

	// read one then cancel
	<-ch
	cancel()

	// drain remaining — channel must close (no deadlock)
	for range ch {
	}
}

func TestWalk_emptyDir(t *testing.T) {
	dir := t.TempDir()

	w := NewFSWalker()
	projects := collect(context.Background(), w.Walk(context.Background(), dir, nil))

	require.Empty(t, projects)
}
