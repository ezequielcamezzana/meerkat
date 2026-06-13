// Package walker traverses the filesystem to discover projects by their
// lockfiles, skipping ignored and irrelevant directories.
package walker

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Project struct {
	Ecosystem      string
	PackageManager string
	Dir            string
	LockFiles      []string
}

type Walker interface {
	Walk(ctx context.Context, root string, excludes []string) <-chan Project
}

type FSWalker struct{}

func NewFSWalker() *FSWalker {
	return &FSWalker{}
}

func (w *FSWalker) Walk(ctx context.Context, root string, excludes []string) <-chan Project {
	ch := make(chan Project)

	basenames := make(map[string]struct{})
	absolute := make(map[string]struct{})
	var patterns []string

	for _, e := range excludes {
		switch {
		case strings.Contains(e, "*"):
			patterns = append(patterns, expandTilde(e))
		case strings.HasPrefix(e, "/") || strings.HasPrefix(e, "~/"):
			absolute[expandTilde(e)] = struct{}{}
		default:
			basenames[e] = struct{}{}
		}
	}

	shouldSkip := func(path string, d fs.DirEntry) bool {
		if !d.IsDir() {
			return false
		}
		if _, ok := basenames[d.Name()]; ok {
			return true
		}
		if _, ok := absolute[path]; ok {
			return true
		}
		for _, pat := range patterns {
			if matched, _ := filepath.Match(pat, path); matched {
				return true
			}
		}
		return false
	}

	go func() {
		defer close(ch)

		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				slog.Debug("walker: skipping path", "path", path, "err", err)
				return nil
			}

			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}

			if shouldSkip(path, d) {
				return filepath.SkipDir
			}

			if d.IsDir() {
				return nil
			}

			info, ok := LockFileInfo(d.Name())
			if !ok {
				return nil
			}

			p := Project{
				Ecosystem:      info.Ecosystem,
				PackageManager: info.PackageManager,
				Dir:            filepath.Dir(path),
				LockFiles:      []string{path},
			}

			select {
			case ch <- p:
			case <-ctx.Done():
				return filepath.SkipAll
			}

			return nil
		})
	}()

	return ch
}

func expandTilde(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
