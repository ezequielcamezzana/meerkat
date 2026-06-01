package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/stretchr/testify/require"
)

type expectedPkg struct {
	Purl      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

var fixtureTests = []struct {
	dir        string
	ecosystem  string
	lockFile   string
	skipReason string
}{
	{dir: "npm-simple", ecosystem: "npm", lockFile: "package-lock.json"},
	{dir: "golang-simple", ecosystem: "golang", lockFile: "go.sum"},
	{dir: "rust-simple", ecosystem: "cargo", lockFile: "Cargo.lock"},
	{dir: "python-poetry", ecosystem: "pypi", lockFile: "poetry.lock"},
	{dir: "conan-simple", ecosystem: "conan", lockFile: "conan.lock"},
}

func TestSyftScanner_fixtures(t *testing.T) {
	s := NewSyftScanner()

	for _, tc := range fixtureTests {
		t.Run(tc.dir, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			fixtureDir := filepath.Join("..", "..", "..", "testdata", "projects", tc.dir)
			lockFilePath := filepath.Join(fixtureDir, tc.lockFile)

			p := walker.Project{
				Ecosystem:      tc.ecosystem,
				PackageManager: tc.ecosystem,
				Dir:            fixtureDir,
				LockFiles:      []string{lockFilePath},
			}

			packages, err := s.Scan(context.Background(), p)
			require.NoError(t, err)
			require.NotEmpty(t, packages, "expected at least one package from %s", tc.dir)

			// verify all expected PURLs are present
			expectedPath := filepath.Join(fixtureDir, "expected-packages.json")
			data, err := os.ReadFile(expectedPath)
			require.NoError(t, err)

			var expected []expectedPkg
			require.NoError(t, json.Unmarshal(data, &expected))

			purlSet := make(map[string]bool, len(packages))
			for _, pkg := range packages {
				purlSet[pkg.Purl] = true
			}

			for _, exp := range expected {
				require.True(t, purlSet[exp.Purl], "expected PURL %q not found in scan results for %s", exp.Purl, tc.dir)
			}

			// verify all packages have required fields set
			for _, pkg := range packages {
				require.NotEmpty(t, pkg.Name)
				require.NotEmpty(t, pkg.Purl)
				require.Equal(t, "project-dependency", pkg.Kind)
				require.Contains(t, pkg.Dirs, fixtureDir)
			}
		})
	}
}
