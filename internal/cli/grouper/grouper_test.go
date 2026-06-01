package grouper

import (
	"testing"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/require"
)

func makeChan(pkgs ...api.Package) <-chan api.Package {
	ch := make(chan api.Package, len(pkgs))
	for _, p := range pkgs {
		ch <- p
	}
	close(ch)
	return ch
}

func TestGroup_noDuplicates(t *testing.T) {
	input := []api.Package{
		{Name: "react", Version: "18.2.0", Purl: "pkg:npm/react@18.2.0", Kind: "project-dependency", Ecosystem: "npm", Dirs: []string{"/a"}},
		{Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21", Kind: "project-dependency", Ecosystem: "npm", Dirs: []string{"/a"}},
	}
	result := Group(makeChan(input...))

	require.Len(t, result, 2)
	// sorted by name: lodash < react
	require.Equal(t, "lodash", result[0].Name)
	require.Equal(t, "react", result[1].Name)
}

func TestGroup_mergeDirs(t *testing.T) {
	p := api.Package{Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21", Kind: "project-dependency", Ecosystem: "npm"}
	p1 := p
	p1.Dirs = []string{"/b"}
	p2 := p
	p2.Dirs = []string{"/a"}

	result := Group(makeChan(p1, p2))

	require.Len(t, result, 1)
	require.Equal(t, []string{"/a", "/b"}, result[0].Dirs) // sorted
}

func TestGroup_mergeDirectTrueWins(t *testing.T) {
	p := api.Package{Name: "x", Purl: "pkg:npm/x@1", Kind: "project-dependency", Ecosystem: "npm", Dirs: []string{"/a"}}
	indirect := p
	indirect.Direct = false
	direct := p
	direct.Direct = true
	direct.Dirs = []string{"/b"}

	result := Group(makeChan(indirect, direct))
	require.Len(t, result, 1)
	require.True(t, result[0].Direct)
}

func TestGroup_mergeScopeRuntimeWins(t *testing.T) {
	p := api.Package{Name: "x", Purl: "pkg:npm/x@1", Kind: "project-dependency", Ecosystem: "npm", Dirs: []string{"/a"}}
	dev := p
	dev.Scope = "dev"
	runtime := p
	runtime.Scope = "runtime"
	runtime.Dirs = []string{"/b"}

	result := Group(makeChan(dev, runtime))
	require.Len(t, result, 1)
	require.Equal(t, "runtime", result[0].Scope)
}

func TestGroup_emptyChan(t *testing.T) {
	result := Group(makeChan())
	require.NotNil(t, result)
	require.Empty(t, result)
}

func TestGroup_sortedByEcosystemNameVersion(t *testing.T) {
	pkgs := []api.Package{
		{Name: "z", Version: "1.0", Purl: "pkg:npm/z@1.0", Kind: "project-dependency", Ecosystem: "npm"},
		{Name: "a", Version: "2.0", Purl: "pkg:cargo/a@2.0", Kind: "project-dependency", Ecosystem: "cargo"},
		{Name: "a", Version: "1.0", Purl: "pkg:npm/a@1.0", Kind: "project-dependency", Ecosystem: "npm"},
	}
	result := Group(makeChan(pkgs...))

	require.Len(t, result, 3)
	require.Equal(t, "cargo", result[0].Ecosystem)
	require.Equal(t, "a", result[1].Name)
	require.Equal(t, "npm", result[1].Ecosystem)
	require.Equal(t, "z", result[2].Name)
}
