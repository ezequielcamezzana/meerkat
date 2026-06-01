package cataloger

import (
	"context"
	"errors"
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/require"
)

// fakeScanner lets tests control what Scan returns per project dir.
type fakeScanner struct {
	results map[string][]api.Package
	errors  map[string]error
	panics  map[string]bool
}

func (f *fakeScanner) Scan(_ context.Context, p walker.Project) ([]api.Package, error) {
	if f.panics[p.Dir] {
		panic("fake panic in scanner")
	}
	if err, ok := f.errors[p.Dir]; ok {
		return nil, err
	}
	return f.results[p.Dir], nil
}

func sendProjects(projects ...walker.Project) <-chan walker.Project {
	ch := make(chan walker.Project, len(projects))
	for _, p := range projects {
		ch <- p
	}
	close(ch)
	return ch
}

func drainAll(pkgCh <-chan api.Package, errCh <-chan ProjectError) ([]api.Package, []ProjectError) {
	var pkgs []api.Package
	var errs []ProjectError
	for pkgCh != nil || errCh != nil {
		select {
		case p, ok := <-pkgCh:
			if !ok {
				pkgCh = nil
			} else {
				pkgs = append(pkgs, p)
			}
		case e, ok := <-errCh:
			if !ok {
				errCh = nil
			} else {
				errs = append(errs, e)
			}
		}
	}
	return pkgs, errs
}

func TestCatalog_allSucceed(t *testing.T) {
	s := &fakeScanner{
		results: map[string][]api.Package{
			"/a": {{Name: "lodash", Purl: "pkg:npm/lodash@4.17.21"}},
			"/b": {{Name: "react", Purl: "pkg:npm/react@18.2.0"}},
			"/c": {{Name: "uuid", Purl: "pkg:golang/github.com/google/uuid@v1.6.0"}},
		},
	}

	cat := New(s, 3)
	projects := sendProjects(
		walker.Project{Dir: "/a"},
		walker.Project{Dir: "/b"},
		walker.Project{Dir: "/c"},
	)

	pkgCh, errCh := cat.Catalog(context.Background(), projects)
	pkgs, errs := drainAll(pkgCh, errCh)

	require.Len(t, pkgs, 3)
	require.Empty(t, errs)
}

func TestCatalog_partialError(t *testing.T) {
	s := &fakeScanner{
		results: map[string][]api.Package{
			"/a": {{Name: "lodash", Purl: "pkg:npm/lodash@4.17.21"}},
			"/c": {{Name: "uuid", Purl: "pkg:golang/github.com/google/uuid@v1.6.0"}},
		},
		errors: map[string]error{
			"/b": errors.New("scan failed"),
		},
	}

	cat := New(s, 2)
	projects := sendProjects(
		walker.Project{Dir: "/a"},
		walker.Project{Dir: "/b"},
		walker.Project{Dir: "/c"},
	)

	pkgCh, errCh := cat.Catalog(context.Background(), projects)
	pkgs, errs := drainAll(pkgCh, errCh)

	require.Len(t, pkgs, 2)
	require.Len(t, errs, 1)
	require.Equal(t, "/b", errs[0].Project.Dir)
}

func TestCatalog_panicRecovered(t *testing.T) {
	s := &fakeScanner{
		results: map[string][]api.Package{
			"/a": {{Name: "lodash", Purl: "pkg:npm/lodash@4.17.21"}},
		},
		panics: map[string]bool{"/b": true},
	}

	cat := New(s, 2)
	projects := sendProjects(
		walker.Project{Dir: "/a"},
		walker.Project{Dir: "/b"},
	)

	pkgCh, errCh := cat.Catalog(context.Background(), projects)
	pkgs, errs := drainAll(pkgCh, errCh)

	require.Len(t, pkgs, 1)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Err.Error(), "panic")
}

func TestCatalog_contextCancel(t *testing.T) {
	s := &fakeScanner{
		results: map[string][]api.Package{
			"/a": {{Name: "lodash", Purl: "pkg:npm/lodash@4.17.21"}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cat := New(s, 2)
	projects := sendProjects(walker.Project{Dir: "/a"})

	pkgCh, errCh := cat.Catalog(ctx, projects)

	// must drain without deadlock
	_, _ = drainAll(pkgCh, errCh)
}
