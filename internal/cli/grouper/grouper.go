package grouper

import (
	"sort"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type packageKey struct {
	Purl string
	Kind string
}

func Group(packages <-chan api.Package) []api.Package {
	index := make(map[packageKey]*api.Package)
	order := []packageKey{} // preserve insertion order for stable output

	for p := range packages {
		p := p // copy
		key := packageKey{Purl: p.Purl, Kind: p.Kind}

		if existing, ok := index[key]; ok {
			mergeDirs(existing, p.Dirs)
			if p.Direct {
				existing.Direct = true
			}
			if scopePriority(p.Scope) > scopePriority(existing.Scope) {
				existing.Scope = p.Scope
			}
		} else {
			// copy dirs to avoid mutating caller's slice
			dirs := make([]string, len(p.Dirs))
			copy(dirs, p.Dirs)
			p.Dirs = dirs
			index[key] = &p
			order = append(order, key)
		}
	}

	result := make([]api.Package, 0, len(order))
	for _, key := range order {
		result = append(result, *index[key])
	}

	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})

	return result
}

func mergeDirs(dst *api.Package, newDirs []string) {
	seen := make(map[string]struct{}, len(dst.Dirs))
	for _, d := range dst.Dirs {
		seen[d] = struct{}{}
	}
	for _, d := range newDirs {
		if _, ok := seen[d]; !ok {
			dst.Dirs = append(dst.Dirs, d)
			seen[d] = struct{}{}
		}
	}
	sort.Strings(dst.Dirs)
}

func scopePriority(scope string) int {
	switch scope {
	case "runtime":
		return 2
	case "dev":
		return 1
	default:
		return 0
	}
}
