package scanner

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type SyftScanner struct{}

func NewSyftScanner() *SyftScanner {
	return &SyftScanner{}
}

func (s *SyftScanner) Scan(ctx context.Context, p walker.Project) ([]api.Package, error) {
	src, err := syft.GetSource(ctx, p.Dir, nil)
	if err != nil {
		return nil, fmt.Errorf("creating source for %s: %w", p.Dir, err)
	}
	defer src.Close()

	catalogers := syftCatalogers(p.Ecosystem)
	cfg := syft.DefaultCreateSBOMConfig().
		WithCatalogerSelection(
			cataloging.NewSelectionRequest().
				WithDefaults(catalogers...),
		)

	sbom, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", p.Dir, err)
	}

	var packages []api.Package
	for syftPkg := range sbom.Artifacts.Packages.Enumerate() {
		ap := convertPackage(syftPkg, p.Dir)
		if ap.Purl == "" {
			continue
		}
		packages = append(packages, ap)
	}

	return packages, nil
}

func convertPackage(p pkg.Package, dir string) api.Package {
	return api.Package{
		Name:      p.Name,
		Version:   p.Version,
		Ecosystem: pkgTypeToEcosystem(p.Type),
		Purl:      p.PURL,
		Scope:     "runtime",//TODO investigating
		Direct:    false,
		Kind:      "project-dependency",
		Dirs:      []string{dir},
	}
}

func pkgTypeToEcosystem(t pkg.Type) string {
	switch t {
	case pkg.NpmPkg:
		return "npm"
	case pkg.GoModulePkg:
		return "golang"
	case pkg.RustPkg:
		return "cargo"
	case pkg.PythonPkg:
		return "pypi"
	case pkg.ConanPkg:
		return "conan"
	default:
		return string(t)
	}
}

// syftCatalogers returns the cataloger names to use for a given ecosystem.
// Running only the relevant catalogers avoids unnecessary work.
func syftCatalogers(ecosystem string) []string {
	switch ecosystem {
	case "npm":
		return []string{"javascript-lock-cataloger"}
	case "golang":
		return []string{"go-module-file-cataloger"}
	case "cargo":
		return []string{"rust-cargo-lock-cataloger"}
	case "pypi":
		return []string{"python-package-cataloger"}
	case "conan":
		return []string{"conan-cataloger"}
	default:
		return []string{"language"}
	}
}
