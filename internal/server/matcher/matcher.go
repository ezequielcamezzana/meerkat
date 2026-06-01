package matcher

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

// VulnMatcher splits OSV access into two steps so callers can interpose a
// freshness check (the vulnerabilities table as cache) between them.
type VulnMatcher interface {
	// QueryBatch returns, per package PURL, the vuln IDs that affect it.
	QueryBatch(ctx context.Context, packages []api.Package) (map[string][]string, error)
	// FetchVulns fetches full vuln records for the given IDs.
	FetchVulns(ctx context.Context, ids []string) ([]Vulnerability, error)
}

// AssembleMatches joins the querybatch result with resolved vuln records and
// package metadata into per-(purl,vuln) matches. IDs missing from vulnByID are
// skipped (e.g. a fetch that failed).
func AssembleMatches(packages []api.Package, idsByPurl map[string][]string, vulnByID map[string]Vulnerability) []Match {
	pkgByPurl := make(map[string]api.Package, len(packages))
	for _, p := range packages {
		pkgByPurl[p.Purl] = p
	}
	var matches []Match
	for purl, ids := range idsByPurl {
		for _, id := range ids {
			v, ok := vulnByID[id]
			if !ok {
				continue
			}
			mt := Match{Purl: purl, Vulnerability: v}
			if p, ok := pkgByPurl[purl]; ok {
				mt.PackageScope = p.Scope
				mt.PackageKind = p.Kind
			}
			matches = append(matches, mt)
		}
	}
	return matches
}

type Match struct {
	Purl             string
	Vulnerability    Vulnerability
	PackageName      string
	PackageVersion   string
	PackageEcosystem string
	PackageScope     string
	PackageKind      string
	Dirs             []string
	ExposureScore    float64
}

type Vulnerability struct {
	ID          string
	Aliases     []string
	Upstream    []string
	Summary     string
	Details     string
	PublishedAt time.Time
	ModifiedAt  time.Time
	Source      string
	Raw         json.RawMessage
}
