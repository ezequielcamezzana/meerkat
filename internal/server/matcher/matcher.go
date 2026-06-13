// Package matcher resolves package vulnerabilities against OSV data and
// extracts fixed-version information.
package matcher

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

// FixedVersion extracts the version(s) that resolve a vuln for a given package
// from the raw OSV record (affected[].ranges[].events[].fixed), matched by
// package name. Returns "" when OSV lists no fix (no patch available yet).
func FixedVersion(raw json.RawMessage, packageName string) string {
	var rec struct {
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if json.Unmarshal(raw, &rec) != nil {
		return ""
	}

	seen := make(map[string]struct{})
	var fixed []string
	for _, a := range rec.Affected {
		if !strings.EqualFold(a.Package.Name, packageName) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					if _, dup := seen[f]; !dup {
						seen[f] = struct{}{}
						fixed = append(fixed, f)
					}
				}
			}
		}
	}
	return strings.Join(fixed, ", ")
}

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
	FixedVersion     string
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
