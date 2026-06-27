package matcher

import "strings"

// Canonical returns the canonical ID for a vulnerability, preferring CVE IDs.
// Priority: own ID if CVE > aliases CVE > upstream CVE > own ID fallback.
func Canonical(v Vulnerability) string {
	// Prefer the canonical stored at fetch time (cache reads carry it). The
	// stored aliases drop the canonical, so recomputing from a cached struct
	// would otherwise lose a CVE that only lived in aliases.
	if v.CanonicalID != "" {
		return v.CanonicalID
	}
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	for _, u := range v.Upstream {
		if strings.HasPrefix(u, "CVE-") {
			return u
		}
	}
	return v.ID
}
