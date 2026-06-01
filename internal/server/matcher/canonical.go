package matcher

import "strings"

// Canonical returns the canonical ID for a vulnerability, preferring CVE IDs.
// Priority: own ID if CVE > aliases CVE > upstream CVE > own ID fallback.
func Canonical(v Vulnerability) string {
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
