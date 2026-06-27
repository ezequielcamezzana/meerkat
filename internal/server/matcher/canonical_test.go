package matcher_test

import (
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/stretchr/testify/assert"
)

func TestCanonical(t *testing.T) {
	cases := []struct {
		id          string
		aliases     []string
		upstream    []string
		canonicalID string
		expected    string
	}{
		{"CVE-2024-1", nil, nil, "", "CVE-2024-1"},
		{"GHSA-x", []string{"CVE-2024-2"}, nil, "", "CVE-2024-2"},
		{"RUSTSEC-1", nil, []string{"CVE-2024-3"}, "", "CVE-2024-3"},
		{"GHSA-y", nil, nil, "", "GHSA-y"},
		{"GHSA-z", []string{"GHSA-other", "CVE-2024-4"}, []string{"CVE-2024-5"}, "", "CVE-2024-4"},
		// Cache read: aliases had the canonical (CVE) stripped at write time, but
		// the stored CanonicalID is authoritative and must win.
		{"GHSA-cached", []string{"GHSA-other"}, nil, "CVE-2024-6", "CVE-2024-6"},
	}

	for _, tc := range cases {
		v := matcher.Vulnerability{ID: tc.id, Aliases: tc.aliases, Upstream: tc.upstream, CanonicalID: tc.canonicalID}
		assert.Equal(t, tc.expected, matcher.Canonical(v), "id=%s", tc.id)
	}
}
