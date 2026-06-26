package db

import "testing"

func sampleVulns() []VulnGrouped {
	return []VulnGrouped{
		{CanonicalID: "CVE-2026-1", Aliases: []string{"GHSA-aaaa"}, ExposureBucket: "critical",
			AffectedPackages: []AffectedPkg{{Dirs: []string{"/app/api"}}}},
		{CanonicalID: "CVE-2026-2", Aliases: []string{"GHSA-bbbb"}, ExposureBucket: "high",
			AffectedPackages: []AffectedPkg{{Dirs: []string{"/app/api", "/app/worker"}}}},
		{CanonicalID: "CVE-2026-3", Aliases: []string{"GHSA-cccc"}, ExposureBucket: "high",
			AffectedPackages: []AffectedPkg{{Dirs: []string{"/app/worker"}}}},
		{CanonicalID: "CVE-2026-4", Aliases: []string{"GHSA-dddd"}, ExposureBucket: "low"},
	}
}

func TestBucketCounts(t *testing.T) {
	got := bucketCounts(sampleVulns())
	want := map[string]int{"critical": 1, "high": 2, "medium": 0, "low": 1}
	for b, n := range want {
		if got[b] != n {
			t.Errorf("bucket %q: got %d, want %d", b, got[b], n)
		}
	}
}

func TestFilterVulns(t *testing.T) {
	all := sampleVulns()

	if n := len(filterVulns(all, "", "", "")); n != 4 {
		t.Errorf("no filter: got %d, want 4", n)
	}
	if n := len(filterVulns(all, "high", "", "")); n != 2 {
		t.Errorf("bucket=high: got %d, want 2", n)
	}
	// Query matches canonical id (case-insensitive).
	if n := len(filterVulns(all, "", "", "cve-2026-2")); n != 1 {
		t.Errorf("q=cve-2026-2: got %d, want 1", n)
	}
	// Query matches an alias.
	if n := len(filterVulns(all, "", "", "ghsa-cccc")); n != 1 {
		t.Errorf("q=alias: got %d, want 1", n)
	}
	// Bucket + query combined.
	if n := len(filterVulns(all, "low", "", "cve-2026-1")); n != 0 {
		t.Errorf("bucket=low q=cve-2026-1: got %d, want 0", n)
	}
	// Project keeps every group touching that dir (CVE-1 + CVE-2 share /app/api).
	if n := len(filterVulns(all, "", "/app/api", "")); n != 2 {
		t.Errorf("project=/app/api: got %d, want 2", n)
	}
	// Project + bucket combined: only CVE-2 is high AND in /app/api.
	if n := len(filterVulns(all, "high", "/app/api", "")); n != 1 {
		t.Errorf("project=/app/api bucket=high: got %d, want 1", n)
	}
	// Unknown project matches nothing.
	if n := len(filterVulns(all, "", "/nope", "")); n != 0 {
		t.Errorf("project=/nope: got %d, want 0", n)
	}
}

func TestPaginate(t *testing.T) {
	all := sampleVulns()

	if got := paginate(all, 0, 0); len(got) != 4 {
		t.Errorf("limit=0 returns all: got %d, want 4", len(got))
	}
	if got := paginate(all, 0, 2); len(got) != 2 || got[0].CanonicalID != "CVE-2026-1" {
		t.Errorf("first page: got %v", got)
	}
	if got := paginate(all, 2, 2); len(got) != 2 || got[0].CanonicalID != "CVE-2026-3" {
		t.Errorf("second page: got %v", got)
	}
	if got := paginate(all, 10, 2); len(got) != 0 {
		t.Errorf("offset past end: got %d, want 0", len(got))
	}
}
