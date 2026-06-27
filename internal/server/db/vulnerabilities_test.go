package db

import (
	"context"
	"testing"
)

// seedTenantVulns builds a small fixture spanning two tenants so the tests can
// assert tenant isolation, search and sort. Layout:
//
//	tenant t1: CVE-A on e1+e2 (exposure 8.0/9.5), CVE-B on e1 (exposure 4.0)
//	tenant t2: CVE-C on e3
func seedTenantVulns(t *testing.T) *DB {
	t.Helper()
	ctx := context.Background()
	d, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed exec: %v", err)
		}
	}

	exec(`INSERT INTO tenants (id, name, created_at) VALUES ('t1','one','2026-01-01T00:00:00Z'), ('t2','two','2026-01-01T00:00:00Z')`)
	exec(`INSERT INTO endpoints (id, hostname, os, arch, user, first_seen, last_seen, tenant_id) VALUES
		('e1','h1','linux','amd64','u','2026-01-01T00:00:00Z','2026-06-15T00:00:00Z','t1'),
		('e2','h2','linux','amd64','u','2026-01-01T00:00:00Z','2026-06-15T00:00:00Z','t1'),
		('e3','h3','linux','amd64','u','2026-01-01T00:00:00Z','2026-06-15T00:00:00Z','t2')`)
	exec(`INSERT INTO vulnerabilities (id, canonical_id, aliases, summary, details, published_at, modified_at, source, raw, severity_score) VALUES
		('CVE-A','CVE-A','["GHSA-aaaa"]','sum A','det A','2026-05-01T00:00:00Z','2026-06-10T00:00:00Z','osv','{}',9.0),
		('CVE-B','CVE-B','["GHSA-bbbb"]','sum B','det B','2026-05-02T00:00:00Z','2026-06-12T00:00:00Z','osv','{}',5.0),
		('CVE-C','CVE-C','["GHSA-cccc"]','sum C','det C','2026-05-03T00:00:00Z','2026-06-11T00:00:00Z','osv','{}',7.0)`)
	exec(`INSERT INTO endpoint_vulnerabilities (endpoint_id, purl, vulnerability_id, package_name, package_version, package_ecosystem, exposure_score, discovered_at) VALUES
		('e1','pkg:a@1','CVE-A','a','1','npm',8.0,'2026-06-01T00:00:00Z'),
		('e2','pkg:a@1','CVE-A','a','1','npm',9.5,'2026-06-03T00:00:00Z'),
		('e1','pkg:b@1','CVE-B','b','1','npm',4.0,'2026-06-05T00:00:00Z'),
		('e3','pkg:c@1','CVE-C','c','1','npm',6.0,'2026-06-02T00:00:00Z')`)

	return d
}

func TestListTenantVulns_TenantIsolationAndSortDiscovered(t *testing.T) {
	d := seedTenantVulns(t)
	got, total, err := d.ListTenantVulns(context.Background(), "t1", VulnListQuery{Sort: "discovered"})
	if err != nil {
		t.Fatalf("ListTenantVulns: %v", err)
	}
	if total != 2 {
		t.Fatalf("total: got %d, want 2", total)
	}
	if len(got) != 2 {
		t.Fatalf("len: got %d, want 2", len(got))
	}
	// discovered DESC → CVE-B (2026-06-05) before CVE-A (MIN 2026-06-01).
	if got[0].CanonicalID != "CVE-B" || got[1].CanonicalID != "CVE-A" {
		t.Fatalf("order: got %s, %s", got[0].CanonicalID, got[1].CanonicalID)
	}
	// CVE-A aggregates across e1+e2.
	a := got[1]
	if a.AffectedCount != 2 {
		t.Errorf("CVE-A affected_count: got %d, want 2", a.AffectedCount)
	}
	if a.ExposureScore != 9.5 {
		t.Errorf("CVE-A exposure: got %v, want 9.5", a.ExposureScore)
	}
	if a.DiscoveredAt != "2026-06-01T00:00:00Z" {
		t.Errorf("CVE-A discovered: got %q", a.DiscoveredAt)
	}
	if a.ModifiedAt != "2026-06-10T00:00:00Z" {
		t.Errorf("CVE-A modified: got %q", a.ModifiedAt)
	}
	if a.ExposureBucket == "" {
		t.Errorf("CVE-A bucket should be derived")
	}
	if len(a.Aliases) != 1 || a.Aliases[0] != "GHSA-aaaa" {
		t.Errorf("CVE-A aliases: got %v", a.Aliases)
	}
}

func TestListTenantVulns_SortExposure(t *testing.T) {
	d := seedTenantVulns(t)
	got, _, err := d.ListTenantVulns(context.Background(), "t1", VulnListQuery{Sort: "exposure"})
	if err != nil {
		t.Fatalf("ListTenantVulns: %v", err)
	}
	// exposure DESC → CVE-A (9.5) before CVE-B (4.0).
	if got[0].CanonicalID != "CVE-A" || got[1].CanonicalID != "CVE-B" {
		t.Fatalf("order: got %s, %s", got[0].CanonicalID, got[1].CanonicalID)
	}
}

func TestListTenantVulns_Search(t *testing.T) {
	d := seedTenantVulns(t)

	// By alias.
	got, total, err := d.ListTenantVulns(context.Background(), "t1", VulnListQuery{Search: "GHSA-aaaa"})
	if err != nil {
		t.Fatalf("ListTenantVulns: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].CanonicalID != "CVE-A" {
		t.Fatalf("search alias: got %d rows total %d", len(got), total)
	}

	// By canonical id, case-insensitive.
	got, total, err = d.ListTenantVulns(context.Background(), "t1", VulnListQuery{Search: "cve-b"})
	if err != nil {
		t.Fatalf("ListTenantVulns: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].CanonicalID != "CVE-B" {
		t.Fatalf("search id: got %d rows total %d", len(got), total)
	}
}

func TestListTenantVulns_Pagination(t *testing.T) {
	d := seedTenantVulns(t)
	got, total, err := d.ListTenantVulns(context.Background(), "t1", VulnListQuery{Sort: "discovered", Limit: 1, Offset: 0})
	if err != nil {
		t.Fatalf("ListTenantVulns: %v", err)
	}
	// total counts all matching groups, ignoring limit.
	if total != 2 {
		t.Fatalf("total: got %d, want 2", total)
	}
	if len(got) != 1 || got[0].CanonicalID != "CVE-B" {
		t.Fatalf("page 1: got %d rows, first %v", len(got), got)
	}
}

func TestGetTenantVulnDetail_Found(t *testing.T) {
	d := seedTenantVulns(t)
	got, err := d.GetTenantVulnDetail(context.Background(), "t1", "CVE-A")
	if err != nil {
		t.Fatalf("GetTenantVulnDetail: %v", err)
	}
	if got == nil {
		t.Fatal("expected detail, got nil")
	}
	if got.Summary != "sum A" || got.Details != "det A" {
		t.Errorf("advisory: summary %q details %q", got.Summary, got.Details)
	}
	if got.ModifiedAt != "2026-06-10T00:00:00Z" {
		t.Errorf("modified: got %q", got.ModifiedAt)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "GHSA-aaaa" {
		t.Errorf("aliases: got %v", got.Aliases)
	}
	// CVE-A is on e1 (8.0) and e2 (9.5), ordered by exposure DESC.
	if len(got.AffectedEndpoints) != 2 {
		t.Fatalf("affected: got %d, want 2", len(got.AffectedEndpoints))
	}
	if got.AffectedEndpoints[0].EndpointID != "e2" {
		t.Errorf("first affected: got %s, want e2", got.AffectedEndpoints[0].EndpointID)
	}
	if got.AffectedEndpoints[0].Hostname != "h2" || got.AffectedEndpoints[0].ExposureScore != 9.5 {
		t.Errorf("e2 fields: %+v", got.AffectedEndpoints[0])
	}
	if len(got.AffectedEndpoints[0].Packages) != 1 ||
		got.AffectedEndpoints[0].Packages[0].PackageName != "a" ||
		got.AffectedEndpoints[0].Packages[0].PackageVersion != "1" {
		t.Errorf("e2 package: %+v", got.AffectedEndpoints[0])
	}
}

func TestGetTenantVulnDetail_TenantIsolation(t *testing.T) {
	d := seedTenantVulns(t)
	// CVE-C only exists on tenant t2.
	got, err := d.GetTenantVulnDetail(context.Background(), "t1", "CVE-C")
	if err != nil {
		t.Fatalf("GetTenantVulnDetail: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for cross-tenant vuln, got %+v", got)
	}
}

func TestGetTenantVulnDetail_NotFound(t *testing.T) {
	d := seedTenantVulns(t)
	got, err := d.GetTenantVulnDetail(context.Background(), "t1", "CVE-NOPE")
	if err != nil {
		t.Fatalf("GetTenantVulnDetail: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}
