package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/scoring"
)

type VulnGrouped struct {
	CanonicalID      string        `json:"canonical_id"`
	Aliases          []string      `json:"aliases,omitempty"`
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
	PublishedAt      string        `json:"published_at,omitempty"`
	ModifiedAt       string        `json:"modified_at,omitempty"`
	DiscoveredAt     string        `json:"discovered_at,omitempty"`
	ExposureScore    float64       `json:"exposure_score"`
	ExposureBucket   string        `json:"exposure_bucket"`
	SeverityScore    float64       `json:"severity_score"`
	CvssBucket       string        `json:"cvss_bucket"`
	Source           string        `json:"source"`
	Scope            string        `json:"scope"`
	Kind             string        `json:"kind"`
	IsNew            bool          `json:"is_new"`
	AffectedPackages []AffectedPkg `json:"affected_packages"`
	Vulns            []VulnRef     `json:"vulns"`
}

type AffectedPkg struct {
	Purl         string   `json:"purl"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Ecosystem    string   `json:"ecosystem"`
	Dirs         []string `json:"dirs"`
	Scope        string   `json:"scope"`
	Kind         string   `json:"kind"`
	DiscoveredAt string   `json:"discovered_at,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
}

type VulnRef struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	URL    string `json:"url,omitempty"`
}

func vulnURL(source, id string) string {
	switch source {
	case "osv":
		return "https://osv.dev/vulnerability/" + id
	}
	return ""
}

type EndpointDetail struct {
	EndpointWithStatus
	User                    string         `json:"user"`
	LastScanID              string         `json:"last_scan_id"`
	ScanRoot                string         `json:"scan_root,omitempty"`
	ScanProjectsScanned     int            `json:"scan_projects_scanned,omitempty"`
	ScanProjectsByEcosystem map[string]int `json:"scan_projects_by_ecosystem,omitempty"`
	ScanWalkMillis          int64          `json:"scan_walk_millis,omitempty"`
	ScanCatalogMillis       int64          `json:"scan_catalog_millis,omitempty"`
	ScanMillis              int64          `json:"scan_millis,omitempty"`
	ScanStartedAt           string         `json:"scan_started_at,omitempty"`
	ChangeLastDay           int            `json:"change_last_day"`
	ChangeLastWeek          int            `json:"change_last_week"`
	ChangeLastMonth         int            `json:"change_last_month"`
	Vulnerabilities         []VulnGrouped  `json:"vulnerabilities"`
}

// GetEndpointDetail returns one endpoint's full detail. sort orders the grouped
// vulnerabilities: "discovered" (newest first) or "exposure" (default).
func (s *DB) GetEndpointDetail(ctx context.Context, id, tenantID, sort string) (*EndpointDetail, error) {
	ep, err := s.GetEndpointRow(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	if ep == nil {
		return nil, nil
	}

	var user string
	s.conn.QueryRowContext(ctx, `SELECT user FROM endpoints WHERE id = ?`, id).Scan(&user)

	var lastScanID, scanRoot, scanStartedAt, ecosystemsJSON string
	var scanProjectsScanned int
	var walkMillis, catalogMillis, scanMillis int64
	s.conn.QueryRowContext(ctx, `
		SELECT scan_id,
		       COALESCE(json_extract(raw, '$.scan.root'), ''),
		       COALESCE(CAST(json_extract(raw, '$.scan.projects_scanned') AS INTEGER), 0),
		       COALESCE(CAST(json_extract(raw, '$.scan.walk_millis') AS INTEGER), 0),
		       COALESCE(CAST(json_extract(raw, '$.scan.catalog_millis') AS INTEGER), 0),
		       COALESCE(CAST(json_extract(raw, '$.scan.scan_millis') AS INTEGER), 0),
		       COALESCE(json_extract(raw, '$.scan.projects_by_ecosystem'), '{}'),
		       COALESCE(json_extract(raw, '$.scan.started_at'), '')
		FROM inventories WHERE endpoint_id = ?`, id).
		Scan(&lastScanID, &scanRoot, &scanProjectsScanned, &walkMillis, &catalogMillis, &scanMillis, &ecosystemsJSON, &scanStartedAt)

	var projectsByEcosystem map[string]int
	json.Unmarshal([]byte(ecosystemsJSON), &projectsByEcosystem)

	hist, err := s.GetHistory(ctx, id, 30)
	if err != nil {
		return nil, fmt.Errorf("getting history: %w", err)
	}

	vulns, err := s.getEndpointVulns(ctx, id, sort)
	if err != nil {
		return nil, fmt.Errorf("getting vulns: %w", err)
	}

	return &EndpointDetail{
		EndpointWithStatus:      *ep,
		User:                    user,
		LastScanID:              lastScanID,
		ScanRoot:                scanRoot,
		ScanProjectsScanned:     scanProjectsScanned,
		ScanProjectsByEcosystem: projectsByEcosystem,
		ScanWalkMillis:          walkMillis,
		ScanCatalogMillis:       catalogMillis,
		ScanMillis:              scanMillis,
		ScanStartedAt:           scanStartedAt,
		ChangeLastDay:           deltaFromHistory(hist, 1),
		ChangeLastWeek:          deltaFromHistory(hist, 7),
		ChangeLastMonth:         deltaFromHistory(hist, 30),
		Vulnerabilities:         vulns,
	}, nil
}

// deltaFromHistory returns the net change in vuln count between the latest
// snapshot and the one from `days` ago. entries must be sorted by date ASC.
// WHY: a missing snapshot means the endpoint had no recorded vulns then, so the
// baseline is 0 — not the earliest available record. A cold-start endpoint with
// only today's 38 vulns is therefore "+38 last month", "0 last day".
func deltaFromHistory(entries []HistoryEntry, days int) int {
	if len(entries) == 0 {
		return 0
	}
	latest := entries[len(entries)-1].VulnCount
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	base := 0
	for _, e := range entries {
		if e.Date <= cutoff {
			base = e.VulnCount
		} else {
			break
		}
	}
	return latest - base
}

func (s *DB) getEndpointVulns(ctx context.Context, endpointID, sort string) ([]VulnGrouped, error) {
	orderBy := "MAX(ev.exposure_score) DESC"
	if sort == "discovered" {
		orderBy = "MAX(ev.discovered_at) DESC, MAX(ev.exposure_score) DESC"
	}
	rows, err := s.conn.QueryContext(ctx, `
		SELECT
			v.canonical_id,
			MIN(v.aliases)      AS aliases,
			MIN(v.summary)      AS summary,
			MIN(v.details)      AS details,
			MIN(v.published_at) AS published_at,
			MAX(v.modified_at)  AS modified_at,
			json_group_array(json_object(
				'id',       v.id,
				'source',   v.source,
				'severity', v.severity_score
			)) AS vuln_refs,
			json_group_array(json_object(
				'purl',          ev.purl,
				'name',          ev.package_name,
				'version',       ev.package_version,
				'ecosystem',     ev.package_ecosystem,
				'dirs',          json(ev.dirs),
				'scope',         ev.package_scope,
				'kind',          ev.package_kind,
				'discovered_at', ev.discovered_at,
				'fixed_version', ev.fixed_version
			)) AS packages,
			MAX(ev.exposure_score) AS exposure_score,
			MAX(ev.discovered_at)  AS discovered_at
		FROM endpoint_vulnerabilities ev
		JOIN vulnerabilities v ON v.id = ev.vulnerability_id
		WHERE ev.endpoint_id = ?
		GROUP BY v.canonical_id
		ORDER BY `+orderBy, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	var result []VulnGrouped
	for rows.Next() {
		var vg VulnGrouped
		var aliasesJSON, vulnIDsJSON, packagesJSON string
		if err := rows.Scan(
			&vg.CanonicalID, &aliasesJSON, &vg.Summary, &vg.Details,
			&vg.PublishedAt, &vg.ModifiedAt,
			&vulnIDsJSON, &packagesJSON,
			&vg.ExposureScore, &vg.DiscoveredAt,
		); err != nil {
			return nil, err
		}
		vg.ExposureBucket = scoring.Bucket(vg.ExposureScore)
		// NEW: published, modified, or discovered within the last 24h.
		vg.IsNew = within24h(vg.PublishedAt, now) ||
			within24h(vg.ModifiedAt, now) ||
			within24h(vg.DiscoveredAt, now)
		json.Unmarshal([]byte(aliasesJSON), &vg.Aliases)

		var rawRefs []struct {
			ID       string  `json:"id"`
			Source   string  `json:"source"`
			Severity float64 `json:"severity"`
		}
		json.Unmarshal([]byte(vulnIDsJSON), &rawRefs)
		seen := make(map[string]struct{})
		for _, r := range rawRefs {
			if _, dup := seen[r.ID]; dup {
				continue
			}
			seen[r.ID] = struct{}{}
			// Canonical severity + source come from the strongest grouped vuln.
			if r.Severity > vg.SeverityScore {
				vg.SeverityScore = r.Severity
				vg.Source = r.Source
			}
			vg.Vulns = append(vg.Vulns, VulnRef{
				ID:     r.ID,
				Source: r.Source,
				URL:    vulnURL(r.Source, r.ID),
			})
		}

		var rawPkgs []AffectedPkg
		json.Unmarshal([]byte(packagesJSON), &rawPkgs)
		pkgSeen := make(map[string]struct{})
		for _, p := range rawPkgs {
			if _, dup := pkgSeen[p.Purl]; dup {
				continue
			}
			pkgSeen[p.Purl] = struct{}{}
			vg.AffectedPackages = append(vg.AffectedPackages, p)
			// Canonical scope/kind = the most powerful among its children.
			// WHY: the empty string weighs 1.0 (default), so seed from the first
			// child before comparing or it would never be overtaken.
			if vg.Scope == "" || scoring.ScopeWeight(p.Scope) > scoring.ScopeWeight(vg.Scope) {
				vg.Scope = p.Scope
			}
			if vg.Kind == "" || scoring.KindWeight(p.Kind) > scoring.KindWeight(vg.Kind) {
				vg.Kind = p.Kind
			}
		}

		vg.CvssBucket = scoring.CVSSBucket(vg.SeverityScore)
		result = append(result, vg)
	}
	return result, rows.Err()
}

// within24h reports whether an ISO-8601 timestamp falls within the last 24h.
func within24h(ts string, now time.Time) bool {
	if ts == "" {
		return false
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", ts)
	if err != nil {
		return false
	}
	d := now.Sub(t)
	return d >= 0 && d < 24*time.Hour
}
