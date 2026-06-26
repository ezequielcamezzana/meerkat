package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/go-chi/chi/v5"
)

// handleEndpointReport serves a vulnerability report for one endpoint.
//
//	?kind=audit (default) → JSON dump for reading/sharing
//	?kind=fix             → Markdown prompt to feed an LLM/agent to remediate
func handleEndpointReport(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		tenantID := tenantIDFromCtx(r.Context())

		detail, err := database.GetEndpointDetail(r.Context(), id, tenantID, "exposure")
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if detail == nil {
			writeProblem(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}

		slug := reportSlug(detail.Hostname)
		switch r.URL.Query().Get("kind") {
		case "fix":
			// project ("" = all) scopes the prompt to a single project dir.
			project := r.URL.Query().Get("project")
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="meerkat-fix-`+slug+`.md"`)
			w.Write([]byte(buildFixReport(detail, project)))
		default:
			w.Header().Set("Content-Disposition", `attachment; filename="meerkat-audit-`+slug+`.json"`)
			writeJSON(w, http.StatusOK, buildAuditReport(detail))
		}
	}
}

func buildAuditReport(d *db.EndpointDetail) map[string]any {
	return map[string]any{
		"endpoint": map[string]any{
			"id":       d.ID,
			"hostname": d.Hostname,
			"os":       d.OS,
			"arch":     d.Arch,
			"tags":     d.Tags,
			"status":   d.Status,
		},
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"vuln_count":      d.VulnCount,
		"vulnerabilities": d.Vulnerabilities,
	}
}

// buildFixReport renders an LLM-ready remediation prompt, grouped by project
// directory (an agent fixes one project at a time). When project is non-empty,
// only that dir's section is emitted.
func buildFixReport(d *db.EndpointDetail, project string) string {
	type fixLine struct {
		name, version, fixed, cve, bucket string
		severity                          float64
	}
	byDir := map[string][]fixLine{}
	dirEcosystem := map[string]string{}

	for _, v := range d.Vulnerabilities {
		for _, p := range v.AffectedPackages {
			dirs := p.Dirs
			if len(dirs) == 0 {
				dirs = []string{"(unknown directory)"}
			}
			for _, dir := range dirs {
				if project != "" && dir != project {
					continue
				}
				byDir[dir] = append(byDir[dir], fixLine{
					name: p.Name, version: p.Version, fixed: p.FixedVersion,
					cve: v.CanonicalID, bucket: v.ExposureBucket, severity: v.SeverityScore,
				})
				if p.Ecosystem != "" {
					dirEcosystem[dir] = p.Ecosystem
				}
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Dependency vulnerability fixes — %s\n\n", d.Hostname)
	b.WriteString("You are fixing dependency vulnerabilities. For each project below, bump the\n")
	b.WriteString("listed packages to a safe version and update the lockfile. Change nothing\n")
	b.WriteString("else, and verify the project still builds.\n\n")

	dirs := make([]string, 0, len(byDir))
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	if len(dirs) == 0 {
		b.WriteString("No vulnerabilities found. Nothing to fix.\n")
		return b.String()
	}

	for _, dir := range dirs {
		if eco := dirEcosystem[dir]; eco != "" {
			fmt.Fprintf(&b, "## %s  (%s)\n", dir, eco)
		} else {
			fmt.Fprintf(&b, "## %s\n", dir)
		}
		for _, l := range byDir[dir] {
			target := "no fix available — mitigate or remove"
			if l.fixed != "" {
				target = ">= " + l.fixed
			}
			sev := ""
			if l.severity > 0 {
				sev = fmt.Sprintf(" · CVSS %.1f", l.severity)
			}
			fmt.Fprintf(&b, "- %s %s → %s  (%s · %s%s)\n", l.name, l.version, target, l.cve, l.bucket, sev)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// reportSlug makes a filename-safe slug from a hostname.
func reportSlug(host string) string {
	if host == "" {
		return "endpoint"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
