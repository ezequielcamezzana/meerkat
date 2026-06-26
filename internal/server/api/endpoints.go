package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/go-chi/chi/v5"
)

func formatTimeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func handleListEndpoints(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := tenantIDFromCtx(r.Context())
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))

		filter := db.EndpointFilter{
			TenantID: tenantID,
			Tag:      q.Get("tag"),
			Status:   q.Get("status"),
			Q:        q.Get("q"),
			Limit:    limit,
			Offset:   offset,
		}

		endpoints, total, err := database.ListEndpoints(r.Context(), filter)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if endpoints == nil {
			endpoints = []db.EndpointWithStatus{}
		}

		type row struct {
			ID          string   `json:"id"`
			Hostname    string   `json:"hostname"`
			OS          string   `json:"os"`
			Arch        string   `json:"arch"`
			Tags        []string `json:"tags"`
			LastSeen    string   `json:"last_seen"`
			LastMatched string   `json:"last_matched_at,omitempty"`
			Status      string   `json:"status"`
			VulnCount   int      `json:"vuln_count"`
		}
		rows := make([]row, len(endpoints))
		for i, e := range endpoints {
			rows[i] = row{
				ID:          e.ID,
				Hostname:    e.Hostname,
				OS:          e.OS,
				Arch:        e.Arch,
				Tags:        e.Tags,
				LastSeen:    e.LastSeen.UTC().Format("2006-01-02T15:04:05Z"),
				LastMatched: formatTimeOrEmpty(e.LastMatched),
				Status:      e.Status,
				VulnCount:   e.VulnCount,
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": rows, "total": total})
	}
}

func handleGetEndpoint(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		tenantID := tenantIDFromCtx(r.Context())
		q := r.URL.Query()

		limit := 20
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
			limit = l
		}
		offset, _ := strconv.Atoi(q.Get("offset"))

		detail, err := database.GetEndpointDetailPage(r.Context(), id, tenantID, db.VulnQuery{
			Sort:    q.Get("sort"),
			Bucket:  q.Get("bucket"),
			Project: q.Get("project"),
			Q:       q.Get("q"),
			Limit:   limit,
			Offset:  offset,
		})
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if detail == nil {
			writeProblem(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}

		vulns := detail.Vulnerabilities
		if vulns == nil {
			vulns = []db.VulnGrouped{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":                         detail.ID,
			"hostname":                   detail.Hostname,
			"os":                         detail.OS,
			"arch":                       detail.Arch,
			"user":                       detail.User,
			"tags":                       detail.Tags,
			"first_seen":                 detail.FirstSeen.UTC().Format("2006-01-02T15:04:05Z"),
			"last_seen":                  detail.LastSeen.UTC().Format("2006-01-02T15:04:05Z"),
			"last_matched_at":            formatTimeOrEmpty(detail.LastMatched),
			"last_scan_id":               detail.LastScanID,
			"status":                     detail.Status,
			"vuln_count":                 detail.VulnCount,
			"scan_root":                  detail.ScanRoot,
			"projects_scanned":           detail.ScanProjectsScanned,
			"scan_projects_by_ecosystem": detail.ScanProjectsByEcosystem,
			"scan_walk_millis":           detail.ScanWalkMillis,
			"scan_catalog_millis":        detail.ScanCatalogMillis,
			"scan_millis":                detail.ScanMillis,
			"scan_started_at":            detail.ScanStartedAt,
			"change_last_day":            detail.ChangeLastDay,
			"change_last_week":           detail.ChangeLastWeek,
			"change_last_month":          detail.ChangeLastMonth,
			"vulnerabilities":            vulns,
			"vuln_total":                 detail.VulnTotal,
			"fixable_total":              detail.FixableTotal,
			"filtered_total":             detail.FilteredTotal,
			"bucket_counts":              detail.BucketCounts,
			"project_stats":              detail.ProjectStats,
		})
	}
}

func handleGetEndpointHistory(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		tenantID := tenantIDFromCtx(r.Context())
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))

		// Verify the endpoint belongs to this tenant before returning history.
		ep, err := database.GetEndpointRow(r.Context(), id, tenantID)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if ep == nil {
			writeProblem(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}

		entries, err := database.GetHistory(r.Context(), id, days)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if entries == nil {
			entries = []db.HistoryEntry{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoint_id": id, "days": entries})
	}
}
