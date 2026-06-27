package api

import (
	"net/http"
	"strconv"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/go-chi/chi/v5"
)

func handleListVulns(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := tenantIDFromCtx(r.Context())
		q := r.URL.Query()

		sort := q.Get("sort")
		if sort != "exposure" {
			sort = "discovered"
		}
		limit := 20
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
			limit = l
		}
		offset, _ := strconv.Atoi(q.Get("offset"))

		vulns, total, err := database.ListTenantVulns(r.Context(), tenantID, db.VulnListQuery{
			Search: q.Get("search"),
			Sort:   sort,
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if vulns == nil {
			vulns = []db.VulnSummary{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns, "total": total})
	}
}

func handleGetVuln(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := tenantIDFromCtx(r.Context())
		canonicalID := chi.URLParam(r, "id")

		detail, err := database.GetTenantVulnDetail(r.Context(), tenantID, canonicalID)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if detail == nil {
			writeProblem(w, http.StatusNotFound, "not_found", "vulnerability not found")
			return
		}
		if detail.AffectedEndpoints == nil {
			detail.AffectedEndpoints = []*db.AffectedEndpoint{}
		}
		writeJSON(w, http.StatusOK, detail)
	}
}
