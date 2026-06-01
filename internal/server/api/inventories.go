package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	meerkatapi "github.com/ezequielcamezzana/meerkat/pkg/api"
)

func handlePostInventory(ing *ingest.Ingest) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var inv meerkatapi.Inventory
		if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
			writeProblem(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
			return
		}

		tenantID := tenantIDFromCtx(r.Context())
		result, err := ing.Process(r.Context(), inv, tenantID)
		if err != nil {
			slog.Error("ingest failed", "err", err)
			writeProblem(w, http.StatusInternalServerError, "ingest_error", err.Error())
			return
		}

		newVulns := result.NewVulnerabilities
		if newVulns == nil {
			newVulns = []meerkatapi.NewVulnRef{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"scan_id":              result.ScanID,
			"endpoint_id":          result.EndpointID,
			"vuln_count":           result.VulnCount,
			"new_vulnerabilities":  newVulns,
			"endpoint_url":         result.EndpointURL,
		})
	}
}
