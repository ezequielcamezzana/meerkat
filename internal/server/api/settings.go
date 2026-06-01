package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
)

type settingsRequest struct {
	Notifications struct {
		Email struct {
			Enabled    bool     `json:"enabled"`
			Recipients []string `json:"recipients"`
		} `json:"email"`
	} `json:"notifications"`
}

func handleGetSettings(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := tenantIDFromCtx(r.Context())
		tenant, err := database.GetTenantByID(r.Context(), tenantID)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, buildSettingsResponse(tenant.NotifyEnabled, tenant.Recipients))
	}
}

func handlePutSettings(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req settingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}

		for _, recipient := range req.Notifications.Email.Recipients {
			if !strings.Contains(recipient, "@") {
				writeProblem(w, http.StatusBadRequest, "invalid_recipient", "recipient must contain @: "+recipient)
				return
			}
		}

		recipients := req.Notifications.Email.Recipients
		if recipients == nil {
			recipients = []string{}
		}

		tenantID := tenantIDFromCtx(r.Context())
		if err := database.UpdateTenantNotifications(r.Context(), tenantID, req.Notifications.Email.Enabled, recipients); err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		writeJSON(w, http.StatusOK, buildSettingsResponse(req.Notifications.Email.Enabled, recipients))
	}
}

func buildSettingsResponse(enabled bool, recipients []string) map[string]any {
	if recipients == nil {
		recipients = []string{}
	}
	return map[string]any{
		"notifications": map[string]any{
			"email": map[string]any{
				"enabled":    enabled,
				"recipients": recipients,
			},
		},
	}
}
