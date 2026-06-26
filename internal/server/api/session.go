package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/ezequielcamezzana/meerkat/internal/server/config"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/google/uuid"
)

const sessionTTL = 24 * time.Hour

func handleLogin(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_json", "invalid request body")
			return
		}

		if req.Key == "" {
			writeProblem(w, http.StatusBadRequest, "missing_key", "key is required")
			return
		}

		hash := auth.Hash(req.Key)
		apiKey, err := database.GetAPIKeyByHash(r.Context(), hash)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", "invalid key")
			return
		}

		secret, err := database.GetOrCreateSessionSecret(r.Context())
		if err != nil {
			slog.Error("getting session secret", "err", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}

		token, err := auth.Sign(apiKey.TenantID, apiKey.Role, secret, sessionTTL)
		if err != nil {
			slog.Error("signing session token", "err", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}

		setSessionCookie(w, token)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// setSessionCookie writes the signed session cookie with the standard attributes.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// handleSession returns the current session's tenant and role. The FE uses the
// role to show a "guest" badge and hide write actions, and magpie_url to link
// PURLs to Magpie when configured.
func handleSession(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"tenant_id":  tenantIDFromCtx(r.Context()),
			"role":       roleFromCtx(r.Context()),
			"magpie_url": cfg.MagpieURL,
		})
	}
}

// handleCreateGuestKey mints a read-only key for the caller's own tenant. It sits
// behind requireComplete, so a guest can't mint another guest, and the tenant is
// taken from the authenticated context — you can only provision for your tenant.
func handleCreateGuestKey(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&req) // body is optional
		if req.Name == "" {
			req.Name = "guest-key"
		}

		token, hash, err := auth.Generate()
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		key, err := database.CreateAPIKey(r.Context(), uuid.NewString(), tenantIDFromCtx(r.Context()), req.Name, db.RoleGuest, hash, now)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"token": token,
			"id":    key.ID,
			"name":  key.Name,
			"role":  key.Role,
		})
	}
}

func handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     auth.CookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
