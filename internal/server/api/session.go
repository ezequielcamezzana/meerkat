package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
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

		token, err := auth.Sign(apiKey.TenantID, secret, sessionTTL)
		if err != nil {
			slog.Error("signing session token", "err", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     auth.CookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   int(sessionTTL.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
