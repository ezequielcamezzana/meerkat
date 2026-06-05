package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
)

type contextKey string

const (
	tenantIDKey contextKey = "tenantID"
	roleKey     contextKey = "role"
)

func tenantIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(tenantIDKey).(string)
	return v
}

func roleFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(roleKey).(string)
	return v
}

// requireComplete rejects read-only (guest) keys. Guards every write endpoint,
// regardless of whether auth came from an api key (ingest) or a session cookie.
func requireComplete(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if roleFromCtx(r.Context()) != db.RoleComplete {
			writeProblem(w, http.StatusForbidden, "forbidden", "read-only key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// apiKeyMiddleware authenticates scanner requests via Bearer token,
// looks up the key in api_keys, and injects tenantID into the context.
func apiKeyMiddleware(database *db.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || !strings.HasPrefix(token, auth.Prefix) {
				writeProblem(w, http.StatusUnauthorized, "unauthorized", "missing or invalid token")
				return
			}

			hash := auth.Hash(token)
			key, err := database.GetAPIKeyByHash(r.Context(), hash)
			if err != nil {
				// WARNING: constant-time compare not needed here since GetAPIKeyByHash
				// already does a DB lookup, but we still avoid leaking via timing on
				// the legacy single-token path below.
				legacyOK, legacyErr := checkLegacyToken(r.Context(), database, token)
				if legacyErr != nil {
					slog.Error("checking legacy token", "err", legacyErr)
					writeProblem(w, http.StatusInternalServerError, "internal_error", "internal error")
					return
				}
				if !legacyOK {
					writeProblem(w, http.StatusUnauthorized, "unauthorized", "invalid token")
					return
				}
				// Legacy token has no tenant — inject empty string so ingest skips
				// tenant association. It's the admin bootstrap token → complete.
				ctx := context.WithValue(r.Context(), tenantIDKey, "")
				ctx = context.WithValue(ctx, roleKey, db.RoleComplete)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			ctx := context.WithValue(r.Context(), tenantIDKey, key.TenantID)
			ctx = context.WithValue(ctx, roleKey, key.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sessionMiddleware validates the mk_session cookie and injects tenantID into the context.
// For browser requests without a valid cookie it redirects to /app/login.
// For API requests it returns 401.
func sessionMiddleware(database *db.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secret, err := database.GetOrCreateSessionSecret(r.Context())
			if err != nil {
				slog.Error("getting session secret", "err", err)
				writeProblem(w, http.StatusInternalServerError, "internal_error", "internal error")
				return
			}

			cookie, err := r.Cookie(auth.CookieName)
			if err != nil {
				redirectOrUnauthorized(w, r)
				return
			}

			tenantID, role, err := auth.Verify(cookie.Value, secret)
			if err != nil {
				redirectOrUnauthorized(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), tenantIDKey, tenantID)
			ctx = context.WithValue(ctx, roleKey, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func redirectOrUnauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "valid session required")
		return
	}
	http.Redirect(w, r, "/app/login", http.StatusSeeOther)
}

func checkLegacyToken(ctx context.Context, database *db.DB, token string) (bool, error) {
	stored, err := database.GetTokenHash(ctx)
	if err != nil {
		return false, err
	}
	if stored == "" {
		return false, nil
	}
	incoming := auth.Hash(token)
	return subtle.ConstantTimeCompare([]byte(incoming), []byte(stored)) == 1, nil
}
