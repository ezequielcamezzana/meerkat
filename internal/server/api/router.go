package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/config"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	"github.com/ezequielcamezzana/meerkat/internal/server/ui"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(database *db.DB, ing *ingest.Ingest, cfg *config.Config) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(slogMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware(cfg.CORSAllowedOrigins))

	indexHTML, _ := ui.FS.ReadFile("index.html")
	assetServer := http.StripPrefix("/app", http.FileServer(http.FS(ui.FS)))
	serveApp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	// Public routes — no auth.
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app", http.StatusMovedPermanently)
	})
	r.Handle("/app/assets/*", assetServer)
	r.Get("/app/login", serveApp)
	r.Get("/v1/healthz", handleHealthz(database))
	r.Post("/app/login", handleLogin(database))
	r.Post("/app/logout", handleLogout())

	// Scanner ingestion — authenticated by API key.
	r.With(apiKeyMiddleware(database)).Post("/v1/inventories", handlePostInventory(ing))

	// App UI — authenticated by session cookie.
	r.Group(func(r chi.Router) {
		r.Use(sessionMiddleware(database))
		r.Get("/app", serveApp)
		r.Get("/app/*", serveApp)
	})

	// API reads — authenticated by session cookie.
	r.Group(func(r chi.Router) {
		r.Use(sessionMiddleware(database))
		r.Get("/v1/endpoints", handleListEndpoints(database))
		r.Get("/v1/endpoints/{id}", handleGetEndpoint(database))
		r.Get("/v1/endpoints/{id}/history", handleGetEndpointHistory(database))
		r.Get("/v1/endpoints/{id}/report", handleEndpointReport(database))
		r.Get("/v1/settings", handleGetSettings(database))
		r.Put("/v1/settings", handlePutSettings(database))
	})

	return r
}

func handleHealthz(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := database.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func slogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	allowAll := len(origins) == 1 && origins[0] == "*"
	allowed := strings.Join(origins, ", ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" {
				for _, o := range origins {
					if o == origin {
						w.Header().Set("Access-Control-Allow-Origin", allowed)
						break
					}
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, typ, detail string) {
	writeJSON(w, status, map[string]any{
		"type":   typ,
		"detail": detail,
		"status": status,
	})
}
