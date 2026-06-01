package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	serverapi "github.com/ezequielcamezzana/meerkat/internal/server/api"
	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/ezequielcamezzana/meerkat/internal/server/config"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/notifier"
	meerkatapi "github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRouter creates a test router with a tenant, an API key, and a valid session cookie.
// Returns (router, db, apiToken, sessionCookie).
func setupRouter(t *testing.T) (http.Handler, *db.DB, string) {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, database.Migrate(context.Background()))
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()

	// Legacy token still works for scanner auth in tests.
	token, hash, err := auth.Generate()
	require.NoError(t, err)
	require.NoError(t, database.ReplaceTokenHash(ctx, hash))

	ing := ingest.New(database, &matcher.NoopMatcher{}, &notifier.NoopNotifier{}, "")
	cfg := &config.Config{CORSAllowedOrigins: []string{"*"}}
	router := serverapi.NewRouter(database, ing, cfg)
	return router, database, token
}

// sessionCookie creates a valid session cookie for the given tenantID using the DB secret.
func sessionCookie(t *testing.T, database *db.DB, tenantID string) *http.Cookie {
	t.Helper()
	secret, err := database.GetOrCreateSessionSecret(context.Background())
	require.NoError(t, err)
	tok, err := auth.Sign(tenantID, secret, 24*time.Hour)
	require.NoError(t, err)
	return &http.Cookie{Name: auth.CookieName, Value: tok}
}

func validInventory() meerkatapi.Inventory {
	return meerkatapi.Inventory{
		SchemaVersion: "0.1.0",
		Endpoint:      meerkatapi.Endpoint{ID: "ep-test", Hostname: "host", OS: "linux", Arch: "amd64"},
		Scan:          meerkatapi.Scan{ID: "scan-test"},
	}
}

func TestPostInventory_Success(t *testing.T) {
	router, _, token := setupRouter(t)

	body, _ := json.Marshal(validInventory())
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "scan-test", resp["scan_id"])
	assert.Equal(t, "ep-test", resp["endpoint_id"])
}

func TestPostInventory_NoToken(t *testing.T) {
	router, _, _ := setupRouter(t)

	body, _ := json.Marshal(validInventory())
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPostInventory_WrongToken(t *testing.T) {
	router, _, _ := setupRouter(t)

	body, _ := json.Marshal(validInventory())
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer mk_wrongtoken00000000000000000000")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPostInventory_NoTokenConfigured(t *testing.T) {
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, database.Migrate(context.Background()))
	defer database.Close()

	ing := ingest.New(database, &matcher.NoopMatcher{}, &notifier.NoopNotifier{}, "")
	cfg := &config.Config{CORSAllowedOrigins: []string{"*"}}
	router := serverapi.NewRouter(database, ing, cfg)

	body, _ := json.Marshal(validInventory())
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer mk_sometoken000000000000000000000")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// No legacy token stored and no api_keys row → 401.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPostInventory_BadJSON(t *testing.T) {
	router, _, token := setupRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
