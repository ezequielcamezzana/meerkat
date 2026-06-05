package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/stretchr/testify/require"
)

func setupSettingsTest(t *testing.T) (http.Handler, *http.Cookie) {
	t.Helper()
	database, err := openTestDB2(t)
	require.NoError(t, err)
	router := setupRouterDefault(t, database)

	ctx := context.Background()
	tenant, err := database.CreateTenant(ctx, "settings-tenant", "settings-test", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	secret, err := database.GetOrCreateSessionSecret(ctx)
	require.NoError(t, err)
	tok, err := auth.Sign(tenant.ID, db.RoleComplete, secret, time.Hour)
	require.NoError(t, err)

	return router, &http.Cookie{Name: auth.CookieName, Value: tok}
}

func TestGetSettings_defaults(t *testing.T) {
	router, cookie := setupSettingsTest(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	notifications, ok := resp["notifications"].(map[string]any)
	require.True(t, ok)
	email, ok := notifications["email"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, email["enabled"])
	require.Empty(t, email["recipients"])
}

func TestPutSettings_valid(t *testing.T) {
	router, cookie := setupSettingsTest(t)

	body := []byte(`{"notifications":{"email":{"enabled":false,"recipients":["a@b.com"]}}}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
	req2.AddCookie(cookie)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusOK, w2.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))

	email := resp["notifications"].(map[string]any)["email"].(map[string]any)
	require.Equal(t, false, email["enabled"])
	recipients := email["recipients"].([]any)
	require.Len(t, recipients, 1)
	require.Equal(t, "a@b.com", recipients[0])
}

func TestPutSettings_invalidJSON(t *testing.T) {
	router, cookie := setupSettingsTest(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/settings", bytes.NewReader([]byte(`{bad json`)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutSettings_invalidRecipient(t *testing.T) {
	router, cookie := setupSettingsTest(t)

	body := []byte(`{"notifications":{"email":{"enabled":true,"recipients":["notanemail"]}}}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}
