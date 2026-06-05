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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeKey creates an api key with the given role and returns its plaintext token.
func makeKey(t *testing.T, database *db.DB, tenantID, role string) string {
	t.Helper()
	token, hash, err := auth.Generate()
	require.NoError(t, err)
	_, err = database.CreateAPIKey(context.Background(), "key-"+role+"-"+tenantID, tenantID, role, role, hash, time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	return token
}

func bearerPost(t *testing.T, router http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestGuestKey_BlockedFromIngest(t *testing.T) {
	router, database, _ := setupRouter(t)
	tenant, err := database.CreateTenant(context.Background(), "t-guest", "t-guest", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	guest := makeKey(t, database, tenant.ID, db.RoleGuest)

	body, _ := json.Marshal(validInventory())
	w := bearerPost(t, router, "/v1/inventories", guest, string(body))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGuestKey_BlockedFromMintingGuest(t *testing.T) {
	router, database, _ := setupRouter(t)
	tenant, err := database.CreateTenant(context.Background(), "t-guest2", "t-guest2", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	guest := makeKey(t, database, tenant.ID, db.RoleGuest)

	w := bearerPost(t, router, "/v1/keys/guest", guest, `{}`)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCompleteKey_MintsGuest_ScopedToTenant(t *testing.T) {
	router, database, _ := setupRouter(t)
	tenant, err := database.CreateTenant(context.Background(), "t-complete", "t-complete", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	complete := makeKey(t, database, tenant.ID, db.RoleComplete)

	w := bearerPost(t, router, "/v1/keys/guest", complete, `{"name":"demo"}`)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp["token"])
	assert.Equal(t, db.RoleGuest, resp["role"])

	// The minted key resolves to the same tenant, as a guest.
	key, err := database.GetAPIKeyByHash(context.Background(), auth.Hash(resp["token"]))
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, key.TenantID)
	assert.Equal(t, db.RoleGuest, key.Role)
}

func TestGuestSession_BlockedFromSettingsPut(t *testing.T) {
	router, database, _ := setupRouter(t)
	tenant, err := database.CreateTenant(context.Background(), "t-sess", "t-sess", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	cookie := sessionCookieRole(t, database, tenant.ID, db.RoleGuest)

	req := httptest.NewRequest(http.MethodPut, "/v1/settings", bytes.NewReader([]byte(`{"notifications":{"email":{"enabled":true,"recipients":[]}}}`)))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGuestSession_CanReadEndpointsAndSession(t *testing.T) {
	router, database, _ := setupRouter(t)
	tenant, err := database.CreateTenant(context.Background(), "t-read", "t-read", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	cookie := sessionCookieRole(t, database, tenant.ID, db.RoleGuest)

	w := getWithSession(t, router, "/v1/endpoints", cookie)
	assert.Equal(t, http.StatusOK, w.Code)

	w = getWithSession(t, router, "/v1/session", cookie)
	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, db.RoleGuest, resp["role"])
	assert.Equal(t, tenant.ID, resp["tenant_id"])
}
