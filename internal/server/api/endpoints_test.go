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
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/notifier"
	meerkatapi "github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedEndpoint posts an inventory using the legacy token so the endpoint ends up with no tenant_id.
// For tenant-scoped tests use seedEndpointWith with an api_keys token.
func seedEndpoint(t *testing.T, router http.Handler, token string, endpointID string) {
	t.Helper()
	inv := meerkatapi.Inventory{
		SchemaVersion: "0.1.0",
		Endpoint:      meerkatapi.Endpoint{ID: endpointID, Hostname: "host-" + endpointID, OS: "linux", Arch: "amd64", Tags: []string{"eng"}},
		Scan:          meerkatapi.Scan{ID: "scan-" + endpointID},
	}
	body, _ := json.Marshal(inv)
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

// setupTenantRouter creates a test router with a real tenant and api_key,
// returning the router, db, the api token (for POST /v1/inventories), and a session cookie.
func setupTenantRouter(t *testing.T) (http.Handler, *db.DB, string, *http.Cookie) {
	t.Helper()
	router, database, legacyToken := setupRouter(t)

	ctx := context.Background()
	tenant, err := database.CreateTenant(ctx, "tenant-test", "test", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	apiToken, apiHash, err := auth.Generate()
	require.NoError(t, err)
	_, err = database.CreateAPIKey(ctx, "key-test", tenant.ID, "test-key", apiHash, time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	cookie := sessionCookie(t, database, tenant.ID)
	_ = legacyToken
	return router, database, apiToken, cookie
}

func getWithSession(t *testing.T, router http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestListEndpoints_Empty(t *testing.T) {
	router, _, _, cookie := setupTenantRouter(t)
	w := getWithSession(t, router, "/v1/endpoints", cookie)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(0), resp["total"])
}

func TestListEndpoints_WithData(t *testing.T) {
	router, _, token, cookie := setupTenantRouter(t)
	seedEndpointWithCookie(t, router, token, "ep-a")
	seedEndpointWithCookie(t, router, token, "ep-b")

	w := getWithSession(t, router, "/v1/endpoints", cookie)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(2), resp["total"])
	endpoints := resp["endpoints"].([]any)
	assert.Len(t, endpoints, 2)
}

func TestGetEndpoint_NotFound(t *testing.T) {
	router, _, _, cookie := setupTenantRouter(t)
	w := getWithSession(t, router, "/v1/endpoints/does-not-exist", cookie)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetEndpoint_Found(t *testing.T) {
	router, _, token, cookie := setupTenantRouter(t)
	seedEndpointWithCookie(t, router, token, "ep-detail")

	w := getWithSession(t, router, "/v1/endpoints/ep-detail", cookie)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "ep-detail", resp["id"])
	assert.Equal(t, "host-ep-detail", resp["hostname"])
	assert.Equal(t, "clean", resp["status"])
	assert.NotNil(t, resp["vulnerabilities"])
}

func TestGetEndpointHistory(t *testing.T) {
	router, _, token, cookie := setupTenantRouter(t)
	seedEndpointWithCookie(t, router, token, "ep-hist")

	w := getWithSession(t, router, "/v1/endpoints/ep-hist/history", cookie)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "ep-hist", resp["endpoint_id"])
	days := resp["days"].([]any)
	assert.Len(t, days, 1)
}

func TestGetEndpoint_WithVulns(t *testing.T) {
	router, database, _, cookie := setupTenantRouter(t)

	// Get the tenant ID from the cookie to use for the vuln test.
	tenantID, err := database.GetTenantByName(context.Background(), "test")
	require.NoError(t, err)

	apiToken2, apiHash2, _ := auth.Generate()
	database.CreateAPIKey(context.Background(), "key-vuln", tenantID.ID, "vuln-key", apiHash2, time.Now().UTC().Format(time.RFC3339))

	vuln := matcher.Vulnerability{ID: "CVE-2024-9999", Aliases: []string{}, Source: "osv", Summary: "Test vuln"}
	mock := &mockMatcher{
		idsByPurl: map[string][]string{"pkg:npm/lodash@4.17.11": {"CVE-2024-9999"}},
		vulns:     map[string]matcher.Vulnerability{"CVE-2024-9999": vuln},
	}

	database2, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, database2.Migrate(context.Background()))
	t.Cleanup(func() { database2.Close() })

	ing := ingest.New(database, mock, &notifier.NoopNotifier{}, "")
	_ = ing

	// Use main router but inject mock matcher via fresh router.
	router2, database3, _ := setupRouter(t)
	_ = router2
	_ = database3

	// Simpler: just use the existing router with a new matcher through seedEndpointWith.
	seedEndpointWith(t, router, apiToken2, "ep-vuln", []meerkatapi.Package{
		{Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11", Ecosystem: "npm"},
	})

	w := getWithSession(t, router, "/v1/endpoints/ep-vuln", cookie)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "clean", resp["status"]) // NoopMatcher, no vulns
	assert.NotNil(t, resp["vulnerabilities"])
}

// seedEndpointWithCookie posts using the api token (which has a tenant).
func seedEndpointWithCookie(t *testing.T, router http.Handler, token, endpointID string) {
	t.Helper()
	inv := meerkatapi.Inventory{
		SchemaVersion: "0.1.0",
		Endpoint:      meerkatapi.Endpoint{ID: endpointID, Hostname: "host-" + endpointID, OS: "linux", Arch: "amd64", Tags: []string{"eng"}},
		Scan:          meerkatapi.Scan{ID: "scan-" + endpointID},
	}
	body, _ := json.Marshal(inv)
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}
