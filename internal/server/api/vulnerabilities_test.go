package api_test

import (
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

func TestListVulns_Empty(t *testing.T) {
	router, _, _, cookie := setupTenantRouter(t)
	w := getWithSession(t, router, "/v1/vulnerabilities", cookie)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(0), resp["total"])
	assert.NotNil(t, resp["vulnerabilities"])
	assert.Len(t, resp["vulnerabilities"], 0)
}

func TestListVulns_Unauthorized(t *testing.T) {
	router, _, _, _ := setupTenantRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/vulnerabilities", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// setupSeededVulnRouter builds a router whose matcher maps lodash → CVE-2024-1111
// and ingests one endpoint carrying it, returning the router and a session cookie
// for the owning tenant.
func setupSeededVulnRouter(t *testing.T) (http.Handler, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, database.Migrate(ctx))
	t.Cleanup(func() { database.Close() })

	tenant, err := database.CreateTenant(ctx, "tenant-vuln", "vulns", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	apiToken, apiHash, err := auth.Generate()
	require.NoError(t, err)
	_, err = database.CreateAPIKey(ctx, "key-vuln", tenant.ID, "vuln-key", db.RoleComplete, apiHash, time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	vuln := matcher.Vulnerability{ID: "CVE-2024-1111", Aliases: []string{"GHSA-zzzz"}, Source: "osv", Summary: "test summary", Details: "advisory body"}
	mock := &mockMatcher{
		idsByPurl: map[string][]string{"pkg:npm/lodash@4.17.11": {"CVE-2024-1111"}},
		vulns:     map[string]matcher.Vulnerability{"CVE-2024-1111": vuln},
	}
	ing := ingest.New(database, mock, &notifier.NoopNotifier{}, "")
	cfg := &config.Config{CORSAllowedOrigins: []string{"*"}}
	router := serverapi.NewRouter(database, ing, cfg, "dev")
	cookie := sessionCookie(t, database, tenant.ID)

	seedEndpointWith(t, router, apiToken, "ep-vuln", []meerkatapi.Package{
		{Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11", Ecosystem: "npm"},
	})
	return router, cookie
}

func TestListVulns_WithData(t *testing.T) {
	router, cookie := setupSeededVulnRouter(t)

	w := getWithSession(t, router, "/v1/vulnerabilities?sort=exposure", cookie)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(1), resp["total"])
	vulns := resp["vulnerabilities"].([]any)
	require.Len(t, vulns, 1)
	row := vulns[0].(map[string]any)
	assert.NotEmpty(t, row["canonical_id"])
	assert.Equal(t, float64(1), row["affected_count"])
}

func TestGetVuln_Found(t *testing.T) {
	router, cookie := setupSeededVulnRouter(t)

	w := getWithSession(t, router, "/v1/vulnerabilities/CVE-2024-1111", cookie)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "CVE-2024-1111", resp["canonical_id"])
	assert.Equal(t, "advisory body", resp["details"])
	affected := resp["affected_endpoints"].([]any)
	require.Len(t, affected, 1)
	ep := affected[0].(map[string]any)
	assert.Equal(t, "ep-vuln", ep["endpoint_id"])
	assert.Equal(t, "lodash", ep["package_name"])
}

func TestGetVuln_NotFound(t *testing.T) {
	router, _, _, cookie := setupTenantRouter(t)
	w := getWithSession(t, router, "/v1/vulnerabilities/CVE-NOPE", cookie)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
