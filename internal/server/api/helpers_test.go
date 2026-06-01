package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	serverapi "github.com/ezequielcamezzana/meerkat/internal/server/api"
	"github.com/ezequielcamezzana/meerkat/internal/server/config"
	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/notifier"
	meerkatapi "github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/require"
)

type mockMatcher struct {
	idsByPurl map[string][]string
	vulns     map[string]matcher.Vulnerability
}

func (m *mockMatcher) QueryBatch(_ context.Context, _ []meerkatapi.Package) (map[string][]string, error) {
	return m.idsByPurl, nil
}

func (m *mockMatcher) FetchVulns(_ context.Context, ids []string) ([]matcher.Vulnerability, error) {
	var out []matcher.Vulnerability
	for _, id := range ids {
		if v, ok := m.vulns[id]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func openTestDB2(t *testing.T) (*db.DB, error) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		return nil, err
	}
	if err := database.Migrate(context.Background()); err != nil {
		return nil, err
	}
	t.Cleanup(func() { database.Close() })
	return database, nil
}

func setupRouterWith(t *testing.T, database *db.DB, ing *ingest.Ingest) http.Handler {
	t.Helper()
	cfg := &config.Config{CORSAllowedOrigins: []string{"*"}}
	return serverapi.NewRouter(database, ing, cfg)
}

func setupRouterDefault(t *testing.T, database *db.DB) http.Handler {
	t.Helper()
	ing := ingest.New(database, &matcher.NoopMatcher{}, &notifier.NoopNotifier{}, "")
	return setupRouterWith(t, database, ing)
}

func seedEndpointWith(t *testing.T, router http.Handler, token string, endpointID string, packages []meerkatapi.Package) {
	t.Helper()
	inv := meerkatapi.Inventory{
		SchemaVersion: "0.1.0",
		Endpoint:      meerkatapi.Endpoint{ID: endpointID, Hostname: "host-" + endpointID, OS: "linux", Arch: "amd64", Tags: []string{"eng"}},
		Scan:          meerkatapi.Scan{ID: "scan-" + endpointID},
		Packages:      packages,
	}
	body, _ := json.Marshal(inv)
	req := httptest.NewRequest(http.MethodPost, "/v1/inventories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}
