package ingest_test

import (
	"context"
	"testing"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/ingest"
	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/notifier"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(":memory:")
	require.NoError(t, err)
	require.NoError(t, database.Migrate(context.Background()))
	t.Cleanup(func() { database.Close() })
	return database
}

type mockMatcher struct {
	idsByPurl map[string][]string
	vulns     map[string]matcher.Vulnerability
}

func (m *mockMatcher) QueryBatch(_ context.Context, _ []api.Package) (map[string][]string, error) {
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

func testInventory(endpointID string, packages []api.Package) api.Inventory {
	return api.Inventory{
		SchemaVersion: "0.1.0",
		Endpoint: api.Endpoint{
			ID:       endpointID,
			Hostname: "test-host",
			OS:       "linux",
			Arch:     "amd64",
			Tags:     []string{"test"},
		},
		Scan: api.Scan{
			ID:        "scan-001",
			StartedAt: time.Now(),
		},
		Packages: packages,
	}
}

func TestProcess_Clean(t *testing.T) {
	database := openTestDB(t)
	ing := ingest.New(database, &matcher.NoopMatcher{}, &notifier.NoopNotifier{}, "")

	inv := testInventory("ep-001", []api.Package{{Purl: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}})

	result, err := ing.Process(context.Background(), inv, "")
	require.NoError(t, err)
	assert.Equal(t, "scan-001", result.ScanID)
	assert.Equal(t, "ep-001", result.EndpointID)
	assert.Equal(t, 0, result.VulnCount)
}

func TestProcess_WithVulns(t *testing.T) {
	database := openTestDB(t)
	vuln := matcher.Vulnerability{
		ID:      "CVE-2024-1234",
		Aliases: []string{},
		Summary: "Test vuln",
		Source:  "osv",
	}
	mock := &mockMatcher{
		idsByPurl: map[string][]string{"pkg:npm/lodash@4.17.11": {"CVE-2024-1234"}},
		vulns:     map[string]matcher.Vulnerability{"CVE-2024-1234": vuln},
	}
	ing := ingest.New(database, mock, &notifier.NoopNotifier{}, "")

	inv := testInventory("ep-002", []api.Package{{Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11", Ecosystem: "npm"}})
	result, err := ing.Process(context.Background(), inv, "")
	require.NoError(t, err)
	assert.Equal(t, 1, result.VulnCount)
}

func TestProcess_SecondScanReplacesVulns(t *testing.T) {
	database := openTestDB(t)
	vuln := matcher.Vulnerability{ID: "CVE-2024-1111", Aliases: []string{}, Source: "osv"}
	mock := &mockMatcher{
		idsByPurl: map[string][]string{"pkg:npm/pkg@1.0.0": {"CVE-2024-1111"}},
		vulns:     map[string]matcher.Vulnerability{"CVE-2024-1111": vuln},
	}
	ing := ingest.New(database, mock, &notifier.NoopNotifier{}, "")

	inv := testInventory("ep-003", []api.Package{{Purl: "pkg:npm/pkg@1.0.0"}})
	_, err := ing.Process(context.Background(), inv, "")
	require.NoError(t, err)

	// Second scan: no vulns
	ing2 := ingest.New(database, &matcher.NoopMatcher{}, &notifier.NoopNotifier{}, "")
	result, err := ing2.Process(context.Background(), inv, "")
	require.NoError(t, err)
	assert.Equal(t, 0, result.VulnCount)
}

func TestProcess_InvalidSchema(t *testing.T) {
	database := openTestDB(t)
	ing := ingest.New(database, &matcher.NoopMatcher{}, &notifier.NoopNotifier{}, "")

	inv := testInventory("ep-004", nil)
	inv.SchemaVersion = "9.9.9"

	_, err := ing.Process(context.Background(), inv, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported schema version")
}
