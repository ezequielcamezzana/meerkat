package matcher_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	batchResp, err := os.ReadFile("../../../testdata/osv/querybatch-response.json")
	require.NoError(t, err)
	vulnDetail, err := os.ReadFile("../../../testdata/osv/vuln-detail.json")
	require.NoError(t, err)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch" {
			w.Write(batchResp)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			w.Write(vulnDetail)
			return
		}
		http.NotFound(w, r)
	}))
}

func TestOSVMatcher_Match(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	m := matcher.NewOSVMatcher(matcher.OSVConfig{BaseURL: srv.URL})
	packages := []api.Package{
		{Purl: "pkg:npm/lodash@4.17.11"},
		{Purl: "pkg:npm/express@4.18.0"},
	}

	matches, err := m.Match(context.Background(), packages)
	require.NoError(t, err)
	require.Len(t, matches, 1)

	assert.Equal(t, "pkg:npm/lodash@4.17.11", matches[0].Purl)
	assert.Equal(t, "GHSA-jf85-cpcp-j695", matches[0].Vulnerability.ID)
	assert.Equal(t, []string{"CVE-2019-10744"}, matches[0].Vulnerability.Aliases)
	assert.Equal(t, "CVE-2019-10744", matcher.Canonical(matches[0].Vulnerability))
}

func TestOSVMatcher_NoVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	defer srv.Close()

	m := matcher.NewOSVMatcher(matcher.OSVConfig{BaseURL: srv.URL})
	matches, err := m.Match(context.Background(), []api.Package{{Purl: "pkg:npm/safe-pkg@1.0.0"}})
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestOSVMatcher_EmptyPackages(t *testing.T) {
	m := matcher.NewOSVMatcher(matcher.OSVConfig{})
	matches, err := m.Match(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestOSVMatcher_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := matcher.NewOSVMatcher(matcher.OSVConfig{BaseURL: srv.URL})
	_, err := m.Match(context.Background(), []api.Package{{Purl: "pkg:npm/lodash@4.17.11"}})
	require.Error(t, err)
}
