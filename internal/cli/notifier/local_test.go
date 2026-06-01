package notifier

import (
	"strings"
	"testing"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/require"
)

func makeVulns(ids ...string) []api.NewVulnRef {
	refs := make([]api.NewVulnRef, len(ids))
	for i, id := range ids {
		refs[i] = api.NewVulnRef{CanonicalID: id}
	}
	return refs
}

func TestLocal_disabled_noAlert(t *testing.T) {
	called := false
	l := &Local{enabled: false, alertFn: func(_, _ string, _ any) error { called = true; return nil }}
	require.NoError(t, l.Notify(api.Endpoint{Hostname: "host"}, makeVulns("CVE-1"), ""))
	require.False(t, called)
}

func TestLocal_emptyVulns_noAlert(t *testing.T) {
	called := false
	l := &Local{enabled: true, alertFn: func(_, _ string, _ any) error { called = true; return nil }}
	require.NoError(t, l.Notify(api.Endpoint{Hostname: "host"}, nil, ""))
	require.False(t, called)
}

func TestLocal_oneVuln_bodyContainsID(t *testing.T) {
	var body string
	l := &Local{enabled: true, alertFn: func(_, b string, _ any) error { body = b; return nil }}
	require.NoError(t, l.Notify(api.Endpoint{Hostname: "web-01"}, makeVulns("CVE-2024-0001"), ""))
	require.Contains(t, body, "CVE-2024-0001")
	require.Contains(t, body, "web-01")
}

func TestLocal_fiveVulns_bodyHasMore(t *testing.T) {
	var body string
	l := &Local{enabled: true, alertFn: func(_, b string, _ any) error { body = b; return nil }}
	vulns := makeVulns("CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5")
	require.NoError(t, l.Notify(api.Endpoint{Hostname: "host"}, vulns, ""))
	require.Contains(t, body, "+3 more")
}

func TestLocal_withURL_appendsURL(t *testing.T) {
	var body string
	l := &Local{enabled: true, alertFn: func(_, b string, _ any) error { body = b; return nil }}
	require.NoError(t, l.Notify(api.Endpoint{Hostname: "host"}, makeVulns("CVE-1"), "http://meerkat/endpoints/abc"))
	require.True(t, strings.HasSuffix(body, "http://meerkat/endpoints/abc"))
}

func TestLocal_noURL_noTrailingNewline(t *testing.T) {
	var body string
	l := &Local{enabled: true, alertFn: func(_, b string, _ any) error { body = b; return nil }}
	require.NoError(t, l.Notify(api.Endpoint{Hostname: "host"}, makeVulns("CVE-1"), ""))
	require.False(t, strings.Contains(body, "\n"))
}
