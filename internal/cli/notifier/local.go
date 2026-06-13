// Package notifier surfaces scan results to the local user via desktop
// notifications.
package notifier

import (
	"fmt"
	"strings"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type Local struct {
	enabled bool
	alertFn func(title, body string, icon any) error
}

func New(enabled bool) *Local {
	return &Local{enabled: enabled, alertFn: defaultAlertFn}
}

func (l *Local) Notify(endpoint api.Endpoint, vulns []api.NewVulnRef, endpointURL string) error {
	if !l.enabled || len(vulns) == 0 {
		return nil
	}

	body := formatBody(endpoint.Hostname, vulns)
	if endpointURL != "" {
		body += "\n" + endpointURL
	}

	return l.alertFn("meerkat", body, "")
}

func formatBody(hostname string, vulns []api.NewVulnRef) string {
	n := len(vulns)
	switch {
	case n == 1:
		return fmt.Sprintf("1 new vulnerability on %s: %s", hostname, vulns[0].CanonicalID)
	case n <= 3:
		ids := make([]string, n)
		for i, v := range vulns {
			ids[i] = v.CanonicalID
		}
		return fmt.Sprintf("%d new vulnerabilities on %s: %s", n, hostname, strings.Join(ids, ", "))
	default:
		return fmt.Sprintf("%d new vulnerabilities on %s: %s, %s, +%d more",
			n, hostname, vulns[0].CanonicalID, vulns[1].CanonicalID, n-2)
	}
}
