// Package notifier emails users about newly discovered vulnerabilities.
package notifier

import (
	"context"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type NewVuln struct {
	CanonicalID string
	Summary     string
	PackageName string
	PackageVer  string
	Purl        string
}

type Notifier interface {
	SendNew(ctx context.Context, endpoint api.Endpoint, vulns []NewVuln, recipients []string, endpointURL string) error
}

type NoopNotifier struct{}

func (n *NoopNotifier) SendNew(_ context.Context, _ api.Endpoint, _ []NewVuln, _ []string, _ string) error {
	return nil
}
