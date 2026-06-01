package matcher

import (
	"context"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type NoopMatcher struct{}

func (n *NoopMatcher) QueryBatch(_ context.Context, _ []api.Package) (map[string][]string, error) {
	return nil, nil
}

func (n *NoopMatcher) FetchVulns(_ context.Context, _ []string) ([]Vulnerability, error) {
	return nil, nil
}
