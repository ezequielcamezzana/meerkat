package scanner

import (
	"context"

	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type Scanner interface {
	Scan(ctx context.Context, p walker.Project) ([]api.Package, error)
}
