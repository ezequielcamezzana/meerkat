package cataloger

import (
	"context"
	"fmt"
	"sync"

	"github.com/ezequielcamezzana/meerkat/internal/cli/scanner"
	"github.com/ezequielcamezzana/meerkat/internal/cli/walker"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type ProjectError struct {
	Project walker.Project
	Err     error
}

type Cataloger struct {
	scanner scanner.Scanner
	workers int
}

func New(s scanner.Scanner, workers int) *Cataloger {
	return &Cataloger{scanner: s, workers: workers}
}

func (c *Cataloger) Catalog(ctx context.Context, projects <-chan walker.Project) (<-chan api.Package, <-chan ProjectError) {
	packages := make(chan api.Package)
	errs := make(chan ProjectError)

	var wg sync.WaitGroup
	for range c.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.work(ctx, projects, packages, errs)
		}()
	}

	go func() {
		wg.Wait()
		close(packages)
		close(errs)
	}()

	return packages, errs
}

func (c *Cataloger) work(ctx context.Context, projects <-chan walker.Project, packages chan<- api.Package, errs chan<- ProjectError) {
	for p := range projects {
		func() {
			defer func() {
				if r := recover(); r != nil {
					errs <- ProjectError{
						Project: p,
						Err:     fmt.Errorf("panic: %v", r),
					}
				}
			}()

			pkgs, err := c.scanner.Scan(ctx, p)
			if err != nil {
				errs <- ProjectError{Project: p, Err: err}
				return
			}

			for _, pkg := range pkgs {
				select {
				case packages <- pkg:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}
