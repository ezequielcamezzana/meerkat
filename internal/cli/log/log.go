// Package log configures the CLI's slog logger, picking text or colored output
// based on whether stderr is a terminal.
package log

import (
	"log/slog"
	"os"

	"golang.org/x/term"
)

func Setup(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	var handler slog.Handler
	if term.IsTerminal(int(os.Stderr.Fd())) {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}

	return slog.New(handler)
}
