// Package ui embeds the server's web frontend assets.
package ui

import "embed"

//go:embed index.html site.html assets
var FS embed.FS
