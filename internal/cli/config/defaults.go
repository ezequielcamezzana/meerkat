package config

import "github.com/google/uuid"

// Platform-specific excludes populated by platform init() functions.
var PlatformBaseExcludes []string
var PlatformExcludes []string
var PlatformPatternExcludes []string

func Defaults() *Config {
	return &Config{
		SchemaVersion: SchemaVersion,
		Endpoint: EndpointConfig{
			ID:   uuid.NewString(),
			Tags: []string{},
		},
		Scan: ScanConfig{
			Interval: "1h",
			Root:     "/",
			Excludes: DefaultExcludes(),
		},
		Server:        ServerConfig{},
		Notifications: NotificationsConfig{Local: true},
	}
}

func DefaultExcludes() []string {
	common := []string{
		// Build artifacts
		"node_modules",
		"target",
		"build",
		"dist",
		"out",
		".next",
		".nuxt",
		".svelte-kit",
		".angular",
		".gradle",
		".mvn",
		"vendor",
		// VCS
		".git",
		".svn",
		".hg",
		// Tool caches
		"__pycache__",
		".pytest_cache",
		".mypy_cache",
		".tox",
		".cache",
		// Virtual envs
		"venv",
		".venv",
		"env",
		"virtualenv",
		// IDEs
		".idea",
		".vscode",
	}

	common = append(common, PlatformBaseExcludes...)
	common = append(common, PlatformExcludes...)
	common = append(common, PlatformPatternExcludes...)
	return common
}
