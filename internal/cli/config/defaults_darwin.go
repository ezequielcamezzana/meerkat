//go:build darwin

package config

func init() {
	PlatformBaseExcludes = []string{
		".fseventsd",
		".Spotlight-V100",
		".DocumentRevisions-V100",
		".PKInstallSandboxManager",
		".PKInstallSandboxManager-SystemSoftware",
		".TemporaryItems",
		".Trashes",
	}

	PlatformExcludes = []string{
		// Personal data (TCC-protected)
		"~/Pictures",
		"~/Music",
		"~/Movies",
		"~/Desktop",
		"~/Documents",
		"~/Downloads",
		// Library subpaths (TCC-protected)
		"~/Library/Mail",
		"~/Library/Messages",
		"~/Library/Calendars",
		"~/Library/AddressBook",
		"~/Library/Application Support/AddressBook",
		"~/Library/Application Support/com.apple.TCC",
		"~/Library/Application Support/MobileSync",
		"~/Library/Cookies",
		"~/Library/HomeKit",
		"~/Library/IdentityServices",
		"~/Library/Mobile Documents",
		"~/Library/Safari",
		"~/Library/Suggestions",
		// System paths
		"/System",
		"/private/var/db",
		"/private/var/folders",
		"/private/var/vm",
		"/Volumes",
	}

	// Electron app bundles — contain node_modules that don't belong to the user
	PlatformPatternExcludes = []string{
		"/Applications/*.app",
		"~/Applications/*.app",
	}
}
