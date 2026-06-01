package api

import "time"

type Inventory struct {
	SchemaVersion string    `json:"schema_version"`
	Scanner       Scanner   `json:"scanner"`
	Endpoint      Endpoint  `json:"endpoint"`
	Scan          Scan      `json:"scan"`
	Packages      []Package `json:"packages"`
}

type Scanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Endpoint struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	User     string   `json:"user"`
	Tags     []string `json:"tags"`
}

type Scan struct {
	ID                  string         `json:"id"`
	StartedAt           time.Time      `json:"started_at"`
	Root                string         `json:"root"`
	ProjectsScanned     int            `json:"projects_scanned"`
	ProjectsByEcosystem map[string]int `json:"projects_by_ecosystem,omitempty"`
	WalkMillis          int64          `json:"walk_millis,omitempty"`
	CatalogMillis       int64          `json:"catalog_millis,omitempty"`
	ScanMillis          int64          `json:"scan_millis,omitempty"`
	CacheHits           int            `json:"cache_hits"`
	CacheMisses         int            `json:"cache_misses"`
	Errors              []ScanError    `json:"errors,omitempty"`
}

type ScanError struct {
	ProjectDir string `json:"project_dir"`
	Ecosystem  string `json:"ecosystem"`
	Message    string `json:"message"`
}

type Package struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Purl      string   `json:"purl"`
	Scope     string   `json:"scope"`
	Direct    bool     `json:"direct"`
	Kind      string   `json:"kind"`
	Dirs      []string `json:"dirs"`
}

type NewVulnRef struct {
	CanonicalID string `json:"canonical_id"`
	Summary     string `json:"summary"`
}
