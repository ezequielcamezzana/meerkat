package scoring

import (
	"encoding/json"
	"strings"

	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

type osvSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRaw struct {
	Severity []osvSeverityEntry `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// SeverityScore derives a 0–10 severity score from an OSV vulnerability's raw JSON.
// Returns (score, source) where source is one of: "cvss_v3", "cvss_v4", "string", "unknown".
func SeverityScore(raw json.RawMessage) (float64, string) {
	if len(raw) == 0 {
		return 5.0, "unknown"
	}

	var v osvRaw
	if err := json.Unmarshal(raw, &v); err != nil {
		return 5.0, "unknown"
	}

	var maxV3, maxV4 float64
	for _, s := range v.Severity {
		switch s.Type {
		case "CVSS_V3":
			if score := parseCVSSv3(s.Score); score > maxV3 {
				maxV3 = score
			}
		case "CVSS_V4":
			if score := parseCVSSv4(s.Score); score > maxV4 {
				maxV4 = score
			}
		}
	}

	if maxV3 > 0 {
		return maxV3, "cvss_v3"
	}
	if maxV4 > 0 {
		return maxV4, "cvss_v4"
	}

	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return 9.0, "string"
	case "HIGH":
		return 7.5, "string"
	case "MODERATE", "MEDIUM":
		return 5.0, "string"
	case "LOW":
		return 3.0, "string"
	}

	return 5.0, "unknown"
}

func parseCVSSv3(vector string) float64 {
	if strings.HasPrefix(vector, "CVSS:3.0/") {
		v, err := cvss30.ParseVector(vector)
		if err != nil {
			return 0
		}
		return v.BaseScore()
	}
	v, err := cvss31.ParseVector(vector)
	if err != nil {
		return 0
	}
	return v.BaseScore()
}

func parseCVSSv4(vector string) float64 {
	v, err := cvss40.ParseVector(vector)
	if err != nil {
		return 0
	}
	return v.Score()
}
