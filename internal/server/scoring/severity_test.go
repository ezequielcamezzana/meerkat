package scoring

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		name       string
		raw        json.RawMessage
		wantScore  float64
		wantSource string
	}{
		{
			name:       "cvss v3.1 critical vector",
			raw:        raw(`{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`),
			wantScore:  9.8,
			wantSource: "cvss_v3",
		},
		{
			name:       "cvss v3.0 vector",
			raw:        raw(`{"severity":[{"type":"CVSS_V3","score":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}`),
			wantScore:  7.5,
			wantSource: "cvss_v3",
		},
		{
			name:       "database_specific CRITICAL",
			raw:        raw(`{"database_specific":{"severity":"CRITICAL"}}`),
			wantScore:  9.0,
			wantSource: "string",
		},
		{
			name:       "database_specific HIGH",
			raw:        raw(`{"database_specific":{"severity":"HIGH"}}`),
			wantScore:  7.5,
			wantSource: "string",
		},
		{
			name:       "database_specific MODERATE",
			raw:        raw(`{"database_specific":{"severity":"MODERATE"}}`),
			wantScore:  5.0,
			wantSource: "string",
		},
		{
			name:       "database_specific MEDIUM",
			raw:        raw(`{"database_specific":{"severity":"MEDIUM"}}`),
			wantScore:  5.0,
			wantSource: "string",
		},
		{
			name:       "database_specific LOW",
			raw:        raw(`{"database_specific":{"severity":"LOW"}}`),
			wantScore:  3.0,
			wantSource: "string",
		},
		{
			name:       "multiple severity entries — max wins",
			raw:        raw(`{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`),
			wantScore:  9.8,
			wantSource: "cvss_v3",
		},
		{
			name:       "no severity — fallback 5.0",
			raw:        raw(`{"id":"TEST-001","summary":"no severity"}`),
			wantScore:  5.0,
			wantSource: "unknown",
		},
		{
			name:       "empty raw",
			raw:        nil,
			wantScore:  5.0,
			wantSource: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, source := SeverityScore(tc.raw)
			assert.Equal(t, tc.wantSource, source)
			assert.InDelta(t, tc.wantScore, score, 0.05)
		})
	}
}
