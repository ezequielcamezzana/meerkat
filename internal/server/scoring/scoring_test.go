package scoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeWeight(t *testing.T) {
	tests := []struct {
		scope string
		want  float64
	}{
		{"runtime", 1.0},
		{"dev", 0.6},
		{"optional", 0.4},
		{"", 1.0},
		{"unknown-scope", 1.0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, ScopeWeight(tc.scope), "scope=%s", tc.scope)
	}
}

func TestKindWeight(t *testing.T) {
	tests := []struct {
		kind string
		want float64
	}{
		{"system-package", 1.0},
		{"global-package", 0.8},
		{"project-dependency", 0.6},
		{"", 1.0},
		{"unknown-kind", 1.0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, KindWeight(tc.kind), "kind=%s", tc.kind)
	}
}

func TestExposureScore(t *testing.T) {
	assert.Equal(t, 0.0, ExposureScore(0, 1.0, 1.0))
	assert.Equal(t, 10.0, ExposureScore(10, 1.0, 1.0))
	assert.Equal(t, 5.0, ExposureScore(10, 1.0, 0.5))
	assert.Equal(t, 3.0, ExposureScore(10, 0.6, 0.5))
}

func TestBucket(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, "critical"},
		{7.0, "critical"},
		{6.9, "high"},
		{4.0, "high"},
		{3.9, "moderate"},
		{2.0, "moderate"},
		{1.9, "low"},
		{0.1, "low"},
		{0.0, "clean"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, Bucket(tc.score), "score=%.1f", tc.score)
	}
}
