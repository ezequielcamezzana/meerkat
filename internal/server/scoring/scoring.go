// Package scoring computes exposure scores from severity, dependency scope and
// package kind, and buckets them into risk levels.
package scoring

func ScopeWeight(scope string) float64 {
	switch scope {
	case "dev":
		return 0.6
	case "optional":
		return 0.4
	default:
		return 1.0
	}
}

func KindWeight(kind string) float64 {
	switch kind {
	case "global-package":
		return 0.8
	case "project-dependency":
		return 0.6
	default:
		return 1.0
	}
}

func ExposureScore(severity, scopeWeight, kindWeight float64) float64 {
	return severity * scopeWeight * kindWeight
}

func Bucket(score float64) string {
	switch {
	case score >= 7.0:
		return "critical"
	case score >= 4.0:
		return "high"
	case score >= 2.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "clean"
	}
}

// CVSSBucket maps a CVSS v3 base score to a severity bucket. Unlike Bucket,
// which works on the exposure scale, this uses the standard CVSS thresholds.
func CVSSBucket(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "clean"
	}
}
