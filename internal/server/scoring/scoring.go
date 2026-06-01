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
		return "moderate"
	case score > 0:
		return "low"
	default:
		return "clean"
	}
}
