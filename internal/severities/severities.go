package severities

import (
	"fmt"
	"strings"
)

const (
	LowSeverity Level = iota
	MediumSeverity
	HighSeverity
	CriticalSeverity
)

type Level int

func (l Level) String() string {
	switch l {
	default:
		return ""

	case LowSeverity:
		return "LOW"

	case MediumSeverity:
		return "MEDIUM"

	case HighSeverity:
		return "HIGH"

	case CriticalSeverity:
		return "CRITICAL"
	}
}

// Parse returns corresponding SeverityLevel constant, or an error if
// caller provides an invalid value.
func Parse(s string) (Level, error) {
	switch strings.ToLower(s) {
	default:
		return -1, fmt.Errorf("invalid severity level: %s", s)

	case "low":
		return LowSeverity, nil

	case "medium":
		return MediumSeverity, nil

	case "high":
		return HighSeverity, nil

	case "critical":
		return CriticalSeverity, nil
	}
}
