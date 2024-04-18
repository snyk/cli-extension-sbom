package severities

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	LowSeverity Level = iota + 1
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

// UnmarshalJSON implements the json.Unmarshaler interface.
func (l *Level) UnmarshalJSON(b []byte) error {
	var sev string
	err := json.Unmarshal(b, &sev)
	if err != nil {
		return err
	}

	*l, err = Parse(sev)
	if err != nil {
		return err
	}

	return nil
}

func (l Level) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.ToLower(l.String()))
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
