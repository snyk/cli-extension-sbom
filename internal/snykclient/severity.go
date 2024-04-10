package snykclient

import (
	"encoding/json"
	"fmt"
)

type SeverityLevel int

func (l SeverityLevel) String() string {
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

func (l *SeverityLevel) UnmarshalJSON(b []byte) error {
	var sev string
	if err := json.Unmarshal(b, &sev); err != nil {
		return err
	}

	switch sev {
	default:
		return fmt.Errorf("invalid severity level: %s", sev)
	case "low":
		*l = LowSeverity
	case "medium":
		*l = MediumSeverity
	case "high":
		*l = HighSeverity
	case "critical":
		*l = CriticalSeverity
	}

	return nil
}

const (
	LowSeverity SeverityLevel = iota
	MediumSeverity
	HighSeverity
	CriticalSeverity
)
