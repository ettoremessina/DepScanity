package model

import (
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityRank returns an integer rank for comparison (Low=1, Critical=4).
func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

func (s Severity) String() string {
	return string(s)
}

// ParseSeverity parses a severity string case-insensitively.
// Accepts "moderate" as "medium".
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "low":
		return SeverityLow, nil
	case "medium", "moderate":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityUnknown, fmt.Errorf("invalid severity: %s", s)
	}
}
