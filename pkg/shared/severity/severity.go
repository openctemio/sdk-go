// Package severity provides unified severity level definitions and mappings
// for security findings across SDK and Backend.
//
// IMPORTANT: This package is shared between sdk and api.
// Any changes must be backward compatible or coordinated across both projects.
package severity

import "strings"

// Level represents a severity level for security findings.
type Level string

const (
	// Critical - Immediate action required. Actively exploited or trivially exploitable.
	Critical Level = "critical"

	// High - Serious vulnerability that should be addressed urgently.
	High Level = "high"

	// Medium - Moderate risk, should be addressed in normal development cycle.
	Medium Level = "medium"

	// Low - Minor issue, address when convenient.
	Low Level = "low"

	// Info - Informational finding, no security impact.
	Info Level = "info"

	// Unknown - Severity could not be determined.
	Unknown Level = "unknown"
)

// AllLevels returns all severity levels in order of priority (highest first).
func AllLevels() []Level {
	return []Level{Critical, High, Medium, Low, Info, Unknown}
}

// String returns the string representation of the severity level.
func (l Level) String() string {
	return string(l)
}

// Priority returns the numeric priority of the severity level.
// Higher numbers = higher priority.
func (l Level) Priority() int {
	switch l {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// IsHigherThan returns true if this severity is higher than the other.
func (l Level) IsHigherThan(other Level) bool {
	return l.Priority() > other.Priority()
}

// IsAtLeast returns true if this severity is at least as high as the other.
func (l Level) IsAtLeast(other Level) bool {
	return l.Priority() >= other.Priority()
}

// FromString normalizes various severity string formats to a standard Level.
// Handles common formats from different scanners:
//   - Semgrep: ERROR, WARNING, INFO
//   - Trivy: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
//   - Gitleaks: (uses rule-based)
//   - SARIF: error, warning, note
func FromString(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "CRIT":
		return Critical
	case "HIGH", "ERROR", "SEVERE":
		return High
	case "MEDIUM", "MODERATE", "WARNING", "WARN", "MED":
		return Medium
	case "LOW":
		return Low
	case "INFO", "INFORMATIONAL", "NOTE", "NONE":
		return Info
	default:
		return Unknown
	}
}

// FromCVSS converts a CVSS score (0.0-10.0) to a severity level.
// Based on CVSS v3.0 severity ratings:
//   - 9.0-10.0: Critical
//   - 7.0-8.9: High
//   - 4.0-6.9: Medium
//   - 0.1-3.9: Low
//   - 0.0: Info
func FromCVSS(score float64) Level {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Info
	}
}

// ToCVSSRange returns the CVSS score range for a severity level.
// Returns (min, max) where min is inclusive and max is exclusive.
func (l Level) ToCVSSRange() (float64, float64) {
	switch l {
	case Critical:
		return 9.0, 10.1
	case High:
		return 7.0, 9.0
	case Medium:
		return 4.0, 7.0
	case Low:
		return 0.1, 4.0
	case Info:
		return 0.0, 0.1
	default:
		return 0.0, 0.0
	}
}

// Compare returns:
//
//	-1 if a < b (a is lower severity)
//	 0 if a == b
//	+1 if a > b (a is higher severity)
func Compare(a, b Level) int {
	pa, pb := a.Priority(), b.Priority()
	switch {
	case pa < pb:
		return -1
	case pa > pb:
		return 1
	default:
		return 0
	}
}

// Max returns the higher severity of two levels.
func Max(a, b Level) Level {
	if a.IsHigherThan(b) {
		return a
	}
	return b
}

// Min returns the lower severity of two levels.
func Min(a, b Level) Level {
	if a.IsHigherThan(b) {
		return b
	}
	return a
}

// CountBySeverity counts findings by severity level.
type CountBySeverity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// Increment increases the count for the given severity.
func (c *CountBySeverity) Increment(level Level) {
	c.Total++
	switch level {
	case Critical:
		c.Critical++
	case High:
		c.High++
	case Medium:
		c.Medium++
	case Low:
		c.Low++
	case Info:
		c.Info++
	default:
		c.Unknown++
	}
}

// HighestSeverity returns the highest severity level that has a non-zero count.
func (c *CountBySeverity) HighestSeverity() Level {
	if c.Critical > 0 {
		return Critical
	}
	if c.High > 0 {
		return High
	}
	if c.Medium > 0 {
		return Medium
	}
	if c.Low > 0 {
		return Low
	}
	if c.Info > 0 {
		return Info
	}
	return Unknown
}
