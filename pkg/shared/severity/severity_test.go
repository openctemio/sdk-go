// Package severity provides unified severity level definitions and mappings.
package severity

import (
	"testing"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{Critical, "critical"},
		{High, "high"},
		{Medium, "medium"},
		{Low, "low"},
		{Info, "info"},
		{Unknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Level.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLevel_Priority(t *testing.T) {
	tests := []struct {
		level    Level
		expected int
	}{
		{Critical, 5},
		{High, 4},
		{Medium, 3},
		{Low, 2},
		{Info, 1},
		{Unknown, 0},
		{Level("invalid"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			if got := tt.level.Priority(); got != tt.expected {
				t.Errorf("Level.Priority() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLevel_IsHigherThan(t *testing.T) {
	tests := []struct {
		name     string
		a, b     Level
		expected bool
	}{
		{"Critical > High", Critical, High, true},
		{"High > Medium", High, Medium, true},
		{"Medium > Low", Medium, Low, true},
		{"Low > Info", Low, Info, true},
		{"Info > Unknown", Info, Unknown, true},
		{"Same severity", High, High, false},
		{"Low not > High", Low, High, false},
		{"Unknown not > Critical", Unknown, Critical, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.IsHigherThan(tt.b); got != tt.expected {
				t.Errorf("Level.IsHigherThan() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLevel_IsAtLeast(t *testing.T) {
	tests := []struct {
		name     string
		a, b     Level
		expected bool
	}{
		{"Critical >= High", Critical, High, true},
		{"High >= High", High, High, true},
		{"High >= Critical", High, Critical, false},
		{"Low >= Low", Low, Low, true},
		{"Info >= Unknown", Info, Unknown, true},
		{"Unknown >= Info", Unknown, Info, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.IsAtLeast(tt.b); got != tt.expected {
				t.Errorf("Level.IsAtLeast() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAllLevels(t *testing.T) {
	levels := AllLevels()
	if len(levels) != 6 {
		t.Errorf("AllLevels() returned %d levels, want 6", len(levels))
	}

	// Verify order (highest first)
	expected := []Level{Critical, High, Medium, Low, Info, Unknown}
	for i, lvl := range levels {
		if lvl != expected[i] {
			t.Errorf("AllLevels()[%d] = %v, want %v", i, lvl, expected[i])
		}
	}
}

func TestFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		// Critical variants
		{"CRITICAL", Critical},
		{"critical", Critical},
		{"crit", Critical},
		{"CRIT", Critical},
		// High variants
		{"HIGH", High},
		{"high", High},
		{"ERROR", High},
		{"error", High},
		{"SEVERE", High},
		// Medium variants
		{"MEDIUM", Medium},
		{"medium", Medium},
		{"MODERATE", Medium},
		{"WARNING", Warning},
		{"warning", Medium},
		{"WARN", Medium},
		{"MED", Medium},
		// Low
		{"LOW", Low},
		{"low", Low},
		// Info variants
		{"INFO", Info},
		{"info", Info},
		{"INFORMATIONAL", Info},
		{"NOTE", Info},
		{"NONE", Info},
		// Unknown
		{"unknown", Unknown},
		{"UNKNOWN", Unknown},
		{"", Unknown},
		{"invalid", Unknown},
		{"random", Unknown},
		// Whitespace handling
		{"  HIGH  ", High},
		{"\tmedium\n", Medium},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := FromString(tt.input); got != tt.expected {
				t.Errorf("FromString(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// Warning is an alias for Medium severity
const Warning Level = Medium

func TestFromCVSS(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected Level
	}{
		// Critical: 9.0-10.0
		{"10.0 is Critical", 10.0, Critical},
		{"9.5 is Critical", 9.5, Critical},
		{"9.0 is Critical", 9.0, Critical},
		// High: 7.0-8.9
		{"8.9 is High", 8.9, High},
		{"8.0 is High", 8.0, High},
		{"7.0 is High", 7.0, High},
		// Medium: 4.0-6.9
		{"6.9 is Medium", 6.9, Medium},
		{"5.0 is Medium", 5.0, Medium},
		{"4.0 is Medium", 4.0, Medium},
		// Low: 0.1-3.9
		{"3.9 is Low", 3.9, Low},
		{"2.0 is Low", 2.0, Low},
		{"0.1 is Low", 0.1, Low},
		// Info: 0.0
		{"0.0 is Info", 0.0, Info},
		// Edge cases
		{"Negative is Info", -1.0, Info},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromCVSS(tt.score); got != tt.expected {
				t.Errorf("FromCVSS(%v) = %v, want %v", tt.score, got, tt.expected)
			}
		})
	}
}

func TestLevel_ToCVSSRange(t *testing.T) {
	tests := []struct {
		level       Level
		expectedMin float64
		expectedMax float64
	}{
		{Critical, 9.0, 10.1},
		{High, 7.0, 9.0},
		{Medium, 4.0, 7.0},
		{Low, 0.1, 4.0},
		{Info, 0.0, 0.1},
		{Unknown, 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			min, max := tt.level.ToCVSSRange()
			if min != tt.expectedMin || max != tt.expectedMax {
				t.Errorf("Level.ToCVSSRange() = (%v, %v), want (%v, %v)",
					min, max, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name     string
		a, b     Level
		expected int
	}{
		{"Critical vs High", Critical, High, 1},
		{"High vs Critical", High, Critical, -1},
		{"High vs High", High, High, 0},
		{"Low vs Medium", Low, Medium, -1},
		{"Unknown vs Info", Unknown, Info, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.a, tt.b); got != tt.expected {
				t.Errorf("Compare(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestMax(t *testing.T) {
	tests := []struct {
		name     string
		a, b     Level
		expected Level
	}{
		{"Critical vs High", Critical, High, Critical},
		{"High vs Critical", High, Critical, Critical},
		{"Low vs Medium", Low, Medium, Medium},
		{"Same severity", High, High, High},
		{"Unknown vs Info", Unknown, Info, Info},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Max(tt.a, tt.b); got != tt.expected {
				t.Errorf("Max(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		name     string
		a, b     Level
		expected Level
	}{
		{"Critical vs High", Critical, High, High},
		{"High vs Critical", High, Critical, High},
		{"Low vs Medium", Low, Medium, Low},
		{"Same severity", High, High, High},
		{"Unknown vs Info", Unknown, Info, Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Min(tt.a, tt.b); got != tt.expected {
				t.Errorf("Min(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestCountBySeverity_Increment(t *testing.T) {
	c := &CountBySeverity{}

	// Increment each severity
	c.Increment(Critical)
	c.Increment(Critical)
	c.Increment(High)
	c.Increment(Medium)
	c.Increment(Medium)
	c.Increment(Medium)
	c.Increment(Low)
	c.Increment(Info)
	c.Increment(Unknown)
	c.Increment(Level("invalid")) // Should increment Unknown

	// Verify counts
	if c.Critical != 2 {
		t.Errorf("Critical = %d, want 2", c.Critical)
	}
	if c.High != 1 {
		t.Errorf("High = %d, want 1", c.High)
	}
	if c.Medium != 3 {
		t.Errorf("Medium = %d, want 3", c.Medium)
	}
	if c.Low != 1 {
		t.Errorf("Low = %d, want 1", c.Low)
	}
	if c.Info != 1 {
		t.Errorf("Info = %d, want 1", c.Info)
	}
	if c.Unknown != 2 {
		t.Errorf("Unknown = %d, want 2", c.Unknown)
	}
	if c.Total != 10 {
		t.Errorf("Total = %d, want 10", c.Total)
	}
}

func TestCountBySeverity_HighestSeverity(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*CountBySeverity)
		expected Level
	}{
		{
			"Critical present",
			func(c *CountBySeverity) { c.Critical = 1; c.High = 2; c.Medium = 3 },
			Critical,
		},
		{
			"High is highest",
			func(c *CountBySeverity) { c.High = 1; c.Medium = 2 },
			High,
		},
		{
			"Medium is highest",
			func(c *CountBySeverity) { c.Medium = 1; c.Low = 2 },
			Medium,
		},
		{
			"Low is highest",
			func(c *CountBySeverity) { c.Low = 1; c.Info = 2 },
			Low,
		},
		{
			"Info is highest",
			func(c *CountBySeverity) { c.Info = 1 },
			Info,
		},
		{
			"All zero returns Unknown",
			func(c *CountBySeverity) {},
			Unknown,
		},
		{
			"Only Unknown present",
			func(c *CountBySeverity) { c.Unknown = 5 },
			Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CountBySeverity{}
			tt.setup(c)
			if got := c.HighestSeverity(); got != tt.expected {
				t.Errorf("HighestSeverity() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance-critical functions
func BenchmarkFromString(b *testing.B) {
	inputs := []string{"CRITICAL", "high", "MEDIUM", "low", "INFO", "unknown", "invalid"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FromString(inputs[i%len(inputs)])
	}
}

func BenchmarkFromCVSS(b *testing.B) {
	scores := []float64{9.5, 7.5, 5.5, 2.5, 0.0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FromCVSS(scores[i%len(scores)])
	}
}

func BenchmarkCompare(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compare(Critical, High)
	}
}
