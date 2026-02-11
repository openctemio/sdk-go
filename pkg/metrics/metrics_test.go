package metrics

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryCollector(t *testing.T) {
	c := NewInMemoryCollector()

	t.Run("Counter", func(t *testing.T) {
		c.CounterInc("test_counter", "label1", "value1")
		c.CounterInc("test_counter", "label1", "value1")
		c.CounterAdd("test_counter", 5, "label1", "value1")

		got := c.GetCounter("test_counter", "label1", "value1")
		if got != 7 {
			t.Errorf("Counter = %v, want %v", got, 7)
		}
	})

	t.Run("Gauge", func(t *testing.T) {
		c.GaugeSet("test_gauge", 42, "label1", "value1")
		got := c.GetGauge("test_gauge", "label1", "value1")
		if got != 42 {
			t.Errorf("Gauge = %v, want %v", got, 42)
		}

		c.GaugeInc("test_gauge", "label1", "value1")
		got = c.GetGauge("test_gauge", "label1", "value1")
		if got != 43 {
			t.Errorf("Gauge after Inc = %v, want %v", got, 43)
		}

		c.GaugeDec("test_gauge", "label1", "value1")
		got = c.GetGauge("test_gauge", "label1", "value1")
		if got != 42 {
			t.Errorf("Gauge after Dec = %v, want %v", got, 42)
		}
	})

	t.Run("Histogram", func(t *testing.T) {
		c.HistogramObserve("test_histogram", 1.5, "label1", "value1")
		c.HistogramObserve("test_histogram", 2.5, "label1", "value1")
		c.HistogramObserve("test_histogram", 3.5, "label1", "value1")

		got := c.GetHistogram("test_histogram", "label1", "value1")
		if len(got) != 3 {
			t.Errorf("Histogram observations = %v, want %v", len(got), 3)
		}
	})

	t.Run("Summary", func(t *testing.T) {
		c.SummaryObserve("test_summary", 1.5, "label1", "value1")
		c.SummaryObserve("test_summary", 2.5, "label1", "value1")

		got := c.GetSummary("test_summary", "label1", "value1")
		if len(got) != 2 {
			t.Errorf("Summary observations = %v, want %v", len(got), 2)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		c.Reset()

		if c.GetCounter("test_counter", "label1", "value1") != 0 {
			t.Error("Counter should be 0 after reset")
		}
		if c.GetGauge("test_gauge", "label1", "value1") != 0 {
			t.Error("Gauge should be 0 after reset")
		}
	})
}

func TestNopCollector(t *testing.T) {
	c := &NopCollector{}

	// These should all be no-ops and not panic
	c.CounterInc("test", "label", "value")
	c.CounterAdd("test", 5, "label", "value")
	c.GaugeSet("test", 42, "label", "value")
	c.GaugeInc("test", "label", "value")
	c.GaugeDec("test", "label", "value")
	c.HistogramObserve("test", 1.5, "label", "value")
	c.SummaryObserve("test", 1.5, "label", "value")
	c.Reset()

	// Handler should return NotFoundHandler
	handler := c.Handler()
	if handler == nil {
		t.Error("Handler should not be nil")
	}
}

func TestTimer(t *testing.T) {
	c := NewInMemoryCollector()
	timer := NewTimer(c, "test_timer", "operation", "test")

	// Simulate some work
	time.Sleep(10 * time.Millisecond)

	duration := timer.ObserveDuration()
	if duration < 10*time.Millisecond {
		t.Errorf("Duration = %v, want >= 10ms", duration)
	}

	// Check that the histogram was updated
	observations := c.GetHistogram("test_timer", "operation", "test")
	if len(observations) != 1 {
		t.Errorf("Histogram observations = %v, want 1", len(observations))
	}
}

func TestDefaultCollector(t *testing.T) {
	// Default should be NopCollector
	collector := GetDefaultCollector()
	if collector == nil {
		t.Error("Default collector should not be nil")
	}

	// Set a custom collector
	custom := NewInMemoryCollector()
	SetDefaultCollector(custom)

	if GetDefaultCollector() != custom {
		t.Error("Default collector should be the custom collector")
	}

	// Set nil should reset to NopCollector
	SetDefaultCollector(nil)
	if _, ok := GetDefaultCollector().(*NopCollector); !ok {
		t.Error("Default collector should be NopCollector after setting nil")
	}
}

func TestCollectorFromContext(t *testing.T) {
	custom := NewInMemoryCollector()
	ctx := WithCollector(context.Background(), custom)

	if CollectorFromContext(ctx) != custom {
		t.Error("CollectorFromContext should return the custom collector")
	}

	// Without context, should return default
	if CollectorFromContext(context.Background()) != GetDefaultCollector() {
		t.Error("CollectorFromContext should return default when not set")
	}
}

func TestMetricDefinitions(t *testing.T) {
	// Test that default metric definitions are properly defined
	definitions := []MetricDefinition{
		ScannerScansTotal,
		ScannerScanDuration,
		ScannerFindingsTotal,
		CollectorCollectsTotal,
		CollectorItemsTotal,
		PusherPushesTotal,
		PusherFindingsPushed,
		PusherAssetsPushed,
		PusherRetries,
		AgentJobsTotal,
		AgentJobDuration,
		AgentQueueSize,
		AgentActiveJobs,
		AgentHeartbeats,
		EnricherEnrichmentsTotal,
		EnricherCacheHits,
		EnricherCacheMisses,
		HTTPRequestsTotal,
		HTTPRequestDuration,
	}

	for _, def := range definitions {
		if def.Name == "" {
			t.Errorf("Metric definition has empty name")
		}
		if def.Type == "" {
			t.Errorf("Metric %s has empty type", def.Name)
		}
		if def.Help == "" {
			t.Errorf("Metric %s has empty help", def.Name)
		}
	}
}

func TestLabelsToValues(t *testing.T) {
	tests := []struct {
		name     string
		labels   []string
		expected []string
	}{
		{
			name:     "empty",
			labels:   []string{},
			expected: nil,
		},
		{
			name:     "single pair",
			labels:   []string{"key1", "value1"},
			expected: []string{"value1"},
		},
		{
			name:     "multiple pairs",
			labels:   []string{"key1", "value1", "key2", "value2"},
			expected: []string{"value1", "value2"},
		},
		{
			name:     "odd number (incomplete pair)",
			labels:   []string{"key1", "value1", "key2"},
			expected: []string{"value1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsToValues(tt.labels)
			if len(got) != len(tt.expected) {
				t.Errorf("labelsToValues(%v) = %v, want %v", tt.labels, got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("labelsToValues(%v)[%d] = %v, want %v", tt.labels, i, got[i], tt.expected[i])
				}
			}
		})
	}
}
