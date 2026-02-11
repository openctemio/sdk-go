// Package metrics provides metrics collection and reporting for the OpenCTEM SDK.
// It includes interfaces for metric collection and a Prometheus-compatible implementation.
package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// =============================================================================
// Metrics Interface
// =============================================================================

// Collector is the interface for collecting and reporting metrics.
// Implement this interface to use custom metrics backends (Prometheus, StatsD, etc.).
type Collector interface {
	// Counter operations
	CounterInc(name string, labels ...string)
	CounterAdd(name string, value float64, labels ...string)

	// Gauge operations
	GaugeSet(name string, value float64, labels ...string)
	GaugeInc(name string, labels ...string)
	GaugeDec(name string, labels ...string)

	// Histogram operations
	HistogramObserve(name string, value float64, labels ...string)

	// Summary operations
	SummaryObserve(name string, value float64, labels ...string)

	// Handler returns an HTTP handler for metrics endpoint
	Handler() http.Handler

	// Reset clears all metrics (for testing)
	Reset()
}

// =============================================================================
// Metric Types
// =============================================================================

// MetricType represents the type of metric.
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// MetricDefinition defines a metric with its metadata.
type MetricDefinition struct {
	Name       string     `json:"name"`
	Type       MetricType `json:"type"`
	Help       string     `json:"help"`
	Labels     []string   `json:"labels,omitempty"`
	Buckets    []float64  `json:"buckets,omitempty"`     // For histograms
	Objectives []float64  `json:"objectives,omitempty"`  // For summaries
	MaxAge     int        `json:"max_age,omitempty"`     // For summaries (seconds)
	AgeBuckets int        `json:"age_buckets,omitempty"` // For summaries
}

// =============================================================================
// Default Metrics - Standard metrics for OpenCTEM SDK
// =============================================================================

var (
	// Scanner metrics
	ScannerScansTotal = MetricDefinition{
		Name:   "openctem_scanner_scans_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of scans executed",
		Labels: []string{"scanner", "status"},
	}
	ScannerScanDuration = MetricDefinition{
		Name:    "openctem_scanner_scan_duration_seconds",
		Type:    MetricTypeHistogram,
		Help:    "Duration of scans in seconds",
		Labels:  []string{"scanner"},
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
	}
	ScannerFindingsTotal = MetricDefinition{
		Name:   "openctem_scanner_findings_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of findings discovered",
		Labels: []string{"scanner", "severity"},
	}

	// Collector metrics
	CollectorCollectsTotal = MetricDefinition{
		Name:   "openctem_collector_collects_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of collections executed",
		Labels: []string{"collector", "status"},
	}
	CollectorItemsTotal = MetricDefinition{
		Name:   "openctem_collector_items_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of items collected",
		Labels: []string{"collector"},
	}

	// Pusher metrics
	PusherPushesTotal = MetricDefinition{
		Name:   "openctem_pusher_pushes_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of push operations",
		Labels: []string{"status"},
	}
	PusherFindingsPushed = MetricDefinition{
		Name:   "openctem_pusher_findings_pushed_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of findings pushed",
		Labels: []string{},
	}
	PusherAssetsPushed = MetricDefinition{
		Name:   "openctem_pusher_assets_pushed_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of assets pushed",
		Labels: []string{},
	}
	PusherRetries = MetricDefinition{
		Name:   "openctem_pusher_retries_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of push retries",
		Labels: []string{},
	}

	// Agent metrics
	AgentJobsTotal = MetricDefinition{
		Name:   "openctem_agent_jobs_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of jobs processed",
		Labels: []string{"job_type", "status"},
	}
	AgentJobDuration = MetricDefinition{
		Name:    "openctem_agent_job_duration_seconds",
		Type:    MetricTypeHistogram,
		Help:    "Duration of job execution in seconds",
		Labels:  []string{"job_type"},
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}
	AgentQueueSize = MetricDefinition{
		Name:   "openctem_agent_queue_size",
		Type:   MetricTypeGauge,
		Help:   "Current number of jobs in queue",
		Labels: []string{},
	}
	AgentActiveJobs = MetricDefinition{
		Name:   "openctem_agent_active_jobs",
		Type:   MetricTypeGauge,
		Help:   "Number of currently executing jobs",
		Labels: []string{},
	}
	AgentHeartbeats = MetricDefinition{
		Name:   "openctem_agent_heartbeats_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of heartbeats sent",
		Labels: []string{"status"},
	}

	// Enricher metrics
	EnricherEnrichmentsTotal = MetricDefinition{
		Name:   "openctem_enricher_enrichments_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of enrichment operations",
		Labels: []string{"enricher", "status"},
	}
	EnricherCacheHits = MetricDefinition{
		Name:   "openctem_enricher_cache_hits_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of cache hits",
		Labels: []string{"enricher"},
	}
	EnricherCacheMisses = MetricDefinition{
		Name:   "openctem_enricher_cache_misses_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of cache misses",
		Labels: []string{"enricher"},
	}

	// HTTP client metrics
	HTTPRequestsTotal = MetricDefinition{
		Name:   "openctem_http_requests_total",
		Type:   MetricTypeCounter,
		Help:   "Total number of HTTP requests made",
		Labels: []string{"method", "host", "status"},
	}
	HTTPRequestDuration = MetricDefinition{
		Name:    "openctem_http_request_duration_seconds",
		Type:    MetricTypeHistogram,
		Help:    "Duration of HTTP requests in seconds",
		Labels:  []string{"method", "host"},
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}
)

// =============================================================================
// NopCollector - No-operation implementation
// =============================================================================

// NopCollector is a no-op metrics collector that discards all metrics.
// Use this when metrics are not needed.
type NopCollector struct{}

func (c *NopCollector) CounterInc(name string, labels ...string)                      {}
func (c *NopCollector) CounterAdd(name string, value float64, labels ...string)       {}
func (c *NopCollector) GaugeSet(name string, value float64, labels ...string)         {}
func (c *NopCollector) GaugeInc(name string, labels ...string)                        {}
func (c *NopCollector) GaugeDec(name string, labels ...string)                        {}
func (c *NopCollector) HistogramObserve(name string, value float64, labels ...string) {}
func (c *NopCollector) SummaryObserve(name string, value float64, labels ...string)   {}
func (c *NopCollector) Handler() http.Handler                                         { return http.NotFoundHandler() }
func (c *NopCollector) Reset()                                                        {}

// =============================================================================
// InMemoryCollector - Simple in-memory implementation for testing
// =============================================================================

// InMemoryCollector stores metrics in memory for testing purposes.
type InMemoryCollector struct {
	mu         sync.RWMutex
	counters   map[string]float64
	gauges     map[string]float64
	histograms map[string][]float64
	summaries  map[string][]float64
}

// NewInMemoryCollector creates a new in-memory metrics collector.
func NewInMemoryCollector() *InMemoryCollector {
	return &InMemoryCollector{
		counters:   make(map[string]float64),
		gauges:     make(map[string]float64),
		histograms: make(map[string][]float64),
		summaries:  make(map[string][]float64),
	}
}

func (c *InMemoryCollector) key(name string, labels []string) string {
	key := name
	for i := 0; i < len(labels); i += 2 {
		if i+1 < len(labels) {
			key += "," + labels[i] + "=" + labels[i+1]
		}
	}
	return key
}

func (c *InMemoryCollector) CounterInc(name string, labels ...string) {
	c.CounterAdd(name, 1, labels...)
}

func (c *InMemoryCollector) CounterAdd(name string, value float64, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.key(name, labels)
	c.counters[key] += value
}

func (c *InMemoryCollector) GaugeSet(name string, value float64, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.key(name, labels)
	c.gauges[key] = value
}

func (c *InMemoryCollector) GaugeInc(name string, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.key(name, labels)
	c.gauges[key]++
}

func (c *InMemoryCollector) GaugeDec(name string, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.key(name, labels)
	c.gauges[key]--
}

func (c *InMemoryCollector) HistogramObserve(name string, value float64, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.key(name, labels)
	c.histograms[key] = append(c.histograms[key], value)
}

func (c *InMemoryCollector) SummaryObserve(name string, value float64, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.key(name, labels)
	c.summaries[key] = append(c.summaries[key], value)
}

func (c *InMemoryCollector) Handler() http.Handler {
	return http.NotFoundHandler()
}

func (c *InMemoryCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counters = make(map[string]float64)
	c.gauges = make(map[string]float64)
	c.histograms = make(map[string][]float64)
	c.summaries = make(map[string][]float64)
}

// GetCounter returns the value of a counter.
func (c *InMemoryCollector) GetCounter(name string, labels ...string) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counters[c.key(name, labels)]
}

// GetGauge returns the value of a gauge.
func (c *InMemoryCollector) GetGauge(name string, labels ...string) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gauges[c.key(name, labels)]
}

// GetHistogram returns all observations of a histogram.
func (c *InMemoryCollector) GetHistogram(name string, labels ...string) []float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.histograms[c.key(name, labels)]
}

// GetSummary returns all observations of a summary.
func (c *InMemoryCollector) GetSummary(name string, labels ...string) []float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.summaries[c.key(name, labels)]
}

// =============================================================================
// Timer - Helper for timing operations
// =============================================================================

// Timer is a helper for timing operations and recording to histograms.
type Timer struct {
	start     time.Time
	collector Collector
	name      string
	labels    []string
}

// NewTimer creates a new timer that will record to the given histogram.
func NewTimer(collector Collector, name string, labels ...string) *Timer {
	return &Timer{
		start:     time.Now(),
		collector: collector,
		name:      name,
		labels:    labels,
	}
}

// ObserveDuration records the duration since the timer was created.
func (t *Timer) ObserveDuration() time.Duration {
	d := time.Since(t.start)
	t.collector.HistogramObserve(t.name, d.Seconds(), t.labels...)
	return d
}

// =============================================================================
// Global Default Collector
// =============================================================================

var defaultCollector Collector = &NopCollector{}
var defaultCollectorMu sync.RWMutex

// SetDefaultCollector sets the global default metrics collector.
func SetDefaultCollector(collector Collector) {
	defaultCollectorMu.Lock()
	defer defaultCollectorMu.Unlock()
	if collector == nil {
		collector = &NopCollector{}
	}
	defaultCollector = collector
}

// GetDefaultCollector returns the global default metrics collector.
func GetDefaultCollector() Collector {
	defaultCollectorMu.RLock()
	defer defaultCollectorMu.RUnlock()
	return defaultCollector
}

// =============================================================================
// Context-based Collector
// =============================================================================

type contextKey string

const collectorContextKey contextKey = "openctem_metrics_collector"

// WithCollector returns a new context with the collector attached.
func WithCollector(ctx context.Context, collector Collector) context.Context {
	return context.WithValue(ctx, collectorContextKey, collector)
}

// CollectorFromContext returns the collector from the context, or the default.
func CollectorFromContext(ctx context.Context) Collector {
	if collector, ok := ctx.Value(collectorContextKey).(Collector); ok {
		return collector
	}
	return GetDefaultCollector()
}

// =============================================================================
// Interface compliance
// =============================================================================

var (
	_ Collector = (*NopCollector)(nil)
	_ Collector = (*InMemoryCollector)(nil)
)
