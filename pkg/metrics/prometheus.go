// Package metrics provides Prometheus-compatible metrics collection.
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// =============================================================================
// Prometheus Collector
// =============================================================================

// PrometheusCollector implements the Collector interface using Prometheus.
type PrometheusCollector struct {
	mu sync.RWMutex

	// Prometheus registry
	registry *prometheus.Registry

	// Registered metrics
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec
	summaries  map[string]*prometheus.SummaryVec

	// Configuration
	namespace string
	subsystem string
}

// PrometheusConfig configures the Prometheus collector.
type PrometheusConfig struct {
	// Namespace prefixes all metric names (e.g., "openctem")
	Namespace string

	// Subsystem prefixes metric names after namespace (e.g., "agent")
	Subsystem string

	// Registry is the Prometheus registry to use (nil = new registry)
	Registry *prometheus.Registry

	// RegisterDefaultMetrics registers standard OpenCTEM SDK metrics
	RegisterDefaultMetrics bool
}

// NewPrometheusCollector creates a new Prometheus metrics collector.
func NewPrometheusCollector(cfg *PrometheusConfig) *PrometheusCollector {
	if cfg == nil {
		cfg = &PrometheusConfig{}
	}

	registry := cfg.Registry
	if registry == nil {
		registry = prometheus.NewRegistry()
		// Register standard Go metrics
		registry.MustRegister(collectors.NewGoCollector())
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	c := &PrometheusCollector{
		registry:   registry,
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		summaries:  make(map[string]*prometheus.SummaryVec),
		namespace:  cfg.Namespace,
		subsystem:  cfg.Subsystem,
	}

	if cfg.RegisterDefaultMetrics {
		c.registerDefaultMetrics()
	}

	return c
}

// registerDefaultMetrics registers the standard OpenCTEM SDK metrics.
func (c *PrometheusCollector) registerDefaultMetrics() {
	// Scanner metrics
	_ = c.RegisterCounter(ScannerScansTotal)
	_ = c.RegisterHistogram(ScannerScanDuration)
	_ = c.RegisterCounter(ScannerFindingsTotal)

	// Collector metrics
	_ = c.RegisterCounter(CollectorCollectsTotal)
	_ = c.RegisterCounter(CollectorItemsTotal)

	// Pusher metrics
	_ = c.RegisterCounter(PusherPushesTotal)
	_ = c.RegisterCounter(PusherFindingsPushed)
	_ = c.RegisterCounter(PusherAssetsPushed)
	_ = c.RegisterCounter(PusherRetries)

	// Agent metrics
	_ = c.RegisterCounter(AgentJobsTotal)
	_ = c.RegisterHistogram(AgentJobDuration)
	_ = c.RegisterGauge(AgentQueueSize)
	_ = c.RegisterGauge(AgentActiveJobs)
	_ = c.RegisterCounter(AgentHeartbeats)

	// Enricher metrics
	_ = c.RegisterCounter(EnricherEnrichmentsTotal)
	_ = c.RegisterCounter(EnricherCacheHits)
	_ = c.RegisterCounter(EnricherCacheMisses)

	// HTTP client metrics
	_ = c.RegisterCounter(HTTPRequestsTotal)
	_ = c.RegisterHistogram(HTTPRequestDuration)
}

// =============================================================================
// Registration Methods
// =============================================================================

// RegisterCounter registers a counter metric.
func (c *PrometheusCollector) RegisterCounter(def MetricDefinition) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.counters[def.Name]; exists {
		return nil // Already registered
	}

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Subsystem: c.subsystem,
			Name:      def.Name,
			Help:      def.Help,
		},
		def.Labels,
	)

	if err := c.registry.Register(counter); err != nil {
		return err
	}

	c.counters[def.Name] = counter
	return nil
}

// RegisterGauge registers a gauge metric.
func (c *PrometheusCollector) RegisterGauge(def MetricDefinition) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.gauges[def.Name]; exists {
		return nil // Already registered
	}

	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Subsystem: c.subsystem,
			Name:      def.Name,
			Help:      def.Help,
		},
		def.Labels,
	)

	if err := c.registry.Register(gauge); err != nil {
		return err
	}

	c.gauges[def.Name] = gauge
	return nil
}

// RegisterHistogram registers a histogram metric.
func (c *PrometheusCollector) RegisterHistogram(def MetricDefinition) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.histograms[def.Name]; exists {
		return nil // Already registered
	}

	buckets := def.Buckets
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}

	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: c.namespace,
			Subsystem: c.subsystem,
			Name:      def.Name,
			Help:      def.Help,
			Buckets:   buckets,
		},
		def.Labels,
	)

	if err := c.registry.Register(histogram); err != nil {
		return err
	}

	c.histograms[def.Name] = histogram
	return nil
}

// RegisterSummary registers a summary metric.
func (c *PrometheusCollector) RegisterSummary(def MetricDefinition) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.summaries[def.Name]; exists {
		return nil // Already registered
	}

	objectives := make(map[float64]float64)
	for _, q := range def.Objectives {
		objectives[q] = 0.001 // Default error margin
	}
	if len(objectives) == 0 {
		objectives = map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}
	}

	summary := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace:  c.namespace,
			Subsystem:  c.subsystem,
			Name:       def.Name,
			Help:       def.Help,
			Objectives: objectives,
		},
		def.Labels,
	)

	if err := c.registry.Register(summary); err != nil {
		return err
	}

	c.summaries[def.Name] = summary
	return nil
}

// =============================================================================
// Collector Interface Implementation
// =============================================================================

func (c *PrometheusCollector) CounterInc(name string, labels ...string) {
	c.CounterAdd(name, 1, labels...)
}

func (c *PrometheusCollector) CounterAdd(name string, value float64, labels ...string) {
	c.mu.RLock()
	counter, ok := c.counters[name]
	c.mu.RUnlock()

	if !ok {
		return // Metric not registered
	}

	labelValues := labelsToValues(labels)
	counter.WithLabelValues(labelValues...).Add(value)
}

func (c *PrometheusCollector) GaugeSet(name string, value float64, labels ...string) {
	c.mu.RLock()
	gauge, ok := c.gauges[name]
	c.mu.RUnlock()

	if !ok {
		return // Metric not registered
	}

	labelValues := labelsToValues(labels)
	gauge.WithLabelValues(labelValues...).Set(value)
}

func (c *PrometheusCollector) GaugeInc(name string, labels ...string) {
	c.mu.RLock()
	gauge, ok := c.gauges[name]
	c.mu.RUnlock()

	if !ok {
		return // Metric not registered
	}

	labelValues := labelsToValues(labels)
	gauge.WithLabelValues(labelValues...).Inc()
}

func (c *PrometheusCollector) GaugeDec(name string, labels ...string) {
	c.mu.RLock()
	gauge, ok := c.gauges[name]
	c.mu.RUnlock()

	if !ok {
		return // Metric not registered
	}

	labelValues := labelsToValues(labels)
	gauge.WithLabelValues(labelValues...).Dec()
}

func (c *PrometheusCollector) HistogramObserve(name string, value float64, labels ...string) {
	c.mu.RLock()
	histogram, ok := c.histograms[name]
	c.mu.RUnlock()

	if !ok {
		return // Metric not registered
	}

	labelValues := labelsToValues(labels)
	histogram.WithLabelValues(labelValues...).Observe(value)
}

func (c *PrometheusCollector) SummaryObserve(name string, value float64, labels ...string) {
	c.mu.RLock()
	summary, ok := c.summaries[name]
	c.mu.RUnlock()

	if !ok {
		return // Metric not registered
	}

	labelValues := labelsToValues(labels)
	summary.WithLabelValues(labelValues...).Observe(value)
}

func (c *PrometheusCollector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

func (c *PrometheusCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reset all counters
	for _, counter := range c.counters {
		counter.Reset()
	}

	// Gauges and histograms can't be reset in Prometheus
	// For a full reset, create a new collector
}

// Registry returns the underlying Prometheus registry.
func (c *PrometheusCollector) Registry() *prometheus.Registry {
	return c.registry
}

// =============================================================================
// Helper Functions
// =============================================================================

// labelsToValues converts label pairs to values only.
// Input: ["label1", "value1", "label2", "value2"]
// Output: ["value1", "value2"]
func labelsToValues(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}

	values := make([]string, 0, len(labels)/2)
	for i := 1; i < len(labels); i += 2 {
		values = append(values, labels[i])
	}
	return values
}

// =============================================================================
// Interface Compliance
// =============================================================================

var _ Collector = (*PrometheusCollector)(nil)
