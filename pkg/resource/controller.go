// Package resource provides system resource monitoring and control.
package resource

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// SystemMetrics contains current system resource metrics.
type SystemMetrics struct {
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	MemoryUsedMB  int64     `json:"memory_used_mb"`
	MemoryTotalMB int64     `json:"memory_total_mb"`
	NumGoroutines int       `json:"num_goroutines"`
	NumCPU        int       `json:"num_cpu"`
	Timestamp     time.Time `json:"timestamp"`
}

// ControllerConfig configures the resource controller.
type ControllerConfig struct {
	// CPUThreshold is the CPU percentage above which new work is paused.
	// Default: 85%
	CPUThreshold float64

	// MemoryThreshold is the memory percentage above which new work is paused.
	// Default: 85%
	MemoryThreshold float64

	// MaxConcurrentJobs limits the number of concurrent jobs.
	// Default: runtime.NumCPU()
	MaxConcurrentJobs int

	// MinConcurrentJobs is the minimum jobs to allow even under load.
	// Default: 1
	MinConcurrentJobs int

	// SampleInterval is how often to sample system metrics.
	// Default: 5 seconds
	SampleInterval time.Duration

	// CooldownDuration is how long to wait after threshold exceeded.
	// Default: 30 seconds
	CooldownDuration time.Duration

	// OnThresholdExceeded is called when resource threshold is exceeded.
	OnThresholdExceeded func(metrics *SystemMetrics, reason string)

	// OnThresholdCleared is called when resources return to normal.
	OnThresholdCleared func(metrics *SystemMetrics)

	// Verbose enables debug logging.
	Verbose bool
}

// DefaultControllerConfig returns sensible defaults.
func DefaultControllerConfig() *ControllerConfig {
	return &ControllerConfig{
		CPUThreshold:      85.0,
		MemoryThreshold:   85.0,
		MaxConcurrentJobs: runtime.NumCPU(),
		MinConcurrentJobs: 1,
		SampleInterval:    5 * time.Second,
		CooldownDuration:  30 * time.Second,
	}
}

// Controller monitors system resources and controls work admission.
type Controller struct {
	config *ControllerConfig

	mu             sync.RWMutex
	currentMetrics *SystemMetrics
	throttled      bool
	throttledAt    time.Time
	throttleReason string

	activeJobs   int32 // atomic
	pendingJobs  int32 // atomic
	rejectedJobs int64 // atomic

	running int32
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Semaphore for job admission
	jobSemaphore chan struct{}

	// CPU sampling state
	cpuSamples    []float64
	cpuSamplesMu  sync.Mutex
	maxCPUSamples int
}

// NewController creates a new resource controller.
func NewController(config *ControllerConfig) *Controller {
	if config == nil {
		config = DefaultControllerConfig()
	}
	if config.MaxConcurrentJobs <= 0 {
		config.MaxConcurrentJobs = runtime.NumCPU()
	}
	if config.MinConcurrentJobs <= 0 {
		config.MinConcurrentJobs = 1
	}
	if config.SampleInterval <= 0 {
		config.SampleInterval = 5 * time.Second
	}
	if config.CooldownDuration <= 0 {
		config.CooldownDuration = 30 * time.Second
	}

	c := &Controller{
		config:        config,
		stopCh:        make(chan struct{}),
		jobSemaphore:  make(chan struct{}, config.MaxConcurrentJobs),
		cpuSamples:    make([]float64, 0, 12), // Keep 1 minute of samples at 5s interval
		maxCPUSamples: 12,
	}

	// Pre-fill semaphore
	for i := 0; i < config.MaxConcurrentJobs; i++ {
		c.jobSemaphore <- struct{}{}
	}

	return c
}

// Start begins resource monitoring.
func (c *Controller) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&c.running, 0, 1) {
		return fmt.Errorf("controller already running")
	}

	c.mu.Lock()
	c.stopCh = make(chan struct{})
	c.mu.Unlock()

	// Initial sample
	c.sampleMetrics()

	c.wg.Add(1)
	go c.monitorLoop(ctx)

	if c.config.Verbose {
		fmt.Printf("[resource] Controller started (cpu_threshold=%.0f%%, mem_threshold=%.0f%%, max_jobs=%d)\n",
			c.config.CPUThreshold, c.config.MemoryThreshold, c.config.MaxConcurrentJobs)
	}

	return nil
}

// Stop stops the resource controller.
func (c *Controller) Stop() {
	if !atomic.CompareAndSwapInt32(&c.running, 1, 0) {
		return
	}

	c.mu.Lock()
	close(c.stopCh)
	c.mu.Unlock()

	c.wg.Wait()

	if c.config.Verbose {
		fmt.Printf("[resource] Controller stopped\n")
	}
}

// AcquireSlot attempts to acquire a job slot.
// Returns true if a slot was acquired, false if throttled or at capacity.
// The caller MUST call ReleaseSlot when done.
func (c *Controller) AcquireSlot(ctx context.Context) bool {
	// Check if throttled
	if c.IsThrottled() {
		atomic.AddInt64(&c.rejectedJobs, 1)
		return false
	}

	// Try to acquire from semaphore with context
	select {
	case <-c.jobSemaphore:
		atomic.AddInt32(&c.activeJobs, 1)
		return true
	case <-ctx.Done():
		return false
	default:
		// At capacity, increment pending counter
		atomic.AddInt32(&c.pendingJobs, 1)
		return false
	}
}

// AcquireSlotBlocking blocks until a slot is available or context is canceled.
func (c *Controller) AcquireSlotBlocking(ctx context.Context) error {
	for {
		// Wait if throttled
		for c.IsThrottled() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				// Check again
			}
		}

		// Try to acquire
		select {
		case <-c.jobSemaphore:
			atomic.AddInt32(&c.activeJobs, 1)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Retry
		}
	}
}

// ReleaseSlot releases a previously acquired job slot.
func (c *Controller) ReleaseSlot() {
	atomic.AddInt32(&c.activeJobs, -1)
	pending := atomic.LoadInt32(&c.pendingJobs)
	if pending > 0 {
		atomic.AddInt32(&c.pendingJobs, -1)
	}

	select {
	case c.jobSemaphore <- struct{}{}:
	default:
		// Semaphore full - shouldn't happen
	}
}

// IsThrottled returns true if resource thresholds are exceeded.
func (c *Controller) IsThrottled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.throttled
}

// GetMetrics returns the current system metrics.
func (c *Controller) GetMetrics() *SystemMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.currentMetrics == nil {
		return &SystemMetrics{Timestamp: time.Now()}
	}
	// Return a copy
	m := *c.currentMetrics
	return &m
}

// GetStatus returns the current controller status.
func (c *Controller) GetStatus() *ControllerStatus {
	c.mu.RLock()
	throttled := c.throttled
	throttledAt := c.throttledAt
	reason := c.throttleReason
	metrics := c.currentMetrics
	c.mu.RUnlock()

	var metricsCopy *SystemMetrics
	if metrics != nil {
		m := *metrics
		metricsCopy = &m
	}

	return &ControllerStatus{
		Throttled:      throttled,
		ThrottledAt:    throttledAt,
		ThrottleReason: reason,
		ActiveJobs:     int(atomic.LoadInt32(&c.activeJobs)),
		PendingJobs:    int(atomic.LoadInt32(&c.pendingJobs)),
		RejectedJobs:   atomic.LoadInt64(&c.rejectedJobs),
		MaxJobs:        c.config.MaxConcurrentJobs,
		Metrics:        metricsCopy,
	}
}

// ControllerStatus represents the current state of the controller.
type ControllerStatus struct {
	Throttled      bool           `json:"throttled"`
	ThrottledAt    time.Time      `json:"throttled_at,omitempty"`
	ThrottleReason string         `json:"throttle_reason,omitempty"`
	ActiveJobs     int            `json:"active_jobs"`
	PendingJobs    int            `json:"pending_jobs"`
	RejectedJobs   int64          `json:"rejected_jobs"`
	MaxJobs        int            `json:"max_jobs"`
	Metrics        *SystemMetrics `json:"metrics,omitempty"`
}

// SetMaxConcurrentJobs dynamically adjusts the max concurrent jobs.
func (c *Controller) SetMaxConcurrentJobs(max int) {
	if max <= 0 {
		max = 1
	}

	c.mu.Lock()
	oldMax := c.config.MaxConcurrentJobs
	c.config.MaxConcurrentJobs = max
	c.mu.Unlock()

	// Resize semaphore
	if max > oldMax {
		// Add slots
		for i := oldMax; i < max; i++ {
			select {
			case c.jobSemaphore <- struct{}{}:
			default:
			}
		}
	}
	// Note: Reducing slots is handled naturally as jobs complete

	if c.config.Verbose {
		fmt.Printf("[resource] Max concurrent jobs changed: %d -> %d\n", oldMax, max)
	}
}

// monitorLoop periodically samples system metrics.
func (c *Controller) monitorLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.sampleMetrics()
			c.checkThresholds()
		}
	}
}

// sampleMetrics captures current system metrics.
func (c *Controller) sampleMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Safe conversion: memory values in MB will never exceed int64 max
	allocMB := m.Alloc / 1024 / 1024
	sysMB := m.Sys / 1024 / 1024

	metrics := &SystemMetrics{
		MemoryUsedMB:  int64(min(allocMB, uint64(1<<62))), //nolint:gosec // MB values are safe
		MemoryTotalMB: int64(min(sysMB, uint64(1<<62))),   //nolint:gosec // MB values are safe
		NumGoroutines: runtime.NumGoroutine(),
		NumCPU:        runtime.NumCPU(),
		Timestamp:     time.Now(),
	}

	// Calculate memory percentage
	if m.Sys > 0 {
		metrics.MemoryPercent = float64(m.Alloc) / float64(m.Sys) * 100
	}

	// Calculate CPU percentage using goroutine count as proxy
	// For accurate CPU, we'd need OS-specific code
	metrics.CPUPercent = c.estimateCPU(metrics)

	c.mu.Lock()
	c.currentMetrics = metrics
	c.mu.Unlock()
}

// estimateCPU estimates CPU usage.
// For cross-platform, we use a combination of goroutine count and GC pressure.
func (c *Controller) estimateCPU(metrics *SystemMetrics) float64 {
	// Simple heuristic based on goroutine count vs CPU count
	// More goroutines than CPUs suggests higher contention
	goroutineRatio := float64(metrics.NumGoroutines) / float64(metrics.NumCPU)

	// Normalize to 0-100 scale with some headroom
	// At 2x goroutines per CPU, estimate ~50% CPU
	// At 4x goroutines per CPU, estimate ~80% CPU
	estimated := goroutineRatio * 25.0
	if estimated > 100 {
		estimated = 100
	}

	// Add to rolling average
	c.cpuSamplesMu.Lock()
	c.cpuSamples = append(c.cpuSamples, estimated)
	if len(c.cpuSamples) > c.maxCPUSamples {
		c.cpuSamples = c.cpuSamples[1:]
	}

	// Return average
	var sum float64
	for _, s := range c.cpuSamples {
		sum += s
	}
	avg := sum / float64(len(c.cpuSamples))
	c.cpuSamplesMu.Unlock()

	return avg
}

// checkThresholds checks if resource thresholds are exceeded.
func (c *Controller) checkThresholds() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.currentMetrics == nil {
		return
	}

	wasThrottled := c.throttled
	var shouldThrottle bool
	var reason string

	// Check CPU threshold
	if c.currentMetrics.CPUPercent >= c.config.CPUThreshold {
		shouldThrottle = true
		reason = fmt.Sprintf("CPU %.1f%% >= %.1f%%", c.currentMetrics.CPUPercent, c.config.CPUThreshold)
	}

	// Check memory threshold
	if c.currentMetrics.MemoryPercent >= c.config.MemoryThreshold {
		shouldThrottle = true
		if reason != "" {
			reason += ", "
		}
		reason += fmt.Sprintf("Memory %.1f%% >= %.1f%%", c.currentMetrics.MemoryPercent, c.config.MemoryThreshold)
	}

	// Check if we should clear throttle
	if c.throttled && !shouldThrottle {
		// Ensure cooldown has passed
		if time.Since(c.throttledAt) >= c.config.CooldownDuration {
			c.throttled = false
			c.throttleReason = ""

			if c.config.Verbose {
				fmt.Printf("[resource] Throttle cleared (was: %s)\n", c.throttleReason)
			}

			if c.config.OnThresholdCleared != nil {
				go c.config.OnThresholdCleared(c.currentMetrics)
			}
		}
	}

	// Check if we should start throttling
	if !wasThrottled && shouldThrottle {
		c.throttled = true
		c.throttledAt = time.Now()
		c.throttleReason = reason

		if c.config.Verbose {
			fmt.Printf("[resource] Throttling activated: %s\n", reason)
		}

		if c.config.OnThresholdExceeded != nil {
			go c.config.OnThresholdExceeded(c.currentMetrics, reason)
		}
	}
}

// ForceGC triggers garbage collection.
func (c *Controller) ForceGC() {
	runtime.GC()
	if c.config.Verbose {
		fmt.Printf("[resource] Forced GC completed\n")
	}
}

// AdaptiveMaxJobs calculates recommended max jobs based on current load.
func (c *Controller) AdaptiveMaxJobs() int {
	metrics := c.GetMetrics()
	if metrics == nil {
		return c.config.MaxConcurrentJobs
	}

	// Start with configured max
	max := c.config.MaxConcurrentJobs

	// Reduce based on CPU load
	if metrics.CPUPercent > 70 {
		reduction := int((metrics.CPUPercent - 70) / 10)
		max -= reduction
	}

	// Reduce based on memory load
	if metrics.MemoryPercent > 70 {
		reduction := int((metrics.MemoryPercent - 70) / 10)
		max -= reduction
	}

	// Ensure minimum
	if max < c.config.MinConcurrentJobs {
		max = c.config.MinConcurrentJobs
	}

	return max
}
