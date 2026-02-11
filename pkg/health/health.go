// Package health provides health check endpoints for the OpenCTEM SDK.
// It supports Kubernetes-style readiness and liveness probes, and
// allows registering custom health checks for dependencies.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// =============================================================================
// Health Check Interface
// =============================================================================

// Checker is the interface for health checks.
type Checker interface {
	// Name returns the check name.
	Name() string

	// Check performs the health check.
	Check(ctx context.Context) CheckResult
}

// CheckFunc is a function type that implements Checker.
type CheckFunc func(ctx context.Context) CheckResult

func (f CheckFunc) Name() string                          { return "" }
func (f CheckFunc) Check(ctx context.Context) CheckResult { return f(ctx) }

// =============================================================================
// Health Status Types
// =============================================================================

// Status represents the health status.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// CheckResult holds the result of a health check.
type CheckResult struct {
	// Status is the health status.
	Status Status `json:"status"`

	// Message provides additional details.
	Message string `json:"message,omitempty"`

	// Duration is how long the check took.
	Duration time.Duration `json:"duration_ms"`

	// Timestamp is when the check was performed.
	Timestamp time.Time `json:"timestamp"`

	// Error is the error if the check failed.
	Error string `json:"error,omitempty"`

	// Metadata holds additional check-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Response is the full health check response.
type Response struct {
	// Status is the overall health status.
	Status Status `json:"status"`

	// Timestamp is when the health check was performed.
	Timestamp time.Time `json:"timestamp"`

	// Checks contains individual check results.
	Checks map[string]CheckResult `json:"checks,omitempty"`

	// Version is the application version.
	Version string `json:"version,omitempty"`

	// Uptime is how long the application has been running.
	Uptime time.Duration `json:"uptime_seconds,omitempty"`
}

// =============================================================================
// Health Handler
// =============================================================================

// Handler manages health checks and provides HTTP endpoints.
type Handler struct {
	mu sync.RWMutex

	// Registered health checks
	checks map[string]Checker

	// Configuration
	version   string
	startTime time.Time
	timeout   time.Duration

	// Security options
	hideVersion bool // Don't expose version in response
	hideUptime  bool // Don't expose uptime in response
	hideDetails bool // Don't expose check details in response

	// Readiness state
	ready bool
}

// HandlerOption configures the health handler.
type HandlerOption func(*Handler)

// WithVersion sets the application version.
func WithVersion(version string) HandlerOption {
	return func(h *Handler) {
		h.version = version
	}
}

// WithTimeout sets the check timeout.
func WithTimeout(timeout time.Duration) HandlerOption {
	return func(h *Handler) {
		h.timeout = timeout
	}
}

// WithHideVersion hides the version from health responses.
// Recommended for production to prevent information disclosure.
func WithHideVersion() HandlerOption {
	return func(h *Handler) {
		h.hideVersion = true
	}
}

// WithHideUptime hides the uptime from health responses.
// Recommended for production to prevent timing attacks.
func WithHideUptime() HandlerOption {
	return func(h *Handler) {
		h.hideUptime = true
	}
}

// WithHideDetails hides check details from health responses.
// Only shows overall status without individual check results.
func WithHideDetails() HandlerOption {
	return func(h *Handler) {
		h.hideDetails = true
	}
}

// WithSecureDefaults applies all security-recommended options.
// This hides version, uptime, and detailed check results.
func WithSecureDefaults() HandlerOption {
	return func(h *Handler) {
		h.hideVersion = true
		h.hideUptime = true
		h.hideDetails = true
	}
}

// NewHandler creates a new health handler.
func NewHandler(opts ...HandlerOption) *Handler {
	h := &Handler{
		checks:    make(map[string]Checker),
		startTime: time.Now(),
		timeout:   5 * time.Second,
		ready:     true,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// Register adds a health check.
func (h *Handler) Register(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = checker
}

// RegisterFunc adds a health check function.
func (h *Handler) RegisterFunc(name string, fn func(ctx context.Context) CheckResult) {
	h.Register(name, CheckFunc(fn))
}

// Unregister removes a health check.
func (h *Handler) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checks, name)
}

// SetReady sets the readiness state.
func (h *Handler) SetReady(ready bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = ready
}

// IsReady returns the readiness state.
func (h *Handler) IsReady() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ready
}

// =============================================================================
// Check Execution
// =============================================================================

// Check runs all registered health checks.
func (h *Handler) Check(ctx context.Context) Response {
	h.mu.RLock()
	checks := make(map[string]Checker, len(h.checks))
	for name, checker := range h.checks {
		checks[name] = checker
	}
	h.mu.RUnlock()

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Run all checks concurrently
	results := make(map[string]CheckResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checks {
		wg.Add(1)
		go func(name string, checker Checker) {
			defer wg.Done()

			start := time.Now()
			result := checker.Check(ctx)
			result.Duration = time.Since(start)
			result.Timestamp = time.Now()

			mu.Lock()
			results[name] = result
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()

	// Calculate overall status
	overallStatus := StatusHealthy
	for _, result := range results {
		switch result.Status {
		case StatusUnhealthy:
			overallStatus = StatusUnhealthy
		case StatusDegraded:
			if overallStatus != StatusUnhealthy {
				overallStatus = StatusDegraded
			}
		}
	}

	response := Response{
		Status:    overallStatus,
		Timestamp: time.Now(),
	}

	// Apply security options
	if !h.hideDetails {
		response.Checks = results
	}
	if !h.hideVersion && h.version != "" {
		response.Version = h.version
	}
	if !h.hideUptime {
		response.Uptime = time.Since(h.startTime)
	}

	return response
}

// =============================================================================
// HTTP Handlers
// =============================================================================

// LivenessHandler returns an HTTP handler for liveness probes.
// Kubernetes uses this to determine if the container should be restarted.
func (h *Handler) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Liveness is always OK if we can serve this response
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    StatusHealthy,
			"timestamp": time.Now(),
		})
	})
}

// ReadinessHandler returns an HTTP handler for readiness probes.
// Kubernetes uses this to determine if the pod should receive traffic.
func (h *Handler) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !h.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":    StatusUnhealthy,
				"message":   "service not ready",
				"timestamp": time.Now(),
			})
			return
		}

		// Run health checks
		response := h.Check(r.Context())

		if response.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		_ = json.NewEncoder(w).Encode(response)
	})
}

// HealthHandler returns an HTTP handler for full health checks.
// Returns detailed information about all checks.
func (h *Handler) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		response := h.Check(r.Context())

		switch response.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still serving traffic
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}

		_ = json.NewEncoder(w).Encode(response)
	})
}

// =============================================================================
// Built-in Health Checks
// =============================================================================

// PingCheck is a simple check that always succeeds.
type PingCheck struct{}

func (c *PingCheck) Name() string { return "ping" }
func (c *PingCheck) Check(ctx context.Context) CheckResult {
	return CheckResult{
		Status:    StatusHealthy,
		Message:   "pong",
		Timestamp: time.Now(),
	}
}

// HTTPCheck checks if an HTTP endpoint is reachable.
type HTTPCheck struct {
	URL     string
	Timeout time.Duration
	Client  *http.Client
}

func (c *HTTPCheck) Name() string { return "http" }
func (c *HTTPCheck) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{Timestamp: time.Now()}

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = err.Error()
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Status = StatusHealthy
		result.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
	}

	return result
}

// DatabaseCheck checks if a database connection is working.
// Uses a simple ping function to test connectivity.
type DatabaseCheck struct {
	PingFunc func(ctx context.Context) error
}

func (c *DatabaseCheck) Name() string { return "database" }
func (c *DatabaseCheck) Check(ctx context.Context) CheckResult {
	result := CheckResult{Timestamp: time.Now()}

	if c.PingFunc == nil {
		result.Status = StatusUnknown
		result.Message = "no ping function configured"
		return result
	}

	start := time.Now()
	err := c.PingFunc(ctx)
	result.Duration = time.Since(start)

	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = err.Error()
	} else {
		result.Status = StatusHealthy
		result.Message = "connected"
	}

	return result
}

// DiskCheck checks available disk space.
type DiskCheck struct {
	Path         string
	MinFreeBytes int64
	// MinFreePercent is the minimum percentage of free space required (0-100).
	// If set, this takes precedence over MinFreeBytes.
	MinFreePercent float64
}

func (c *DiskCheck) Name() string { return "disk" }
func (c *DiskCheck) Check(ctx context.Context) CheckResult {
	result := CheckResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}

	path := c.Path
	if path == "" {
		path = "/"
	}

	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("failed to get disk stats: %v", err)
		return result
	}

	// Calculate disk usage
	// Bsize is always positive on supported platforms (Linux/Unix)
	totalBytes := stat.Blocks * uint64(stat.Bsize) //nolint:gosec // G115: safe conversion
	freeBytes := stat.Bavail * uint64(stat.Bsize)  //nolint:gosec // G115: safe conversion
	usedBytes := totalBytes - freeBytes
	freePercent := float64(freeBytes) / float64(totalBytes) * 100

	result.Metadata["total_bytes"] = totalBytes
	result.Metadata["free_bytes"] = freeBytes
	result.Metadata["used_bytes"] = usedBytes
	result.Metadata["free_percent"] = fmt.Sprintf("%.2f%%", freePercent)
	result.Metadata["path"] = path

	// Check thresholds
	if c.MinFreePercent > 0 {
		if freePercent < c.MinFreePercent {
			result.Status = StatusUnhealthy
			result.Error = fmt.Sprintf("disk free space %.2f%% is below threshold %.2f%%", freePercent, c.MinFreePercent)
			return result
		}
	} else if c.MinFreeBytes > 0 {
		// Safe comparison: convert threshold to uint64 instead of converting freeBytes to int64
		if freeBytes < uint64(c.MinFreeBytes) { //nolint:gosec // MinFreeBytes is always positive here
			result.Status = StatusUnhealthy
			result.Error = fmt.Sprintf("disk free space %d bytes is below threshold %d bytes", freeBytes, c.MinFreeBytes)
			return result
		}
	}

	result.Status = StatusHealthy
	result.Message = fmt.Sprintf("disk has %.2f%% free space", freePercent)
	return result
}

// MemoryCheck checks Go runtime memory usage.
// For system-wide memory, use SystemMemoryCheck.
type MemoryCheck struct {
	// MaxHeapBytes is the maximum heap size in bytes.
	MaxHeapBytes uint64
	// MaxHeapPercent is not applicable for Go runtime (use MaxHeapBytes).
	MaxUsagePercent float64
}

func (c *MemoryCheck) Name() string { return "memory" }
func (c *MemoryCheck) Check(ctx context.Context) CheckResult {
	result := CheckResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	result.Metadata["heap_alloc_bytes"] = m.HeapAlloc
	result.Metadata["heap_sys_bytes"] = m.HeapSys
	result.Metadata["heap_inuse_bytes"] = m.HeapInuse
	result.Metadata["stack_inuse_bytes"] = m.StackInuse
	result.Metadata["num_gc"] = m.NumGC
	result.Metadata["goroutines"] = runtime.NumGoroutine()

	// Check heap threshold
	if c.MaxHeapBytes > 0 && m.HeapAlloc > c.MaxHeapBytes {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("heap usage %d bytes exceeds threshold %d bytes", m.HeapAlloc, c.MaxHeapBytes)
		return result
	}

	result.Status = StatusHealthy
	result.Message = fmt.Sprintf("heap: %d MB, goroutines: %d", m.HeapAlloc/1024/1024, runtime.NumGoroutine())
	return result
}

// SystemMemoryCheck is defined in sysinfo_linux.go and sysinfo_other.go
// for platform-specific implementations.

// =============================================================================
// Global Default Handler
// =============================================================================

var defaultHandler *Handler
var defaultHandlerOnce sync.Once

// Default returns the global default health handler.
func Default() *Handler {
	defaultHandlerOnce.Do(func() {
		defaultHandler = NewHandler()
		defaultHandler.Register("ping", &PingCheck{})
	})
	return defaultHandler
}

// Register adds a health check to the default handler.
func Register(name string, checker Checker) {
	Default().Register(name, checker)
}

// RegisterFunc adds a health check function to the default handler.
func RegisterFunc(name string, fn func(ctx context.Context) CheckResult) {
	Default().RegisterFunc(name, fn)
}

// SetReady sets the readiness state on the default handler.
func SetReady(ready bool) {
	Default().SetReady(ready)
}

// =============================================================================
// HTTP Server Helper
// =============================================================================

// ServerConfig configures the health check server.
type ServerConfig struct {
	// Address to listen on (default ":8080")
	Address string

	// Paths for health endpoints
	LivenessPath  string
	ReadinessPath string
	HealthPath    string

	// Handler to use (default = Default())
	Handler *Handler
}

// DefaultServerConfig returns the default server configuration.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Address:       ":8080",
		LivenessPath:  "/healthz",
		ReadinessPath: "/readyz",
		HealthPath:    "/health",
	}
}

// RegisterRoutes registers health check routes on an http.ServeMux.
func RegisterRoutes(mux *http.ServeMux, cfg *ServerConfig) {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}

	h := cfg.Handler
	if h == nil {
		h = Default()
	}

	if cfg.LivenessPath != "" {
		mux.Handle(cfg.LivenessPath, h.LivenessHandler())
	}
	if cfg.ReadinessPath != "" {
		mux.Handle(cfg.ReadinessPath, h.ReadinessHandler())
	}
	if cfg.HealthPath != "" {
		mux.Handle(cfg.HealthPath, h.HealthHandler())
	}
}

// =============================================================================
// Interface Compliance
// =============================================================================

var (
	_ Checker = (*PingCheck)(nil)
	_ Checker = (*HTTPCheck)(nil)
	_ Checker = (*DatabaseCheck)(nil)
	_ Checker = (*DiskCheck)(nil)
	_ Checker = (*MemoryCheck)(nil)
	_ Checker = (*SystemMemoryCheck)(nil)
	_ Checker = CheckFunc(nil)
)
