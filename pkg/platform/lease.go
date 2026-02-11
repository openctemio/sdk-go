package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// LeaseClient defines the interface for lease operations.
type LeaseClient interface {
	RenewLease(ctx context.Context, req *LeaseRenewRequest) (*LeaseRenewResponse, error)
	ReleaseLease(ctx context.Context) error
}

// LeaseRenewRequest contains the data for renewing a lease.
type LeaseRenewRequest struct {
	HolderIdentity       string   `json:"holder_identity"`
	LeaseDurationSeconds int      `json:"lease_duration_seconds"`
	CurrentJobs          int      `json:"current_jobs"`
	MaxJobs              int      `json:"max_jobs"`
	CPUPercent           *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent        *float64 `json:"memory_percent,omitempty"`
	DiskPercent          *float64 `json:"disk_percent,omitempty"`
	JobsCompletedTotal   int      `json:"jobs_completed_total,omitempty"`
	JobsFailedTotal      int      `json:"jobs_failed_total,omitempty"`
}

// LeaseRenewResponse contains the response from lease renewal.
type LeaseRenewResponse struct {
	Success         bool      `json:"success"`
	Message         string    `json:"message,omitempty"`
	ResourceVersion int       `json:"resource_version"`
	RenewTime       time.Time `json:"renew_time"`
}

// LeaseConfig configures the LeaseManager.
type LeaseConfig struct {
	// LeaseDuration is how long the lease is valid for.
	// Default: 60 seconds.
	LeaseDuration time.Duration

	// RenewInterval is how often to renew the lease.
	// Should be less than LeaseDuration (typically 1/3).
	// Default: 20 seconds.
	RenewInterval time.Duration

	// GracePeriod is how long to wait after lease expiry before considering agent dead.
	// Default: 15 seconds.
	GracePeriod time.Duration

	// MaxJobs is the maximum concurrent jobs this agent can handle.
	MaxJobs int

	// MetricsCollector provides system metrics for lease renewal.
	// If nil, metrics are not reported.
	MetricsCollector MetricsCollector

	// OnLeaseExpired is called when the lease expires (agent should shutdown).
	OnLeaseExpired func()

	// Verbose enables debug logging.
	Verbose bool

	// UseSecureIdentity enables cryptographically secure holder identity.
	// When true, the holder identity includes a random nonce that cannot be guessed.
	// Default: true (should only be false for testing).
	UseSecureIdentity *bool

	// IdentityPrefix is an optional prefix for the holder identity.
	// Useful for identifying agent type (e.g., "scanner", "collector").
	IdentityPrefix string
}

// identityNonceLength is the length of the random nonce in bytes.
const identityNonceLength = 16

// MetricsCollector collects system metrics.
type MetricsCollector interface {
	Collect() (*SystemMetrics, error)
}

// LeaseManager manages the agent's lease with the control plane.
// It periodically renews the lease to indicate the agent is healthy.
type LeaseManager struct {
	client          LeaseClient
	config          *LeaseConfig
	holderIdentity  string
	currentJobs     int
	jobsCompleted   int
	jobsFailed      int
	resourceVersion int
	lastRenewTime   time.Time
	lastError       error
	mu              sync.RWMutex
	running         bool
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewLeaseManager creates a new LeaseManager.
func NewLeaseManager(client LeaseClient, config *LeaseConfig) *LeaseManager {
	if config == nil {
		config = &LeaseConfig{}
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = DefaultLeaseDuration
	}
	if config.RenewInterval == 0 {
		config.RenewInterval = DefaultRenewInterval
	}
	if config.GracePeriod == 0 {
		config.GracePeriod = 15 * time.Second
	}
	if config.MaxJobs == 0 {
		config.MaxJobs = DefaultMaxConcurrentJobs
	}

	// Generate holder identity
	holderIdentity := generateHolderIdentity(config)

	return &LeaseManager{
		client:         client,
		config:         config,
		holderIdentity: holderIdentity,
		stopCh:         make(chan struct{}),
	}
}

// generateHolderIdentity creates a cryptographically secure holder identity.
// SECURITY: The identity includes a random nonce to prevent lease hijacking.
// Format: prefix-hostname-pid-nonce or prefix-hostname-pid (if secure identity disabled)
func generateHolderIdentity(config *LeaseConfig) string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Build base identity
	prefix := config.IdentityPrefix
	if prefix == "" {
		prefix = "agent"
	}

	baseIdentity := fmt.Sprintf("%s-%s-%d", prefix, hostname, os.Getpid())

	// Check if secure identity is enabled (default: true)
	useSecure := true
	if config.UseSecureIdentity != nil {
		useSecure = *config.UseSecureIdentity
	}

	if !useSecure {
		return baseIdentity
	}

	// Generate cryptographically secure nonce
	nonce := make([]byte, identityNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		// Fallback to time-based nonce if crypto/rand fails (very unlikely)
		// This is still better than no nonce at all
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", baseIdentity, time.Now().UnixNano(), os.Getpid())))
		nonce = h[:identityNonceLength]
	}

	// Create identity with nonce
	return fmt.Sprintf("%s-%s", baseIdentity, hex.EncodeToString(nonce))
}

// Start starts the lease renewal loop.
func (m *LeaseManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("lease manager already running")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[lease] Starting lease manager (duration=%v, interval=%v)\n",
			m.config.LeaseDuration, m.config.RenewInterval)
	}

	// Renew immediately on start
	if err := m.renew(ctx); err != nil {
		if m.config.Verbose {
			fmt.Printf("[lease] Initial renewal failed: %v\n", err)
		}
		// Don't fail start - continue trying
	}

	m.wg.Add(1)
	go m.renewLoop(ctx)

	return nil
}

// Stop stops the lease manager and releases the lease.
func (m *LeaseManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	// Wait for renewal loop to stop
	m.wg.Wait()

	// Release the lease
	if err := m.client.ReleaseLease(ctx); err != nil {
		if m.config.Verbose {
			fmt.Printf("[lease] Failed to release lease: %v\n", err)
		}
		return err
	}

	if m.config.Verbose {
		fmt.Printf("[lease] Lease released\n")
	}

	return nil
}

// SetCurrentJobs updates the current number of jobs being processed.
func (m *LeaseManager) SetCurrentJobs(count int) {
	m.mu.Lock()
	m.currentJobs = count
	m.mu.Unlock()
}

// IncrementJobs increments the current job count by 1.
func (m *LeaseManager) IncrementJobs() {
	m.mu.Lock()
	m.currentJobs++
	m.mu.Unlock()
}

// DecrementJobs decrements the current job count by 1 and increments completed.
func (m *LeaseManager) DecrementJobs(failed bool) {
	m.mu.Lock()
	if m.currentJobs > 0 {
		m.currentJobs--
	}
	if failed {
		m.jobsFailed++
	} else {
		m.jobsCompleted++
	}
	m.mu.Unlock()
}

// GetStatus returns the current lease status.
func (m *LeaseManager) GetStatus() *LeaseStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	timeSinceRenew := time.Since(m.lastRenewTime)
	healthy := timeSinceRenew < m.config.LeaseDuration+m.config.GracePeriod

	return &LeaseStatus{
		Running:         m.running,
		Healthy:         healthy,
		LastRenewTime:   m.lastRenewTime,
		ResourceVersion: m.resourceVersion,
		CurrentJobs:     m.currentJobs,
		LastError:       m.lastError,
	}
}

// LeaseStatus represents the current status of the lease.
type LeaseStatus struct {
	Running         bool
	Healthy         bool
	LastRenewTime   time.Time
	ResourceVersion int
	CurrentJobs     int
	LastError       error
}

// renewLoop is the background renewal loop.
func (m *LeaseManager) renewLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.RenewInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	maxConsecutiveFailures := 3

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.renew(ctx); err != nil {
				consecutiveFailures++
				if m.config.Verbose {
					fmt.Printf("[lease] Renewal failed (%d/%d): %v\n",
						consecutiveFailures, maxConsecutiveFailures, err)
				}

				// Check if lease has expired
				m.mu.RLock()
				timeSinceRenew := time.Since(m.lastRenewTime)
				expired := timeSinceRenew > m.config.LeaseDuration+m.config.GracePeriod
				m.mu.RUnlock()

				if expired && m.config.OnLeaseExpired != nil {
					if m.config.Verbose {
						fmt.Printf("[lease] Lease expired! Triggering callback\n")
					}
					m.config.OnLeaseExpired()
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

// renew performs a single lease renewal.
func (m *LeaseManager) renew(ctx context.Context) error {
	m.mu.RLock()
	req := &LeaseRenewRequest{
		HolderIdentity:       m.holderIdentity,
		LeaseDurationSeconds: int(m.config.LeaseDuration.Seconds()),
		CurrentJobs:          m.currentJobs,
		MaxJobs:              m.config.MaxJobs,
		JobsCompletedTotal:   m.jobsCompleted,
		JobsFailedTotal:      m.jobsFailed,
	}
	m.mu.RUnlock()

	// Collect metrics if available
	if m.config.MetricsCollector != nil {
		metrics, err := m.config.MetricsCollector.Collect()
		if err == nil {
			req.CPUPercent = &metrics.CPUPercent
			req.MemoryPercent = &metrics.MemoryPercent
			req.DiskPercent = &metrics.DiskPercent
		}
	}

	resp, err := m.client.RenewLease(ctx, req)
	if err != nil {
		m.mu.Lock()
		m.lastError = err
		m.mu.Unlock()
		return err
	}

	if !resp.Success {
		err := fmt.Errorf("lease renewal rejected: %s", resp.Message)
		m.mu.Lock()
		m.lastError = err
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	m.lastRenewTime = resp.RenewTime
	m.resourceVersion = resp.ResourceVersion
	m.lastError = nil
	m.mu.Unlock()

	if m.config.Verbose {
		fmt.Printf("[lease] Renewed (version=%d)\n", resp.ResourceVersion)
	}

	return nil
}

// =============================================================================
// Default Metrics Collector
// =============================================================================

// SimpleMetricsCollector provides basic system metrics collection.
type SimpleMetricsCollector struct{}

// Collect collects system metrics.
// This is a simplified implementation - production should use proper system calls.
func (c *SimpleMetricsCollector) Collect() (*SystemMetrics, error) {
	// In production, use runtime.NumCPU(), runtime.MemStats, etc.
	// For now, return placeholder values
	return &SystemMetrics{
		CPUPercent:    0,
		MemoryPercent: 0,
		DiskPercent:   0,
	}, nil
}

// =============================================================================
// HTTP Client Implementation
// =============================================================================

// httpLeaseClient implements LeaseClient using HTTP.
type httpLeaseClient struct {
	baseURL    string
	apiKey     string
	agentID    string
	httpClient *http.Client
}

// NewHTTPLeaseClient creates a new HTTP-based lease client.
func NewHTTPLeaseClient(baseURL, apiKey, agentID string) LeaseClient {
	return &httpLeaseClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		agentID: agentID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *httpLeaseClient) RenewLease(ctx context.Context, req *LeaseRenewRequest) (*LeaseRenewResponse, error) {
	url := fmt.Sprintf("%s/api/v1/platform/lease", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result LeaseRenewResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c *httpLeaseClient) ReleaseLease(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/platform/lease", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}
