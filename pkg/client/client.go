// Package client provides the OpenCTEM API client.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/chunk"
	"github.com/openctemio/sdk-go/pkg/compress"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/retry"
)

// Client is the OpenCTEM API client.
// It implements the core.Pusher interface.
type Client struct {
	baseURL    string
	apiKey     string
	agentID    string // Agent ID for tracking which agent is pushing
	httpClient *http.Client
	maxRetries int
	retryDelay time.Duration
	verbose    bool

	// Compression configuration
	compressor       *compress.Compressor
	compressionLevel compress.Level
	analyzer         *compress.Analyzer

	// Retry queue (optional)
	retryQueue  retry.RetryQueue
	retryWorker *retry.RetryWorker
	retryMu     sync.RWMutex
}

// Ensure Client implements core.Pusher
var _ core.Pusher = (*Client)(nil)

// Config holds client configuration.
type Config struct {
	BaseURL    string        `yaml:"base_url" json:"base_url"`
	APIKey     string        `yaml:"api_key" json:"api_key"`
	AgentID    string        `yaml:"agent_id" json:"agent_id"` // Registered agent ID for audit trail
	Timeout    time.Duration `yaml:"timeout" json:"timeout"`
	MaxRetries int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
	Verbose    bool          `yaml:"verbose" json:"verbose"`

	// Compression configuration
	EnableCompression bool   `yaml:"enable_compression" json:"enable_compression"` // Enable request compression (default: true)
	CompressionAlgo   string `yaml:"compression_algo" json:"compression_algo"`     // "zstd" or "gzip" (default: "zstd")
	CompressionLevel  int    `yaml:"compression_level" json:"compression_level"`   // 1-9 (default: 3)

	// Retry queue configuration (optional)
	EnableRetryQueue bool          `yaml:"enable_retry_queue" json:"enable_retry_queue"`
	RetryQueueDir    string        `yaml:"retry_queue_dir" json:"retry_queue_dir"`       // Default: ~/.openctem/retry-queue
	RetryInterval    time.Duration `yaml:"retry_interval" json:"retry_interval"`         // Default: 5m
	RetryMaxAttempts int           `yaml:"retry_max_attempts" json:"retry_max_attempts"` // Default: 10
	RetryTTL         time.Duration `yaml:"retry_ttl" json:"retry_ttl"`                   // Default: 7d (168h)
}

// DefaultConfig returns default client config.
func DefaultConfig() *Config {
	return &Config{
		Timeout:           30 * time.Second,
		MaxRetries:        3,
		RetryDelay:        2 * time.Second,
		EnableCompression: true,
		CompressionAlgo:   "zstd",
		CompressionLevel:  3,
	}
}

// New creates a new OpenCTEM API client.
func New(cfg *Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 2 * time.Second
	}

	// Initialize compression if enabled
	var compressor *compress.Compressor
	var analyzer *compress.Analyzer
	compressionLevel := compress.Level(cfg.CompressionLevel)
	if compressionLevel == 0 {
		compressionLevel = compress.LevelDefault
	}

	if cfg.EnableCompression {
		algo := compress.AlgorithmZSTD
		if cfg.CompressionAlgo == "gzip" {
			algo = compress.AlgorithmGzip
		}
		compressor = compress.NewCompressor(algo, compressionLevel)
		analyzer = compress.NewAnalyzer(nil)
	}

	return &Client{
		baseURL:          cfg.BaseURL,
		apiKey:           cfg.APIKey,
		agentID:          cfg.AgentID,
		maxRetries:       cfg.MaxRetries,
		retryDelay:       cfg.RetryDelay,
		// SSRF: BaseURL is operator-configured at SDK consumer site.
		// Using SafeHTTPClient ensures the dialer rejects RFC1918 /
		// link-local / CGNAT targets even when a custom scanner binds
		// the SDK to an attacker-influenced API endpoint.
		httpClient: httpsec.SafeHTTPClient(cfg.Timeout),
		verbose:          cfg.Verbose,
		compressor:       compressor,
		compressionLevel: compressionLevel,
		analyzer:         analyzer,
	}
}

// =============================================================================
// Functional Options Pattern (AWS SDK style)
// =============================================================================

// Option is a function that configures the client.
type Option func(*Client)

// NewWithOptions creates a new client using functional options.
// Example:
//
//	client := client.NewWithOptions(
//	    client.WithBaseURL("http://localhost:8080"),
//	    client.WithAPIKey("xxx"),
//	    client.WithAgentID("agent-1"),
//	    client.WithTimeout(30 * time.Second),
//	)
func NewWithOptions(opts ...Option) *Client {
	c := &Client{
		maxRetries: 3,
		retryDelay: 2 * time.Second,
		// SSRF: see the imperative constructor above for rationale.
		httpClient: httpsec.SafeHTTPClient(30 * time.Second),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithBaseURL sets the API base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithAgentID sets the agent ID for tracking which agent is pushing data.
func WithAgentID(id string) Option {
	return func(c *Client) {
		c.agentID = id
	}
}

// WithTimeout sets the HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithRetry sets retry configuration.
func WithRetry(maxRetries int, retryDelay time.Duration) Option {
	return func(c *Client) {
		c.maxRetries = maxRetries
		c.retryDelay = retryDelay
	}
}

// WithVerbose enables verbose logging.
func WithVerbose(v bool) Option {
	return func(c *Client) {
		c.verbose = v
	}
}

// WithCompression enables request compression with the specified algorithm.
// Supported algorithms: "zstd" (recommended), "gzip"
func WithCompression(algorithm string, level int) Option {
	return func(c *Client) {
		algo := compress.AlgorithmZSTD
		if algorithm == "gzip" {
			algo = compress.AlgorithmGzip
		}
		compressionLevel := compress.Level(level)
		if compressionLevel == 0 {
			compressionLevel = compress.LevelDefault
		}
		c.compressor = compress.NewCompressor(algo, compressionLevel)
		c.compressionLevel = compressionLevel
		c.analyzer = compress.NewAnalyzer(nil)
	}
}

// WithoutCompression disables request compression.
func WithoutCompression() Option {
	return func(c *Client) {
		c.compressor = nil
		c.analyzer = nil
	}
}

// IngestResponse is the response from ingest endpoints.
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	AssetsCreated   int      `json:"assets_created"`
	AssetsUpdated   int      `json:"assets_updated"`
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	Errors          []string `json:"errors,omitempty"`
}

// HeartbeatRequest is the heartbeat payload.
type HeartbeatRequest struct {
	Name       string          `json:"name,omitempty"`
	Status     core.AgentState `json:"status"`
	Version    string          `json:"version,omitempty"`
	Hostname   string          `json:"hostname,omitempty"`
	Message    string          `json:"message,omitempty"`
	Scanners   []string        `json:"scanners,omitempty"`
	Collectors []string        `json:"collectors,omitempty"`
	Uptime     int64           `json:"uptime_seconds,omitempty"`
	TotalScans int64           `json:"total_scans,omitempty"`
	Errors     int64           `json:"errors,omitempty"`

	// System Metrics
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float64 `json:"memory_percent,omitempty"`
	ActiveJobs    int     `json:"active_jobs,omitempty"`
	Region        string  `json:"region,omitempty"`
}

// PushFindings sends findings to OpenCTEM.
// If the push fails and a retry queue is configured, the report is queued for later retry.
func (c *Client) PushFindings(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	result, err := c.pushFindingsInternal(ctx, report)

	// If push failed and retry queue is enabled, queue for retry
	if err != nil && c.hasRetryQueue() {
		if queueErr := c.queueForRetry(ctx, report, retry.ItemTypeFindings, err); queueErr != nil {
			if c.verbose {
				fmt.Printf("[openctem] Failed to queue for retry: %v\n", queueErr)
			}
		} else if c.verbose {
			fmt.Printf("[openctem] Queued for retry due to: %v\n", err)
		}
	}

	return result, err
}

// pushFindingsInternal performs the actual push without retry queue logic.
func (c *Client) pushFindingsInternal(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	url := fmt.Sprintf("%s/api/v1/agent/ingest", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Pushing %d findings to %s\n", len(report.Findings), url)
	}

	// Send CTIS Report directly (API expects ctis.Report format)
	body, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp IngestResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Push completed: %d findings created, %d updated\n",
			resp.FindingsCreated, resp.FindingsUpdated)
	}

	success := len(resp.Errors) == 0
	message := ""
	if !success {
		message = fmt.Sprintf("%d errors occurred", len(resp.Errors))
	}

	return &core.PushResult{
		Success:         success,
		Message:         message,
		FindingsCreated: resp.FindingsCreated,
		FindingsUpdated: resp.FindingsUpdated,
		AssetsCreated:   resp.AssetsCreated,
		AssetsUpdated:   resp.AssetsUpdated,
	}, nil
}

// PushAssets sends assets to OpenCTEM.
// If the push fails and a retry queue is configured, the report is queued for later retry.
func (c *Client) PushAssets(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	result, err := c.pushAssetsInternal(ctx, report)

	// If push failed and retry queue is enabled, queue for retry
	if err != nil && c.hasRetryQueue() {
		if queueErr := c.queueForRetry(ctx, report, retry.ItemTypeAssets, err); queueErr != nil {
			if c.verbose {
				fmt.Printf("[openctem] Failed to queue assets for retry: %v\n", queueErr)
			}
		} else if c.verbose {
			fmt.Printf("[openctem] Queued assets for retry due to: %v\n", err)
		}
	}

	return result, err
}

// pushAssetsInternal performs the actual push without retry queue logic.
func (c *Client) pushAssetsInternal(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	url := fmt.Sprintf("%s/api/v1/agent/ingest", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Pushing %d assets to %s\n", len(report.Assets), url)
	}

	// Send CTIS Report directly with findings cleared (API expects ctis.Report format)
	assetOnlyReport := *report
	assetOnlyReport.Findings = nil

	body, err := json.Marshal(&assetOnlyReport)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp IngestResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	success := len(resp.Errors) == 0

	return &core.PushResult{
		Success:       success,
		AssetsCreated: resp.AssetsCreated,
		AssetsUpdated: resp.AssetsUpdated,
	}, nil
}

// SendHeartbeat sends a heartbeat to OpenCTEM.
func (c *Client) SendHeartbeat(ctx context.Context, status *core.AgentStatus) error {
	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", c.baseURL)

	req := HeartbeatRequest{
		Name:       status.Name,
		Status:     status.Status,
		Scanners:   status.Scanners,
		Collectors: status.Collectors,
		Uptime:     status.Uptime,
		TotalScans: status.TotalScans,
		Errors:     status.Errors,
		Message:    status.Message,
		// System metrics
		CPUPercent:    status.CPUPercent,
		MemoryPercent: status.MemoryPercent,
		ActiveJobs:    status.ActiveJobs,
		Region:        status.Region,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	if _, err := c.doRequest(ctx, "POST", url, body); err != nil {
		return err
	}

	if c.verbose {
		fmt.Printf("[openctem] Heartbeat sent: %s\n", status.Status)
	}

	return nil
}

// TestConnection tests the API connection.
func (c *Client) TestConnection(ctx context.Context) error {
	status := &core.AgentStatus{
		Name:    "connection-test",
		Status:  core.AgentStateRunning,
		Message: "connection test",
	}
	return c.SendHeartbeat(ctx, status)
}

// checkFingerprintsRequest is the internal request for checking fingerprint existence.
type checkFingerprintsRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// checkFingerprintsResponse is the internal response for fingerprint check.
type checkFingerprintsResponse struct {
	Existing []string `json:"existing"` // Fingerprints that already exist
	Missing  []string `json:"missing"`  // Fingerprints that don't exist
}

// CheckFingerprints checks which fingerprints already exist on the server.
// This is used by the retry mechanism to avoid re-uploading data that already exists.
// It also serves as a connectivity check before processing the retry queue.
// This method implements retry.FingerprintChecker interface.
func (c *Client) CheckFingerprints(ctx context.Context, fingerprints []string) (*retry.FingerprintCheckResult, error) {
	if len(fingerprints) == 0 {
		return &retry.FingerprintCheckResult{
			Existing: []string{},
			Missing:  []string{},
		}, nil
	}

	req := checkFingerprintsRequest{
		Fingerprints: fingerprints,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/api/v1/agent/ingest/check"
	respBody, err := c.doRequest(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("check fingerprints: %w", err)
	}

	var resp checkFingerprintsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Fingerprint check: %d existing, %d missing\n",
			len(resp.Existing), len(resp.Missing))
	}

	return &retry.FingerprintCheckResult{
		Existing: resp.Existing,
		Missing:  resp.Missing,
	}, nil
}

// doRequest performs an HTTP request with retry logic.
func (c *Client) doRequest(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: delay * 2^(attempt-1)
			backoff := c.retryDelay * time.Duration(1<<(attempt-1))
			if c.verbose {
				fmt.Printf("[openctem] Retrying request (attempt %d/%d) after %v\n", attempt, c.maxRetries, backoff)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, err := c.doRequestOnce(ctx, method, url, body)
		if err == nil {
			return data, nil
		}

		lastErr = err

		// Don't retry on client errors (4xx) except 429 (rate limit)
		if isClientError(err) && !isRateLimitError(err) {
			return nil, err
		}

		// Don't retry on context errors
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, lastErr)
}

// doRequestOnce performs a single HTTP request.
func (c *Client) doRequestOnce(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	// Compress body if compression is enabled and body is large enough
	requestBody := body
	var contentEncoding string

	if c.compressor != nil && len(body) > 1024 { // Only compress if > 1KB
		compressed, stats, err := c.compressor.CompressWithStats(body)
		if err == nil && len(compressed) < len(body) {
			// Only use compressed if it's actually smaller
			requestBody = compressed
			contentEncoding = c.compressor.ContentEncoding()
			if c.verbose {
				fmt.Printf("[openctem] Compressed request: %d -> %d bytes (%.1f%% savings)\n",
					stats.OriginalSize, stats.CompressedSize, stats.Savings)
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "sdk/1.0")

	// Add Content-Encoding header if compressed
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	// Add agent ID header for audit trail
	if c.agentID != "" {
		req.Header.Set("X-Agent-ID", c.agentID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: string(data)}
	}

	return data, nil
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
	RequestID  string `json:"request_id,omitempty"`
}

func (e *HTTPError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("http %d: %s (request_id: %s)", e.StatusCode, e.Body, e.RequestID)
	}
	return fmt.Sprintf("http %d: %s", e.StatusCode, e.Body)
}

// =============================================================================
// Error Checking Helpers (Public API)
// =============================================================================

// IsHTTPError checks if err is an HTTPError and returns it.
func IsHTTPError(err error) (*HTTPError, bool) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr, true
	}
	return nil, false
}

// IsClientError checks if the error is a 4xx client error.
func IsClientError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
	}
	return false
}

// IsServerError checks if the error is a 5xx server error.
func IsServerError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode >= 500
	}
	return false
}

// IsRateLimitError checks if the error is a 429 rate limit error.
func IsRateLimitError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 429
	}
	return false
}

// IsAuthenticationError checks if the error is a 401 authentication error.
func IsAuthenticationError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 401
	}
	return false
}

// IsAuthorizationError checks if the error is a 403 authorization error.
func IsAuthorizationError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 403
	}
	return false
}

// IsNotFoundError checks if the error is a 404 not found error.
func IsNotFoundError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 404
	}
	return false
}

// IsRetryable checks if the error should be retried.
func IsRetryable(err error) bool {
	// Rate limit errors are retryable
	if IsRateLimitError(err) {
		return true
	}
	// Server errors (except 501) are retryable
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode >= 500 && httpErr.StatusCode != 501
	}
	return false
}

// Private helpers (keep backward compatibility)
func isClientError(err error) bool    { return IsClientError(err) }
func isRateLimitError(err error) bool { return IsRateLimitError(err) }

// SetVerbose sets verbose mode.
func (c *Client) SetVerbose(v bool) {
	c.verbose = v
}

// ============================================================================
// Retry Queue Methods
// ============================================================================

// hasRetryQueue returns true if a retry queue is configured.
func (c *Client) hasRetryQueue() bool {
	c.retryMu.RLock()
	defer c.retryMu.RUnlock()
	return c.retryQueue != nil
}

// queueForRetry adds a report to the retry queue for later retry.
func (c *Client) queueForRetry(ctx context.Context, report *ctis.Report, itemType retry.ItemType, originalErr error) error {
	c.retryMu.RLock()
	queue := c.retryQueue
	c.retryMu.RUnlock()

	if queue == nil {
		return errors.New("retry queue not configured")
	}

	item := &retry.QueueItem{
		Type:        itemType,
		Report:      report,
		LastError:   originalErr.Error(),
		AgentID:     c.agentID,
		ScannerName: "",
	}

	// Set scanner name from tool info if available
	if report.Tool != nil {
		item.ScannerName = report.Tool.Name
	}

	// Set target path from first asset if available
	if len(report.Assets) > 0 {
		item.TargetPath = report.Assets[0].Value
	}

	_, err := queue.Enqueue(ctx, item)
	return err
}

// EnableRetryQueue enables the retry queue with the given configuration.
// This creates a file-based retry queue and optionally starts the background worker.
func (c *Client) EnableRetryQueue(ctx context.Context, cfg *RetryQueueConfig) error {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()

	if cfg == nil {
		cfg = DefaultRetryQueueConfig()
	}

	// Create file-based queue
	queue, err := retry.NewFileRetryQueue(&retry.FileQueueConfig{
		Dir:           cfg.Dir,
		MaxSize:       cfg.MaxSize,
		Deduplication: true,
		Verbose:       c.verbose,
		Backoff:       cfg.Backoff,
	})
	if err != nil {
		return fmt.Errorf("create retry queue: %w", err)
	}

	c.retryQueue = queue

	// Create worker if auto-start is enabled
	if cfg.AutoStart {
		worker := retry.NewRetryWorker(&retry.RetryWorkerConfig{
			Interval:    cfg.Interval,
			BatchSize:   cfg.BatchSize,
			MaxAttempts: cfg.MaxAttempts,
			TTL:         cfg.TTL,
			Backoff:     cfg.Backoff,
			Verbose:     c.verbose,
		}, queue, c)

		c.retryWorker = worker

		// Start the worker
		if err := worker.Start(ctx); err != nil {
			return fmt.Errorf("start retry worker: %w", err)
		}
	}

	if c.verbose {
		fmt.Printf("[openctem] Retry queue enabled (dir: %s)\n", cfg.Dir)
	}

	return nil
}

// StartRetryWorker starts the background retry worker.
// EnableRetryQueue must be called first.
func (c *Client) StartRetryWorker(ctx context.Context) error {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()

	if c.retryQueue == nil {
		return errors.New("retry queue not enabled")
	}

	if c.retryWorker != nil && c.retryWorker.IsRunning() {
		return nil // Already running
	}

	if c.retryWorker == nil {
		c.retryWorker = retry.NewRetryWorker(nil, c.retryQueue, c)
	}

	return c.retryWorker.Start(ctx)
}

// StopRetryWorker stops the background retry worker gracefully.
func (c *Client) StopRetryWorker(ctx context.Context) error {
	c.retryMu.Lock()
	worker := c.retryWorker
	c.retryMu.Unlock()

	if worker == nil {
		return nil
	}

	return worker.Stop(ctx)
}

// DisableRetryQueue stops the worker and closes the retry queue.
func (c *Client) DisableRetryQueue(ctx context.Context) error {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()

	// Stop worker if running
	if c.retryWorker != nil {
		if err := c.retryWorker.Stop(ctx); err != nil {
			return fmt.Errorf("stop retry worker: %w", err)
		}
		c.retryWorker = nil
	}

	// Close queue
	if c.retryQueue != nil {
		if err := c.retryQueue.Close(); err != nil {
			return fmt.Errorf("close retry queue: %w", err)
		}
		c.retryQueue = nil
	}

	return nil
}

// GetRetryQueueStats returns statistics about the retry queue.
func (c *Client) GetRetryQueueStats(ctx context.Context) (*retry.QueueStats, error) {
	c.retryMu.RLock()
	queue := c.retryQueue
	c.retryMu.RUnlock()

	if queue == nil {
		return nil, errors.New("retry queue not enabled")
	}

	return queue.Stats(ctx)
}

// GetRetryWorkerStats returns statistics about the retry worker.
func (c *Client) GetRetryWorkerStats() (*retry.WorkerStats, error) {
	c.retryMu.RLock()
	worker := c.retryWorker
	c.retryMu.RUnlock()

	if worker == nil {
		return nil, errors.New("retry worker not running")
	}

	stats := worker.Stats()
	return &stats, nil
}

// ProcessRetryQueueNow immediately processes pending items in the retry queue.
// This is useful for testing or manual intervention.
func (c *Client) ProcessRetryQueueNow(ctx context.Context) error {
	c.retryMu.RLock()
	worker := c.retryWorker
	c.retryMu.RUnlock()

	if worker == nil {
		return errors.New("retry worker not configured")
	}

	return worker.ProcessNow(ctx)
}

// PushReport implements retry.ReportPusher interface.
// This is used by the retry worker to push items from the queue.
func (c *Client) PushReport(ctx context.Context, report *ctis.Report) error {
	// Use internal methods to avoid re-queueing on failure
	if len(report.Findings) > 0 {
		_, err := c.pushFindingsInternal(ctx, report)
		return err
	}
	if len(report.Assets) > 0 {
		_, err := c.pushAssetsInternal(ctx, report)
		return err
	}
	return nil
}

// RetryQueueConfig configures the retry queue.
type RetryQueueConfig struct {
	// Dir is the directory to store queue files.
	// Default: ~/.openctem/retry-queue
	Dir string

	// MaxSize is the maximum number of items in the queue.
	// Default: 1000
	MaxSize int

	// Interval is how often to check the queue for items to retry.
	// Default: 5 minutes
	Interval time.Duration

	// BatchSize is the maximum number of items to process per check.
	// Default: 10
	BatchSize int

	// MaxAttempts is the maximum number of retry attempts per item.
	// Default: 10
	MaxAttempts int

	// TTL is how long to keep items in the queue before expiring.
	// Default: 7 days
	TTL time.Duration

	// Backoff configures the retry backoff behavior.
	Backoff *retry.BackoffConfig

	// AutoStart starts the retry worker automatically.
	// Default: true
	AutoStart bool
}

// DefaultRetryQueueConfig returns a configuration with default values.
func DefaultRetryQueueConfig() *RetryQueueConfig {
	return &RetryQueueConfig{
		MaxSize:     retry.DefaultMaxQueueSize,
		Interval:    retry.DefaultRetryInterval,
		BatchSize:   retry.DefaultBatchSize,
		MaxAttempts: retry.DefaultMaxAttempts,
		TTL:         retry.DefaultTTL,
		Backoff:     retry.DefaultBackoffConfig(),
		AutoStart:   true,
	}
}

// Close gracefully shuts down the client and releases resources.
// This stops the retry worker and closes the retry queue if enabled.
func (c *Client) Close() error {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()

	// Stop the retry worker if running
	if c.retryWorker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.retryWorker.Stop(ctx)
		c.retryWorker = nil
	}

	// Close the retry queue
	if c.retryQueue != nil {
		if err := c.retryQueue.Close(); err != nil {
			return fmt.Errorf("close retry queue: %w", err)
		}
		c.retryQueue = nil
	}

	return nil
}

// =============================================================================
// Exposure Events API
// =============================================================================

// ExposureEvent represents an attack surface change event.
type ExposureEvent struct {
	// Event type: new_asset, asset_removed, exposure_detected, exposure_resolved
	Type string `json:"type"`

	// Asset identifier
	AssetID   string `json:"asset_id,omitempty"`
	AssetType string `json:"asset_type,omitempty"`
	AssetName string `json:"asset_name,omitempty"`

	// Exposure details
	ExposureType string `json:"exposure_type,omitempty"` // port_open, service_exposed, etc.
	Protocol     string `json:"protocol,omitempty"`
	Port         int    `json:"port,omitempty"`
	Service      string `json:"service,omitempty"`

	// Detection info
	DetectedAt  time.Time `json:"detected_at"`
	DetectedBy  string    `json:"detected_by,omitempty"` // scan source
	Severity    string    `json:"severity,omitempty"`
	Description string    `json:"description,omitempty"`

	// Resolution
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// Metadata
	Tags       []string       `json:"tags,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// PushExposuresResult is the result of pushing exposure events.
type PushExposuresResult struct {
	EventsCreated int `json:"events_created"`
	EventsUpdated int `json:"events_updated"`
	EventsSkipped int `json:"events_skipped"`
}

// PushExposures sends exposure events to OpenCTEM.
func (c *Client) PushExposures(ctx context.Context, events []ExposureEvent) (*PushExposuresResult, error) {
	url := fmt.Sprintf("%s/api/v1/exposures/ingest", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Pushing %d exposure events to %s\n", len(events), url)
	}

	input := struct {
		AgentID string          `json:"agent_id,omitempty"`
		Events  []ExposureEvent `json:"events"`
	}{
		AgentID: c.agentID,
		Events:  events,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal events: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp PushExposuresResult
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Exposure push completed: %d created, %d updated\n",
			resp.EventsCreated, resp.EventsUpdated)
	}

	return &resp, nil
}

// =============================================================================
// Threat Intelligence API
// =============================================================================

// EPSSScore represents an EPSS score for a CVE.
type EPSSScore struct {
	CVEID      string    `json:"cve_id"`
	Score      float64   `json:"score"`      // 0.0 to 1.0
	Percentile float64   `json:"percentile"` // 0.0 to 100.0
	Date       time.Time `json:"date"`
}

// GetEPSSScores fetches EPSS scores for the given CVE IDs.
func (c *Client) GetEPSSScores(ctx context.Context, cveIDs []string) ([]EPSSScore, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	url := fmt.Sprintf("%s/api/v1/threatintel/epss", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Fetching EPSS scores for %d CVEs\n", len(cveIDs))
	}

	input := struct {
		CVEIDs []string `json:"cve_ids"`
	}{
		CVEIDs: cveIDs,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Scores []EPSSScore `json:"scores"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return resp.Scores, nil
}

// KEVEntry represents a CISA Known Exploited Vulnerabilities entry.
type KEVEntry struct {
	CVEID                      string    `json:"cve_id"`
	VendorProject              string    `json:"vendor_project"`
	Product                    string    `json:"product"`
	VulnerabilityName          string    `json:"vulnerability_name"`
	DateAdded                  time.Time `json:"date_added"`
	ShortDescription           string    `json:"short_description"`
	RequiredAction             string    `json:"required_action"`
	DueDate                    time.Time `json:"due_date"`
	KnownRansomwareCampaignUse string    `json:"known_ransomware_campaign_use"`
}

// GetKEVEntries fetches CISA KEV entries for the given CVE IDs.
func (c *Client) GetKEVEntries(ctx context.Context, cveIDs []string) ([]KEVEntry, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	url := fmt.Sprintf("%s/api/v1/threatintel/kev", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Fetching KEV entries for %d CVEs\n", len(cveIDs))
	}

	input := struct {
		CVEIDs []string `json:"cve_ids"`
	}{
		CVEIDs: cveIDs,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entries []KEVEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return resp.Entries, nil
}

// =============================================================================
// Chunked Upload API
// =============================================================================

// ChunkUploadResponse is the response from chunk upload endpoint.
type ChunkUploadResponse struct {
	ChunkID         string `json:"chunk_id"`
	ReportID        string `json:"report_id"`
	ChunkIndex      int    `json:"chunk_index"`
	Status          string `json:"status"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	FindingsSkipped int    `json:"findings_skipped"`
}

// UploadChunk uploads a single chunk of a large report.
// This implements the chunk.Uploader interface.
func (c *Client) UploadChunk(ctx context.Context, data *chunk.ChunkData) error {
	url := fmt.Sprintf("%s/api/v1/agent/ingest/chunk", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Uploading chunk %d/%d for report %s\n",
			data.ChunkIndex+1, data.TotalChunks, data.ReportID)
	}

	// Serialize chunk data
	chunkJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal chunk data: %w", err)
	}

	// Compress chunk data using ZSTD (default)
	var compressedData []byte
	compressionAlgo := "zstd"

	if c.compressor != nil {
		compressedData, err = c.compressor.Compress(chunkJSON)
		if err != nil {
			return fmt.Errorf("compress chunk data: %w", err)
		}
		compressionAlgo = string(c.compressor.Algorithm())
	} else {
		// Use default ZSTD compressor
		compressedData, err = compress.QuickCompress(chunkJSON)
		if err != nil {
			return fmt.Errorf("compress chunk data: %w", err)
		}
	}

	// Base64 encode compressed data
	encodedData := base64.StdEncoding.EncodeToString(compressedData)

	// Build request body
	reqBody := struct {
		ReportID    string `json:"report_id"`
		ChunkIndex  int    `json:"chunk_index"`
		TotalChunks int    `json:"total_chunks"`
		Compression string `json:"compression"`
		Data        string `json:"data"`
		IsFinal     bool   `json:"is_final"`
	}{
		ReportID:    data.ReportID,
		ChunkIndex:  data.ChunkIndex,
		TotalChunks: data.TotalChunks,
		Compression: compressionAlgo,
		Data:        encodedData,
		IsFinal:     data.IsFinal,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Send request (the body itself is not compressed at HTTP level since data is base64)
	respBody, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return fmt.Errorf("upload chunk: %w", err)
	}

	var resp ChunkUploadResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Chunk %d/%d uploaded: %d findings, %d assets\n",
			data.ChunkIndex+1, data.TotalChunks, resp.FindingsCreated, resp.AssetsCreated)
	}

	return nil
}

// AsChunkUploader returns the client as a chunk.Uploader interface.
// This is useful for passing to chunk.Manager.
func (c *Client) AsChunkUploader() chunk.Uploader {
	return c
}

// =============================================================================
// Suppression API
// =============================================================================

// SuppressionRule represents a platform-controlled suppression rule.
type SuppressionRule struct {
	RuleID      string  `json:"rule_id,omitempty"`
	ToolName    string  `json:"tool_name,omitempty"`
	PathPattern string  `json:"path_pattern,omitempty"`
	AssetID     *string `json:"asset_id,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// GetSuppressions fetches active suppression rules from the platform.
// These rules are used to filter out false positives from scan results.
func (c *Client) GetSuppressions(ctx context.Context) ([]SuppressionRule, error) {
	url := fmt.Sprintf("%s/api/v1/suppressions/active", c.baseURL)

	if c.verbose {
		fmt.Println("[openctem] Fetching suppression rules")
	}

	data, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		// Non-fatal: suppressions are optional
		if c.verbose {
			fmt.Printf("[openctem] Warning: could not fetch suppressions: %v\n", err)
		}
		return nil, nil
	}

	var resp struct {
		Rules []SuppressionRule `json:"rules"`
		Count int               `json:"count"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal suppressions response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Fetched %d suppression rules\n", resp.Count)
	}

	return resp.Rules, nil
}

// FilterSuppressedFindings removes findings that match suppression rules.
// This is used by the security gate to exclude false positives.
func (c *Client) FilterSuppressedFindings(findings []ctis.Finding, rules []SuppressionRule) []ctis.Finding {
	if len(rules) == 0 {
		return findings
	}

	var filtered []ctis.Finding
	for _, f := range findings {
		if !c.isFiningSuppressed(f, rules) {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// isFiningSuppressed checks if a finding matches any suppression rule.
func (c *Client) isFiningSuppressed(f ctis.Finding, rules []SuppressionRule) bool {
	for _, rule := range rules {
		if c.matchesSuppressionRule(f, rule) {
			return true
		}
	}
	return false
}

// matchesSuppressionRule checks if a finding matches a specific suppression rule.
// Note: ToolName is not checked here because Finding doesn't have Tool info;
// it should be checked at the Report level before calling this function.
func (c *Client) matchesSuppressionRule(f ctis.Finding, rule SuppressionRule) bool {
	// Check rule ID (supports wildcard suffix)
	if rule.RuleID != "" {
		if strings.HasSuffix(rule.RuleID, "*") {
			prefix := strings.TrimSuffix(rule.RuleID, "*")
			if !strings.HasPrefix(f.RuleID, prefix) {
				return false
			}
		} else if rule.RuleID != f.RuleID {
			return false
		}
	}

	// Check path pattern
	if rule.PathPattern != "" && f.Location != nil && f.Location.Path != "" {
		if !matchGlobPattern(rule.PathPattern, f.Location.Path) {
			return false
		}
	}

	return true
}

// matchGlobPattern provides simple glob matching with ** support.
func matchGlobPattern(pattern, path string) bool {
	// Handle ** patterns
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			if prefix != "" && !strings.HasPrefix(path, prefix) {
				return false
			}
			if suffix != "" && !strings.HasSuffix(path, suffix) {
				return false
			}
			return true
		}
	}

	// Simple wildcard matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	return pattern == path
}

// =============================================================================
// Finding Enrichment API
// =============================================================================

// EnrichFindings adds EPSS and KEV data to findings with CVE IDs.
func (c *Client) EnrichFindings(ctx context.Context, findings []ctis.Finding) ([]ctis.Finding, error) {
	// Collect CVE IDs
	cveIDs := make([]string, 0)
	for _, f := range findings {
		if f.Vulnerability != nil && f.Vulnerability.CVEID != "" {
			cveIDs = append(cveIDs, f.Vulnerability.CVEID)
		}
	}

	if len(cveIDs) == 0 {
		return findings, nil
	}

	// Fetch EPSS scores
	epssScores, _ := c.GetEPSSScores(ctx, cveIDs)
	epssMap := make(map[string]EPSSScore)
	for _, score := range epssScores {
		epssMap[score.CVEID] = score
	}

	// Fetch KEV entries
	kevEntries, _ := c.GetKEVEntries(ctx, cveIDs)
	kevMap := make(map[string]bool)
	for _, entry := range kevEntries {
		kevMap[entry.CVEID] = true
	}

	// Enrich findings
	result := make([]ctis.Finding, len(findings))
	for i, f := range findings {
		result[i] = f
		if f.Vulnerability != nil && f.Vulnerability.CVEID != "" {
			cveID := f.Vulnerability.CVEID
			if epss, ok := epssMap[cveID]; ok {
				result[i].Vulnerability.EPSSScore = epss.Score
				result[i].Vulnerability.EPSSPercentile = epss.Percentile
			}
			if kevMap[cveID] {
				result[i].Vulnerability.InCISAKEV = true
			}
		}
	}

	return result, nil
}
