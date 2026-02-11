package platform

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// JobClient defines the interface for job operations.
type JobClient interface {
	// Poll polls for new jobs using long-polling.
	Poll(ctx context.Context, req *PollRequest) (*PollResponse, error)

	// AcknowledgeJob acknowledges receipt of a job.
	AcknowledgeJob(ctx context.Context, jobID string) error

	// ReportJobResult reports the result of a completed job.
	ReportJobResult(ctx context.Context, result *JobResult) error

	// ReportJobProgress reports progress on a running job.
	ReportJobProgress(ctx context.Context, jobID string, progress int, message string) error
}

// PollRequest contains the data for polling jobs.
type PollRequest struct {
	MaxJobs        int      `json:"max_jobs"`
	Capabilities   []string `json:"capabilities,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// PollResponse contains the response from job polling.
type PollResponse struct {
	Jobs             []*JobInfo `json:"jobs"`
	PollIntervalHint int        `json:"poll_interval_hint,omitempty"` // Suggested wait before next poll
	QueueDepth       int        `json:"queue_depth,omitempty"`        // Total pending jobs
}

// JobExecutor executes platform jobs.
type JobExecutor interface {
	Execute(ctx context.Context, job *JobInfo) (*JobResult, error)
}

// PollerConfig configures the JobPoller.
type PollerConfig struct {
	// MaxConcurrentJobs is the maximum number of concurrent jobs.
	MaxConcurrentJobs int

	// PollTimeout is the long-poll timeout (how long to wait for jobs).
	PollTimeout time.Duration

	// RetryDelay is the delay between poll attempts on error.
	RetryDelay time.Duration

	// Capabilities to advertise when polling.
	Capabilities []string

	// OnJobStarted is called when a job starts executing.
	OnJobStarted func(job *JobInfo)

	// OnJobCompleted is called when a job completes (success or failure).
	OnJobCompleted func(job *JobInfo, result *JobResult)

	// Verbose enables debug logging.
	Verbose bool

	// AllowedJobTypes restricts which job types can be executed.
	// If empty, all job types are allowed.
	AllowedJobTypes []string

	// MaxPayloadSize limits the maximum payload size for jobs (default: 10MB).
	MaxPayloadSize int

	// RequireAuthToken requires jobs to have a valid auth token.
	// When true, jobs without AuthToken will be rejected.
	RequireAuthToken bool

	// ValidateTokenClaims enables JWT claims validation.
	// When true, the AuthToken's tenant_id claim must match job's TenantID.
	ValidateTokenClaims bool
}

// JobValidationError represents a job validation failure.
type JobValidationError struct {
	JobID  string
	Reason string
}

func (e *JobValidationError) Error() string {
	return fmt.Sprintf("job %s validation failed: %s", e.JobID, e.Reason)
}

// ValidateJob validates a job before execution.
// SECURITY: This prevents processing of malformed or unauthorized jobs.
func ValidateJob(job *JobInfo, config *PollerConfig) error {
	if job == nil {
		return &JobValidationError{Reason: "job is nil"}
	}

	// Validate job ID
	if job.ID == "" {
		return &JobValidationError{Reason: "job ID is required"}
	}

	// Validate tenant ID
	if job.TenantID == "" {
		return &JobValidationError{JobID: job.ID, Reason: "tenant ID is required"}
	}

	// Validate job type
	if job.Type == "" {
		return &JobValidationError{JobID: job.ID, Reason: "job type is required"}
	}

	// Check allowed job types if configured
	if len(config.AllowedJobTypes) > 0 {
		allowed := false
		for _, t := range config.AllowedJobTypes {
			if t == job.Type {
				allowed = true
				break
			}
		}
		if !allowed {
			return &JobValidationError{
				JobID:  job.ID,
				Reason: fmt.Sprintf("job type %q not allowed", job.Type),
			}
		}
	}

	// Validate payload size
	maxSize := config.MaxPayloadSize
	if maxSize == 0 {
		maxSize = 10 * 1024 * 1024 // Default 10MB
	}
	if job.Payload != nil {
		payloadBytes, _ := json.Marshal(job.Payload)
		if len(payloadBytes) > maxSize {
			return &JobValidationError{
				JobID:  job.ID,
				Reason: fmt.Sprintf("payload size %d exceeds limit %d", len(payloadBytes), maxSize),
			}
		}
	}

	// Validate auth token if required
	if config.RequireAuthToken {
		if job.AuthToken == "" {
			return &JobValidationError{JobID: job.ID, Reason: "auth token is required"}
		}

		// Validate token claims if enabled
		if config.ValidateTokenClaims {
			if err := validateTokenTenantClaim(job.AuthToken, job.TenantID); err != nil {
				return &JobValidationError{JobID: job.ID, Reason: err.Error()}
			}
		}
	}

	// Validate timeout (prevent zero or unreasonably long timeouts)
	if job.TimeoutSec < 0 {
		return &JobValidationError{JobID: job.ID, Reason: "negative timeout not allowed"}
	}
	if job.TimeoutSec > 3600 { // Max 1 hour
		return &JobValidationError{
			JobID:  job.ID,
			Reason: fmt.Sprintf("timeout %d seconds exceeds maximum 3600", job.TimeoutSec),
		}
	}

	return nil
}

// validateTokenTenantClaim validates that the JWT token's tenant_id claim matches the job's TenantID.
// SECURITY: This prevents a malicious server from sending jobs with mismatched tokens.
// Note: This does NOT validate the token signature - that should be done by the API when using the token.
func validateTokenTenantClaim(token, expectedTenantID string) error {
	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode payload (middle part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return fmt.Errorf("invalid JWT payload encoding")
		}
	}

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("invalid JWT payload JSON")
	}

	// Check tenant_id claim
	tenantID, ok := claims["tenant_id"].(string)
	if !ok {
		// Also check sub claim as fallback
		tenantID, ok = claims["sub"].(string)
		if !ok {
			return fmt.Errorf("JWT missing tenant_id claim")
		}
	}

	if tenantID != expectedTenantID {
		return fmt.Errorf("JWT tenant_id %q does not match job tenant_id %q", tenantID, expectedTenantID)
	}

	return nil
}

// ResourceController is an optional interface for resource-based job throttling.
// If set on JobPoller, jobs will only be accepted when resources are available.
type ResourceController interface {
	// AcquireSlot attempts to acquire a job execution slot.
	// Returns true if acquired, false if throttled or at capacity.
	AcquireSlot(ctx context.Context) bool

	// ReleaseSlot releases a previously acquired slot.
	ReleaseSlot()

	// IsThrottled returns true if resource limits are exceeded.
	IsThrottled() bool
}

// AuditLogger is an optional interface for audit logging.
// If set on JobPoller, job lifecycle events will be logged.
type AuditLogger interface {
	// JobStarted logs a job start event.
	JobStarted(jobID, jobType string, details map[string]interface{})

	// JobCompleted logs a job completion event.
	JobCompleted(jobID string, duration time.Duration, details map[string]interface{})

	// JobFailed logs a job failure event.
	JobFailed(jobID string, err error, details map[string]interface{})

	// ResourceThrottle logs a resource throttle event.
	ResourceThrottle(reason string, metrics map[string]interface{})
}

// JobPoller polls for and executes platform jobs.
//
// The JobPoller uses long-polling to efficiently wait for jobs. When no jobs
// are available, the server holds the connection open until a job arrives or
// the timeout expires. This provides near-real-time job dispatch with minimal
// network overhead.
//
// Optional integrations:
//   - ResourceController: Throttle job acceptance based on CPU/memory
//   - AuditLogger: Log job lifecycle events for debugging and compliance
type JobPoller struct {
	client       JobClient
	executor     JobExecutor
	config       *PollerConfig
	leaseManager *LeaseManager

	// Optional resource controller for throttling
	resourceController ResourceController

	// Optional audit logger for event logging
	auditLogger AuditLogger

	running     int32 // atomic
	stopCh      chan struct{}
	activeJobs  sync.WaitGroup
	currentJobs int32 // atomic count
	mu          sync.Mutex

	// jobCancels tracks cancel functions for running jobs.
	// Used to cancel jobs when lease expires.
	jobCancels   map[string]context.CancelFunc
	jobCancelsMu sync.Mutex
}

// NewJobPoller creates a new JobPoller.
func NewJobPoller(client JobClient, executor JobExecutor, config *PollerConfig) *JobPoller {
	if config == nil {
		config = &PollerConfig{}
	}
	if config.MaxConcurrentJobs == 0 {
		config.MaxConcurrentJobs = DefaultMaxConcurrentJobs
	}
	if config.PollTimeout == 0 {
		config.PollTimeout = DefaultPollTimeout
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}

	return &JobPoller{
		client:     client,
		executor:   executor,
		config:     config,
		stopCh:     make(chan struct{}),
		jobCancels: make(map[string]context.CancelFunc),
	}
}

// SetLeaseManager sets the lease manager for job count reporting.
// It also registers a callback to cancel all running jobs when lease expires.
func (p *JobPoller) SetLeaseManager(lm *LeaseManager) {
	p.leaseManager = lm

	// Register lease expiry callback to cancel all running jobs
	if lm != nil && lm.config != nil {
		originalCallback := lm.config.OnLeaseExpired
		lm.config.OnLeaseExpired = func() {
			// Cancel all running jobs
			p.cancelAllJobs("lease expired")

			// Call original callback if set
			if originalCallback != nil {
				originalCallback()
			}
		}
	}
}

// SetResourceController sets the optional resource controller for throttling.
// When set, jobs will only be accepted when resources are available.
func (p *JobPoller) SetResourceController(rc ResourceController) {
	p.resourceController = rc
}

// SetAuditLogger sets the optional audit logger for event logging.
// When set, job lifecycle events will be logged.
func (p *JobPoller) SetAuditLogger(logger AuditLogger) {
	p.auditLogger = logger
}

// cancelAllJobs cancels all currently running jobs.
// SECURITY: Called when lease expires to prevent orphaned job execution.
func (p *JobPoller) cancelAllJobs(reason string) {
	p.jobCancelsMu.Lock()
	defer p.jobCancelsMu.Unlock()

	if p.config.Verbose {
		fmt.Printf("[poller] Canceling %d running jobs: %s\n", len(p.jobCancels), reason)
	}

	for jobID, cancel := range p.jobCancels {
		if p.config.Verbose {
			fmt.Printf("[poller] Canceling job %s\n", jobID)
		}
		cancel()
	}
	// Clear the map - job goroutines will clean up their own entries
}

// registerJobCancel registers a cancel function for a running job.
func (p *JobPoller) registerJobCancel(jobID string, cancel context.CancelFunc) {
	p.jobCancelsMu.Lock()
	p.jobCancels[jobID] = cancel
	p.jobCancelsMu.Unlock()
}

// unregisterJobCancel removes a job's cancel function.
func (p *JobPoller) unregisterJobCancel(jobID string) {
	p.jobCancelsMu.Lock()
	delete(p.jobCancels, jobID)
	p.jobCancelsMu.Unlock()
}

// Start starts the job poller.
func (p *JobPoller) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&p.running, 0, 1) {
		return fmt.Errorf("poller already running")
	}

	p.mu.Lock()
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	if p.config.Verbose {
		fmt.Printf("[poller] Starting (max_jobs=%d, timeout=%v)\n",
			p.config.MaxConcurrentJobs, p.config.PollTimeout)
	}

	go p.pollLoop(ctx)

	return nil
}

// Stop stops the job poller and waits for active jobs to complete.
func (p *JobPoller) Stop(timeout time.Duration) error {
	if !atomic.CompareAndSwapInt32(&p.running, 1, 0) {
		return nil // Already stopped
	}

	p.mu.Lock()
	close(p.stopCh)
	p.mu.Unlock()

	if p.config.Verbose {
		fmt.Printf("[poller] Stopping, waiting for active jobs...\n")
	}

	// Wait for active jobs with timeout
	done := make(chan struct{})
	go func() {
		p.activeJobs.Wait()
		close(done)
	}()

	select {
	case <-done:
		if p.config.Verbose {
			fmt.Printf("[poller] All jobs completed\n")
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for jobs to complete")
	}
}

// CurrentJobCount returns the current number of running jobs.
func (p *JobPoller) CurrentJobCount() int {
	return int(atomic.LoadInt32(&p.currentJobs))
}

// pollLoop is the main polling loop.
func (p *JobPoller) pollLoop(ctx context.Context) {
	for atomic.LoadInt32(&p.running) == 1 {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
			p.pollOnce(ctx)
		}
	}
}

func (p *JobPoller) pollOnce(ctx context.Context) {
	// Check if resource controller is throttling
	if p.resourceController != nil && p.resourceController.IsThrottled() {
		if p.config.Verbose {
			fmt.Printf("[poller] Resource throttling active, waiting...\n")
		}
		// Log throttle event via audit logger
		if p.auditLogger != nil {
			p.auditLogger.ResourceThrottle("system resources exceeded threshold", nil)
		}
		time.Sleep(5 * time.Second)
		return
	}

	// Calculate available capacity
	current := int(atomic.LoadInt32(&p.currentJobs))
	available := p.config.MaxConcurrentJobs - current
	if available <= 0 {
		// At capacity, wait a bit before checking again
		time.Sleep(time.Second)
		return
	}

	// Create poll context with timeout
	pollCtx, cancel := context.WithTimeout(ctx, p.config.PollTimeout+5*time.Second)
	defer cancel()

	req := &PollRequest{
		MaxJobs:        available,
		Capabilities:   p.config.Capabilities,
		TimeoutSeconds: int(p.config.PollTimeout.Seconds()),
	}

	if p.config.Verbose {
		fmt.Printf("[poller] Polling for jobs (capacity=%d/%d)\n",
			available, p.config.MaxConcurrentJobs)
	}

	resp, err := p.client.Poll(pollCtx, req)
	if err != nil {
		if pollCtx.Err() != nil {
			// Context canceled or timeout - normal during shutdown
			return
		}
		if p.config.Verbose {
			fmt.Printf("[poller] Poll failed: %v\n", err)
		}
		time.Sleep(p.config.RetryDelay)
		return
	}

	if len(resp.Jobs) == 0 {
		// No jobs available - the long-poll already waited
		return
	}

	if p.config.Verbose {
		fmt.Printf("[poller] Received %d jobs (queue_depth=%d)\n",
			len(resp.Jobs), resp.QueueDepth)
	}

	// Process each job
	for _, job := range resp.Jobs {
		// SECURITY: Validate job before processing
		if err := ValidateJob(job, p.config); err != nil {
			if p.config.Verbose {
				fmt.Printf("[poller] Job validation failed: %v\n", err)
			}
			// Report validation failure back to server
			failResult := &JobResult{
				JobID:       job.ID,
				Status:      "failed",
				Error:       fmt.Sprintf("validation failed: %v", err),
				CompletedAt: time.Now(),
			}
			if reportErr := p.client.ReportJobResult(ctx, failResult); reportErr != nil {
				if p.config.Verbose {
					fmt.Printf("[poller] Failed to report validation failure for job %s: %v\n", job.ID, reportErr)
				}
			}
			continue
		}

		// Check resource controller before accepting job
		if p.resourceController != nil {
			if !p.resourceController.AcquireSlot(ctx) {
				if p.config.Verbose {
					fmt.Printf("[poller] Resource controller rejected job %s (throttled)\n", job.ID)
				}
				if p.auditLogger != nil {
					p.auditLogger.ResourceThrottle("job rejected due to resource limits", map[string]interface{}{
						"job_id":   job.ID,
						"job_type": job.Type,
					})
				}
				// Don't acknowledge - let the job be picked up later or by another agent
				continue
			}
		}

		// Acknowledge receipt
		if err := p.client.AcknowledgeJob(ctx, job.ID); err != nil {
			if p.config.Verbose {
				fmt.Printf("[poller] Failed to acknowledge job %s: %v\n", job.ID, err)
			}
			// Release resource slot if acquired
			if p.resourceController != nil {
				p.resourceController.ReleaseSlot()
			}
			continue
		}

		// Execute job asynchronously
		p.activeJobs.Add(1)
		atomic.AddInt32(&p.currentJobs, 1)
		if p.leaseManager != nil {
			p.leaseManager.IncrementJobs()
		}

		go p.executeJob(ctx, job)
	}
}

func (p *JobPoller) executeJob(ctx context.Context, job *JobInfo) {
	defer func() {
		p.activeJobs.Done()
		atomic.AddInt32(&p.currentJobs, -1)
		p.unregisterJobCancel(job.ID)

		// Release resource controller slot if present
		if p.resourceController != nil {
			p.resourceController.ReleaseSlot()
		}
	}()

	startTime := time.Now()

	if p.config.Verbose {
		fmt.Printf("[poller] Executing job %s (type=%s, tenant=%s)\n",
			job.ID, job.Type, job.TenantID)
	}

	// Log job start via audit logger
	if p.auditLogger != nil {
		p.auditLogger.JobStarted(job.ID, job.Type, map[string]interface{}{
			"tenant_id": job.TenantID,
			"priority":  job.Priority,
		})
	}

	if p.config.OnJobStarted != nil {
		p.config.OnJobStarted(job)
	}

	// Create context with job timeout
	// SECURITY: Also check lease status - if lease is unhealthy, use shorter timeout
	var jobCtx context.Context
	var cancel context.CancelFunc

	// Determine effective timeout
	timeout := time.Duration(job.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute // Default timeout to prevent indefinite execution
	}

	// If lease manager exists, check lease health and potentially reduce timeout
	if p.leaseManager != nil {
		status := p.leaseManager.GetStatus()
		if !status.Healthy {
			// Lease is unhealthy - use grace period as max timeout
			graceTimeout := p.leaseManager.config.GracePeriod
			if graceTimeout < timeout {
				timeout = graceTimeout
				if p.config.Verbose {
					fmt.Printf("[poller] Job %s: reducing timeout to %v due to unhealthy lease\n",
						job.ID, timeout)
				}
			}
		}
	}

	jobCtx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	// Register cancel function so job can be canceled if lease expires
	p.registerJobCancel(job.ID, cancel)

	// Execute the job
	result, err := p.executor.Execute(jobCtx, job)

	// Build result if not provided
	if result == nil {
		result = &JobResult{
			JobID:       job.ID,
			CompletedAt: time.Now(),
			DurationMs:  time.Since(startTime).Milliseconds(),
		}
	} else {
		result.JobID = job.ID
		result.CompletedAt = time.Now()
		if result.DurationMs == 0 {
			result.DurationMs = time.Since(startTime).Milliseconds()
		}
	}

	duration := time.Since(startTime)

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()

		// Check if error was due to context cancellation (lease expiry)
		if jobCtx.Err() == context.Canceled {
			result.Error = "job canceled: " + err.Error()
			if p.config.Verbose {
				fmt.Printf("[poller] Job %s canceled (possibly due to lease expiry): %v\n", job.ID, err)
			}
		} else if jobCtx.Err() == context.DeadlineExceeded {
			result.Error = "job timed out: " + err.Error()
			if p.config.Verbose {
				fmt.Printf("[poller] Job %s timed out: %v\n", job.ID, err)
			}
		} else {
			if p.config.Verbose {
				fmt.Printf("[poller] Job %s failed: %v\n", job.ID, err)
			}
		}

		// Log job failure via audit logger
		if p.auditLogger != nil {
			p.auditLogger.JobFailed(job.ID, err, map[string]interface{}{
				"job_type":  job.Type,
				"tenant_id": job.TenantID,
				"duration":  duration.String(),
			})
		}
	} else {
		result.Status = "completed"
		if p.config.Verbose {
			fmt.Printf("[poller] Job %s completed (findings=%d, duration=%dms)\n",
				job.ID, result.FindingsCount, result.DurationMs)
		}

		// Log job completion via audit logger
		if p.auditLogger != nil {
			p.auditLogger.JobCompleted(job.ID, duration, map[string]interface{}{
				"job_type":       job.Type,
				"tenant_id":      job.TenantID,
				"findings_count": result.FindingsCount,
			})
		}
	}

	// Update lease manager
	if p.leaseManager != nil {
		p.leaseManager.DecrementJobs(result.Status == "failed")
	}

	// Report result back to server
	if reportErr := p.client.ReportJobResult(ctx, result); reportErr != nil {
		if p.config.Verbose {
			fmt.Printf("[poller] Failed to report result for job %s: %v\n", job.ID, reportErr)
		}
	}

	if p.config.OnJobCompleted != nil {
		p.config.OnJobCompleted(job, result)
	}
}

// =============================================================================
// HTTP Client Implementation
// =============================================================================

// httpJobClient implements JobClient using HTTP.
type httpJobClient struct {
	baseURL    string
	apiKey     string
	agentID    string
	httpClient *http.Client
}

// NewHTTPJobClient creates a new HTTP-based job client.
func NewHTTPJobClient(baseURL, apiKey, agentID string, pollTimeout time.Duration) JobClient {
	return &httpJobClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		agentID: agentID,
		httpClient: &http.Client{
			// Timeout should be longer than poll timeout to allow for response
			Timeout: pollTimeout + 10*time.Second,
		},
	}
}

func (c *httpJobClient) Poll(ctx context.Context, req *PollRequest) (*PollResponse, error) {
	url := fmt.Sprintf("%s/api/v1/platform/poll", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
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

	var result PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c *httpJobClient) AcknowledgeJob(ctx context.Context, jobID string) error {
	url := fmt.Sprintf("%s/api/v1/platform/jobs/%s/ack", c.baseURL, jobID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
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

func (c *httpJobClient) ReportJobResult(ctx context.Context, result *JobResult) error {
	url := fmt.Sprintf("%s/api/v1/platform/jobs/%s/result", c.baseURL, result.JobID)

	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
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

func (c *httpJobClient) ReportJobProgress(ctx context.Context, jobID string, progress int, message string) error {
	url := fmt.Sprintf("%s/api/v1/platform/jobs/%s/progress", c.baseURL, jobID)

	body, err := json.Marshal(map[string]interface{}{
		"progress": progress,
		"message":  message,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
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
