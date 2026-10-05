package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openctemio/sdk-go/pkg/audit" //nolint:staticcheck // the removed platform-mode client; removed with it
	"github.com/openctemio/sdk-go/pkg/chunk"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/pipeline" //nolint:staticcheck // the removed platform-mode client; removed with it
	"github.com/openctemio/sdk-go/pkg/resource"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// ClientConfig configures the PlatformClient.
type ClientConfig struct {
	// BaseURL is the API base URL.
	BaseURL string

	// APIKey is the sensor's API key.
	APIKey string

	// SensorID is the sensor's ID.
	SensorID string

	// PollTimeout is the long-poll timeout for job polling.
	PollTimeout time.Duration

	// Verbose enables debug logging.
	Verbose bool
}

// PlatformClient provides a unified interface for platform sensor operations.
// It implements LeaseClient and JobClient interfaces.
type PlatformClient struct {
	leaseClient LeaseClient
	jobClient   JobClient
	config      *ClientConfig
	// Concrete refs to the underlying HTTP clients, kept so the API key can be
	// rotated at runtime (SetAPIKey) — the interface fields above cannot expose
	// a key setter. Populated when built via NewPlatformClient; nil if a caller
	// injects custom LeaseClient/JobClient implementations.
	httpLease *httpLeaseClient
	httpJob   *httpJobClient
	// renewClient issues the self-renew call. Short timeout — renewal is a tiny
	// request and must not hang the renew loop.
	renewClient *http.Client
}

// NewPlatformClient creates a new PlatformClient.
func NewPlatformClient(config *ClientConfig) *PlatformClient {
	if config.PollTimeout == 0 {
		config.PollTimeout = DefaultPollTimeout
	}

	lease := NewHTTPLeaseClient(config.BaseURL, config.APIKey, config.SensorID)
	job := NewHTTPJobClient(config.BaseURL, config.APIKey, config.SensorID, config.PollTimeout)

	pc := &PlatformClient{
		leaseClient: lease,
		jobClient:   job,
		config:      config,
		renewClient: newAPIHTTPClient(15 * time.Second),
	}
	// Keep concrete refs for runtime key rotation.
	if hl, ok := lease.(*httpLeaseClient); ok {
		pc.httpLease = hl
	}
	if hj, ok := job.(*httpJobClient); ok {
		pc.httpJob = hj
	}
	return pc
}

// RenewKeyResponse is the result of a self-renew call. ExpiresAt is nil when the
// server has no key TTL configured (the key never expires).
type RenewKeyResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RenewKey rotates this sensor's API key by presenting the current one. It
// uses protocol v2 (POST /api/v2/sensor/keys, api RFC-029 §4.7) and falls
// back to protocol v1 (POST /api/v1/agent/renew) only when the platform does
// not serve the v2 route (404/405 without a problem document). It does NOT
// swap the key in — the caller decides when to call SetAPIKey (and persist),
// so a failed persist never leaves the running client on a key the sensor
// can't recover after a restart. It never retries: without a key TTL the
// platform replaces the presented key, so a repeated renewal after a lost
// answer would be refused.
func (c *PlatformClient) RenewKey(ctx context.Context) (*RenewKeyResponse, error) {
	out, err := c.renewKey(ctx, protov2.PathPrefix+protov2.KeysPath, false)
	if errors.Is(err, errRenewRouteMissing) {
		out, err = c.renewKey(ctx, legacyv1.PathRenew, true)
	}
	return out, err
}

// errRenewRouteMissing: the platform does not serve the v2 renewal route.
var errRenewRouteMissing = errors.New("v2 key renewal not served")

func (c *PlatformClient) renewKey(ctx context.Context, path string, v1 bool) (*RenewKeyResponse, error) {
	url, err := apiURL(c.config.BaseURL, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.currentAPIKey())
	if v1 {
		// Protocol v1 only; v2 identifies the sensor by its key alone.
		req.Header.Set(legacyv1.HeaderSensorID, c.config.SensorID)
	}

	resp, err := c.renewClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case !v1 && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) &&
		!protov2.IsProblemContentType(resp.Header.Get("Content-Type")):
		return nil, errRenewRouteMissing
	case v1 && resp.StatusCode != http.StatusOK, !v1 && resp.StatusCode != http.StatusCreated:
		return nil, &RenewError{StatusCode: resp.StatusCode}
	}

	var out RenewKeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.APIKey == "" {
		return nil, fmt.Errorf("renew returned an empty key")
	}
	return &out, nil
}

// RenewError is a refused key renewal. It satisfies the HTTPStatusCode
// interface pkg/core uses to tell a rejected key from other failures.
type RenewError struct{ StatusCode int }

func (e *RenewError) Error() string { return fmt.Sprintf("unexpected status: %d", e.StatusCode) }

// HTTPStatusCode returns the response status.
func (e *RenewError) HTTPStatusCode() int { return e.StatusCode }

// SetAPIKey atomically swaps the API key used by all subsequent lease and job
// requests. Safe to call concurrently with in-flight requests.
func (c *PlatformClient) SetAPIKey(key string) {
	if c.httpLease != nil {
		c.httpLease.setAPIKey(key)
	}
	if c.httpJob != nil {
		c.httpJob.setAPIKey(key)
	}
}

// currentAPIKey returns the key currently in use (from a concrete sub-client
// when available, else the construction-time config value).
func (c *PlatformClient) currentAPIKey() string {
	if c.httpJob != nil {
		return c.httpJob.getAPIKey()
	}
	if c.httpLease != nil {
		return c.httpLease.getAPIKey()
	}
	return c.config.APIKey
}

// =============================================================================
// LeaseClient Implementation
// =============================================================================

// RenewLease implements LeaseClient.
func (c *PlatformClient) RenewLease(ctx context.Context, req *LeaseRenewRequest) (*LeaseRenewResponse, error) {
	return c.leaseClient.RenewLease(ctx, req)
}

// ReleaseLease implements LeaseClient.
func (c *PlatformClient) ReleaseLease(ctx context.Context) error {
	return c.leaseClient.ReleaseLease(ctx)
}

// =============================================================================
// JobClient Implementation
// =============================================================================

// Poll implements JobClient.
func (c *PlatformClient) Poll(ctx context.Context, req *PollRequest) (*PollResponse, error) {
	return c.jobClient.Poll(ctx, req)
}

// AcknowledgeJob implements JobClient.
func (c *PlatformClient) AcknowledgeJob(ctx context.Context, jobID string) error {
	return c.jobClient.AcknowledgeJob(ctx, jobID)
}

// ReportJobResult implements JobClient.
func (c *PlatformClient) ReportJobResult(ctx context.Context, result *JobResult) error {
	return c.jobClient.ReportJobResult(ctx, result)
}

// ReportJobProgress implements JobClient.
func (c *PlatformClient) ReportJobProgress(ctx context.Context, jobID string, progress int, message string) error {
	return c.jobClient.ReportJobProgress(ctx, jobID, progress, message)
}

// =============================================================================
// Interface assertions
// =============================================================================

var _ LeaseClient = (*PlatformClient)(nil)
var _ JobClient = (*PlatformClient)(nil)

// =============================================================================
// Platform Sensor Builder
// =============================================================================

// SensorBuilder provides a fluent API for building a platform sensor.
type SensorBuilder struct {
	config           *ClientConfig
	leaseConfig      *LeaseConfig
	pollerConfig     *PollerConfig
	executor         JobExecutor
	metricsCollector MetricsCollector
	onLeaseExpired   func()
	onJobStarted     func(*JobInfo)
	onJobCompleted   func(*JobInfo, *JobResult)

	// SDK integrations
	resourceConfig *resource.ControllerConfig
	auditConfig    *audit.LoggerConfig
	pipelineConfig *pipeline.PipelineConfig
	uploader       pipeline.Uploader
	chunkConfig    *chunk.Config
	chunkUploader  chunk.Uploader
}

// NewSensorBuilder creates a new SensorBuilder.
func NewSensorBuilder() *SensorBuilder {
	return &SensorBuilder{
		config:       &ClientConfig{},
		leaseConfig:  &LeaseConfig{},
		pollerConfig: &PollerConfig{},
	}
}

// WithCredentials sets the sensor credentials.
func (b *SensorBuilder) WithCredentials(baseURL, apiKey, sensorID string) *SensorBuilder {
	b.config.BaseURL = baseURL
	b.config.APIKey = apiKey
	b.config.SensorID = sensorID
	return b
}

// WithLeaseDuration sets the lease duration.
func (b *SensorBuilder) WithLeaseDuration(d time.Duration) *SensorBuilder {
	b.leaseConfig.LeaseDuration = d
	return b
}

// WithRenewInterval sets the lease renewal interval.
func (b *SensorBuilder) WithRenewInterval(d time.Duration) *SensorBuilder {
	b.leaseConfig.RenewInterval = d
	return b
}

// WithMaxJobs sets the maximum concurrent jobs.
func (b *SensorBuilder) WithMaxJobs(n int) *SensorBuilder {
	b.leaseConfig.MaxJobs = n
	b.pollerConfig.MaxConcurrentJobs = n
	return b
}

// WithPollTimeout sets the poll timeout.
func (b *SensorBuilder) WithPollTimeout(d time.Duration) *SensorBuilder {
	b.config.PollTimeout = d
	b.pollerConfig.PollTimeout = d
	return b
}

// WithCapabilities sets the sensor capabilities.
func (b *SensorBuilder) WithCapabilities(caps ...string) *SensorBuilder {
	b.pollerConfig.Capabilities = caps
	return b
}

// WithExecutor sets the job executor.
func (b *SensorBuilder) WithExecutor(executor JobExecutor) *SensorBuilder {
	b.executor = executor
	return b
}

// WithMetricsCollector sets the metrics collector.
func (b *SensorBuilder) WithMetricsCollector(collector MetricsCollector) *SensorBuilder {
	b.metricsCollector = collector
	return b
}

// OnLeaseExpired sets the callback for lease expiration.
func (b *SensorBuilder) OnLeaseExpired(fn func()) *SensorBuilder {
	b.onLeaseExpired = fn
	return b
}

// OnJobStarted sets the callback for job start.
func (b *SensorBuilder) OnJobStarted(fn func(*JobInfo)) *SensorBuilder {
	b.onJobStarted = fn
	return b
}

// OnJobCompleted sets the callback for job completion.
func (b *SensorBuilder) OnJobCompleted(fn func(*JobInfo, *JobResult)) *SensorBuilder {
	b.onJobCompleted = fn
	return b
}

// WithVerbose enables verbose logging.
func (b *SensorBuilder) WithVerbose(v bool) *SensorBuilder {
	b.config.Verbose = v
	b.leaseConfig.Verbose = v
	b.pollerConfig.Verbose = v
	return b
}

// WithResourceController enables resource throttling with the given config.
// When enabled, jobs will only be accepted when CPU/memory are below thresholds.
func (b *SensorBuilder) WithResourceController(config *resource.ControllerConfig) *SensorBuilder {
	b.resourceConfig = config
	return b
}

// WithAuditLogger enables audit logging with the given config.
// When enabled, all job lifecycle events will be logged.
func (b *SensorBuilder) WithAuditLogger(config *audit.LoggerConfig) *SensorBuilder {
	b.auditConfig = config
	return b
}

// WithPipeline enables the async upload pipeline.
// The pipeline allows scan results to be uploaded asynchronously in the background,
// so scans can complete immediately without waiting for uploads.
func (b *SensorBuilder) WithPipeline(config *pipeline.PipelineConfig, uploader pipeline.Uploader) *SensorBuilder {
	b.pipelineConfig = config
	b.uploader = uploader
	return b
}

// WithChunkManager enables chunked uploads for large reports.
// When enabled, large reports are automatically detected and split into chunks
// for efficient upload. The chunk manager handles compression, storage,
// retry, and background upload.
func (b *SensorBuilder) WithChunkManager(config *chunk.Config, uploader chunk.Uploader) *SensorBuilder {
	b.chunkConfig = config
	b.chunkUploader = uploader
	return b
}

// Build creates a PlatformSensor from the builder configuration.
func (b *SensorBuilder) Build() (*PlatformSensor, error) {
	if b.config.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if b.config.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	if b.config.SensorID == "" {
		return nil, fmt.Errorf("sensor ID is required")
	}
	if b.executor == nil {
		return nil, fmt.Errorf("executor is required")
	}

	// Apply callbacks
	b.leaseConfig.OnLeaseExpired = b.onLeaseExpired
	b.leaseConfig.MetricsCollector = b.metricsCollector
	b.pollerConfig.OnJobStarted = b.onJobStarted
	b.pollerConfig.OnJobCompleted = b.onJobCompleted

	client := NewPlatformClient(b.config)

	leaseManager := NewLeaseManager(client, b.leaseConfig)
	poller := NewJobPoller(client, b.executor, b.pollerConfig)
	poller.SetLeaseManager(leaseManager)

	sensor := &PlatformSensor{
		client:       client,
		leaseManager: leaseManager,
		poller:       poller,
		config:       b.config,
	}

	// Create resource controller if configured
	if b.resourceConfig != nil {
		// Sync verbose setting
		b.resourceConfig.Verbose = b.config.Verbose

		// Sync max concurrent jobs if not set
		if b.resourceConfig.MaxConcurrentJobs <= 0 && b.pollerConfig.MaxConcurrentJobs > 0 {
			b.resourceConfig.MaxConcurrentJobs = b.pollerConfig.MaxConcurrentJobs
		}

		sensor.resourceController = resource.NewController(b.resourceConfig)
		poller.SetResourceController(sensor.resourceController)
	}

	// Create audit logger if configured
	if b.auditConfig != nil {
		// Set sensor ID if not already set
		if b.auditConfig.SensorID == "" {
			b.auditConfig.SensorID = b.config.SensorID
		}
		b.auditConfig.Verbose = b.config.Verbose

		logger, err := audit.NewLogger(b.auditConfig)
		if err != nil {
			return nil, fmt.Errorf("create audit logger: %w", err)
		}
		sensor.auditLogger = logger
		poller.SetAuditLogger(logger)
	}

	// Create upload pipeline if configured
	if b.pipelineConfig != nil && b.uploader != nil {
		b.pipelineConfig.Verbose = b.config.Verbose

		// Wire audit logging to pipeline callbacks
		if sensor.auditLogger != nil {
			originalOnCompleted := b.pipelineConfig.OnCompleted
			b.pipelineConfig.OnCompleted = func(item *pipeline.QueueItem, result *pipeline.Result) {
				sensor.auditLogger.Info(audit.EventUploadCompleted, "Upload completed", map[string]interface{}{
					"queue_item_id":    item.ID,
					"job_id":           item.JobID,
					"findings_created": result.FindingsCreated,
					"assets_created":   result.AssetsCreated,
				})
				if originalOnCompleted != nil {
					originalOnCompleted(item, result)
				}
			}

			originalOnFailed := b.pipelineConfig.OnFailed
			b.pipelineConfig.OnFailed = func(item *pipeline.QueueItem, err error) {
				sensor.auditLogger.Error(audit.EventUploadFailed, "Upload failed", err, map[string]interface{}{
					"queue_item_id": item.ID,
					"job_id":        item.JobID,
					"attempts":      item.Attempts,
				})
				if originalOnFailed != nil {
					originalOnFailed(item, err)
				}
			}
		}

		sensor.uploadPipeline = pipeline.NewPipeline(b.pipelineConfig, b.uploader)
	}

	// Create chunk manager if configured
	if b.chunkConfig != nil {
		chunkMgr, err := chunk.NewManager(b.chunkConfig)
		if err != nil {
			return nil, fmt.Errorf("create chunk manager: %w", err)
		}

		if b.chunkUploader != nil {
			chunkMgr.SetUploader(b.chunkUploader)
		}

		// Set verbose mode
		chunkMgr.SetVerbose(b.config.Verbose)

		// Wire audit logging to chunk callbacks
		if sensor.auditLogger != nil {
			chunkMgr.SetCallbacks(
				// onProgress
				func(p *chunk.Progress) {
					sensor.auditLogger.ChunkUploaded(p.ReportID, p.CompletedChunks, p.TotalChunks, int(p.BytesUploaded))
				},
				// onComplete
				func(reportID string) {
					sensor.auditLogger.Info(audit.EventUploadCompleted, "Chunked upload completed", map[string]interface{}{
						"report_id": reportID,
					})
				},
				// onError
				func(reportID string, err error) {
					sensor.auditLogger.Error(audit.EventChunkFailed, "Chunked upload failed", err, map[string]interface{}{
						"report_id": reportID,
					})
				},
			)
		}

		sensor.chunkManager = chunkMgr
	}

	return sensor, nil
}

// =============================================================================
// Platform Sensor
// =============================================================================

// PlatformSensor represents a fully configured platform sensor.
type PlatformSensor struct {
	client       *PlatformClient
	leaseManager *LeaseManager
	poller       *JobPoller
	config       *ClientConfig

	// SDK integrations
	resourceController *resource.Controller
	auditLogger        *audit.Logger
	uploadPipeline     *pipeline.Pipeline
	chunkManager       *chunk.Manager
}

// Start starts the platform sensor (lease manager + job poller).
func (a *PlatformSensor) Start(ctx context.Context) error {
	if a.config.Verbose {
		fmt.Printf("[sensor] Starting platform sensor %s\n", a.config.SensorID)
	}

	// Start resource controller if configured
	if a.resourceController != nil {
		if err := a.resourceController.Start(ctx); err != nil {
			return fmt.Errorf("start resource controller: %w", err)
		}
		if a.config.Verbose {
			fmt.Printf("[sensor] Resource controller started\n")
		}
	}

	// Start audit logger if configured
	if a.auditLogger != nil {
		a.auditLogger.Start()
		a.auditLogger.Info(audit.EventSensorStart, "Platform sensor starting", map[string]interface{}{
			"sensor_id": a.config.SensorID,
		})
		if a.config.Verbose {
			fmt.Printf("[sensor] Audit logger started\n")
		}
	}

	// Start upload pipeline if configured
	if a.uploadPipeline != nil {
		if err := a.uploadPipeline.Start(ctx); err != nil {
			a.stopHelpers()
			return fmt.Errorf("start upload pipeline: %w", err)
		}
		if a.config.Verbose {
			fmt.Printf("[sensor] Upload pipeline started\n")
		}
	}

	// Start chunk manager if configured
	if a.chunkManager != nil {
		if err := a.chunkManager.Start(ctx); err != nil {
			a.stopHelpers()
			return fmt.Errorf("start chunk manager: %w", err)
		}
		if a.config.Verbose {
			fmt.Printf("[sensor] Chunk manager started\n")
		}
	}

	// Start lease manager
	if err := a.leaseManager.Start(ctx); err != nil {
		a.stopHelpers()
		return fmt.Errorf("start lease manager: %w", err)
	}

	// Start job poller
	if err := a.poller.Start(ctx); err != nil {
		// Stop lease manager if poller fails
		_ = a.leaseManager.Stop(ctx)
		a.stopHelpers()
		return fmt.Errorf("start job poller: %w", err)
	}

	if a.config.Verbose {
		fmt.Printf("[sensor] Platform sensor started\n")
	}

	return nil
}

// stopHelpers stops resource controller, audit logger, pipeline, and chunk manager.
func (a *PlatformSensor) stopHelpers() {
	// Stop pipeline first (wait for pending uploads)
	if a.uploadPipeline != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = a.uploadPipeline.Stop(ctx)
		cancel()
	}

	// Close chunk manager (flushes pending chunks)
	if a.chunkManager != nil {
		a.chunkManager.Close()
	}

	if a.resourceController != nil {
		a.resourceController.Stop()
	}
	if a.auditLogger != nil {
		a.auditLogger.Flush()
		_ = a.auditLogger.Stop()
	}
}

// Stop stops the platform sensor gracefully.
func (a *PlatformSensor) Stop(ctx context.Context, timeout time.Duration) error {
	if a.config.Verbose {
		fmt.Printf("[sensor] Stopping platform sensor...\n")
	}

	// Log sensor stop event
	if a.auditLogger != nil {
		a.auditLogger.Info(audit.EventSensorStop, "Platform sensor stopping", map[string]interface{}{
			"sensor_id": a.config.SensorID,
		})
	}

	// Stop poller first (stop accepting new jobs)
	if err := a.poller.Stop(timeout); err != nil {
		if a.config.Verbose {
			fmt.Printf("[sensor] Warning: poller stop error: %v\n", err)
		}
	}

	// Then release lease
	if err := a.leaseManager.Stop(ctx); err != nil {
		if a.config.Verbose {
			fmt.Printf("[sensor] Warning: lease release error: %v\n", err)
		}
	}

	// Stop helpers (resource controller, audit logger)
	a.stopHelpers()

	if a.config.Verbose {
		fmt.Printf("[sensor] Platform sensor stopped\n")
	}

	return nil
}

// Status returns the current sensor status.
func (a *PlatformSensor) Status() *SensorStatus {
	leaseStatus := a.leaseManager.GetStatus()

	return &SensorStatus{
		SensorID:    a.config.SensorID,
		Running:     leaseStatus.Running,
		Healthy:     leaseStatus.Healthy,
		CurrentJobs: a.poller.CurrentJobCount(),
		LastRenew:   leaseStatus.LastRenewTime,
		LastError:   leaseStatus.LastError,
	}
}

// SensorStatus represents the current sensor status.
type SensorStatus struct {
	SensorID    string
	Running     bool
	Healthy     bool
	CurrentJobs int
	LastRenew   time.Time
	LastError   error

	// Resource status (if controller is enabled)
	ResourceStatus *resource.ControllerStatus
}

// ResourceController returns the resource controller if configured.
func (a *PlatformSensor) ResourceController() *resource.Controller {
	return a.resourceController
}

// AuditLogger returns the audit logger if configured.
func (a *PlatformSensor) AuditLogger() *audit.Logger {
	return a.auditLogger
}

// ExtendedStatus returns the full sensor status including resource metrics.
func (a *PlatformSensor) ExtendedStatus() *SensorStatus {
	status := a.Status()

	if a.resourceController != nil {
		status.ResourceStatus = a.resourceController.GetStatus()
	}

	return status
}

// Pipeline returns the upload pipeline if configured.
func (a *PlatformSensor) Pipeline() *pipeline.Pipeline {
	return a.uploadPipeline
}

// SubmitReport queues a report for async upload via the pipeline.
// Returns immediately after queueing. Use Pipeline().GetStats() to monitor progress.
// Returns an error if the pipeline is not configured.
func (a *PlatformSensor) SubmitReport(report *ctis.Report, opts ...pipeline.SubmitOption) (string, error) {
	if a.uploadPipeline == nil {
		return "", fmt.Errorf("upload pipeline not configured")
	}
	return a.uploadPipeline.Submit(report, opts...)
}

// FlushPipeline waits for all pending uploads to complete.
// Returns an error if the pipeline is not configured or if the context is canceled.
func (a *PlatformSensor) FlushPipeline(ctx context.Context) error {
	if a.uploadPipeline == nil {
		return nil // No pipeline, nothing to flush
	}
	return a.uploadPipeline.Flush(ctx)
}

// PipelineStats returns the current pipeline statistics.
// Returns nil if the pipeline is not configured.
func (a *PlatformSensor) PipelineStats() *pipeline.Stats {
	if a.uploadPipeline == nil {
		return nil
	}
	return a.uploadPipeline.GetStats()
}

// ChunkManager returns the chunk manager if configured.
func (a *PlatformSensor) ChunkManager() *chunk.Manager {
	return a.chunkManager
}

// NeedsChunking checks if a report should be uploaded via chunking.
// Returns false if chunk manager is not configured.
func (a *PlatformSensor) NeedsChunking(report *ctis.Report) bool {
	if a.chunkManager == nil {
		return false
	}
	return a.chunkManager.NeedsChunking(report)
}

// SubmitChunkedReport queues a large report for chunked upload.
// The report will be split into chunks, compressed, and uploaded in the background.
// Returns an error if the chunk manager is not configured.
func (a *PlatformSensor) SubmitChunkedReport(ctx context.Context, report *ctis.Report) (*chunk.Report, error) {
	if a.chunkManager == nil {
		return nil, fmt.Errorf("chunk manager not configured")
	}
	return a.chunkManager.SubmitReport(ctx, report)
}

// SmartSubmitReport automatically chooses between regular upload, pipeline, or chunked upload.
// - Small reports: uploaded directly via pipeline (if configured) or returned for manual upload
// - Large reports: uploaded via chunk manager (if configured)
//
// Returns:
// - For pipeline submissions: (pipelineItemID, nil, nil)
// - For chunked submissions: ("", chunkReport, nil)
// - If neither is configured: ("", nil, error)
func (a *PlatformSensor) SmartSubmitReport(ctx context.Context, report *ctis.Report, opts ...pipeline.SubmitOption) (string, *chunk.Report, error) {
	// Check if report needs chunking
	if a.NeedsChunking(report) {
		if a.chunkManager == nil {
			return "", nil, fmt.Errorf("large report requires chunking but chunk manager not configured")
		}
		chunkReport, err := a.chunkManager.SubmitReport(ctx, report)
		return "", chunkReport, err
	}

	// Use pipeline for smaller reports
	if a.uploadPipeline != nil {
		id, err := a.uploadPipeline.Submit(report, opts...)
		return id, nil, err
	}

	// Neither configured
	return "", nil, fmt.Errorf("no upload mechanism configured (neither pipeline nor chunk manager)")
}
