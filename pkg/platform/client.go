package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/audit"
	"github.com/openctemio/sdk-go/pkg/chunk"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/pipeline"
	"github.com/openctemio/sdk-go/pkg/resource"
)

// ClientConfig configures the PlatformClient.
type ClientConfig struct {
	// BaseURL is the API base URL.
	BaseURL string

	// APIKey is the agent's API key.
	APIKey string

	// AgentID is the agent's ID.
	AgentID string

	// PollTimeout is the long-poll timeout for job polling.
	PollTimeout time.Duration

	// Verbose enables debug logging.
	Verbose bool
}

// PlatformClient provides a unified interface for platform agent operations.
// It implements LeaseClient and JobClient interfaces.
type PlatformClient struct {
	leaseClient LeaseClient
	jobClient   JobClient
	config      *ClientConfig
}

// NewPlatformClient creates a new PlatformClient.
func NewPlatformClient(config *ClientConfig) *PlatformClient {
	if config.PollTimeout == 0 {
		config.PollTimeout = DefaultPollTimeout
	}

	return &PlatformClient{
		leaseClient: NewHTTPLeaseClient(config.BaseURL, config.APIKey, config.AgentID),
		jobClient:   NewHTTPJobClient(config.BaseURL, config.APIKey, config.AgentID, config.PollTimeout),
		config:      config,
	}
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
// Platform Agent Builder
// =============================================================================

// AgentBuilder provides a fluent API for building a platform agent.
type AgentBuilder struct {
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

// NewAgentBuilder creates a new AgentBuilder.
func NewAgentBuilder() *AgentBuilder {
	return &AgentBuilder{
		config:       &ClientConfig{},
		leaseConfig:  &LeaseConfig{},
		pollerConfig: &PollerConfig{},
	}
}

// WithCredentials sets the agent credentials.
func (b *AgentBuilder) WithCredentials(baseURL, apiKey, agentID string) *AgentBuilder {
	b.config.BaseURL = baseURL
	b.config.APIKey = apiKey
	b.config.AgentID = agentID
	return b
}

// WithLeaseDuration sets the lease duration.
func (b *AgentBuilder) WithLeaseDuration(d time.Duration) *AgentBuilder {
	b.leaseConfig.LeaseDuration = d
	return b
}

// WithRenewInterval sets the lease renewal interval.
func (b *AgentBuilder) WithRenewInterval(d time.Duration) *AgentBuilder {
	b.leaseConfig.RenewInterval = d
	return b
}

// WithMaxJobs sets the maximum concurrent jobs.
func (b *AgentBuilder) WithMaxJobs(n int) *AgentBuilder {
	b.leaseConfig.MaxJobs = n
	b.pollerConfig.MaxConcurrentJobs = n
	return b
}

// WithPollTimeout sets the poll timeout.
func (b *AgentBuilder) WithPollTimeout(d time.Duration) *AgentBuilder {
	b.config.PollTimeout = d
	b.pollerConfig.PollTimeout = d
	return b
}

// WithCapabilities sets the agent capabilities.
func (b *AgentBuilder) WithCapabilities(caps ...string) *AgentBuilder {
	b.pollerConfig.Capabilities = caps
	return b
}

// WithExecutor sets the job executor.
func (b *AgentBuilder) WithExecutor(executor JobExecutor) *AgentBuilder {
	b.executor = executor
	return b
}

// WithMetricsCollector sets the metrics collector.
func (b *AgentBuilder) WithMetricsCollector(collector MetricsCollector) *AgentBuilder {
	b.metricsCollector = collector
	return b
}

// OnLeaseExpired sets the callback for lease expiration.
func (b *AgentBuilder) OnLeaseExpired(fn func()) *AgentBuilder {
	b.onLeaseExpired = fn
	return b
}

// OnJobStarted sets the callback for job start.
func (b *AgentBuilder) OnJobStarted(fn func(*JobInfo)) *AgentBuilder {
	b.onJobStarted = fn
	return b
}

// OnJobCompleted sets the callback for job completion.
func (b *AgentBuilder) OnJobCompleted(fn func(*JobInfo, *JobResult)) *AgentBuilder {
	b.onJobCompleted = fn
	return b
}

// WithVerbose enables verbose logging.
func (b *AgentBuilder) WithVerbose(v bool) *AgentBuilder {
	b.config.Verbose = v
	b.leaseConfig.Verbose = v
	b.pollerConfig.Verbose = v
	return b
}

// WithResourceController enables resource throttling with the given config.
// When enabled, jobs will only be accepted when CPU/memory are below thresholds.
func (b *AgentBuilder) WithResourceController(config *resource.ControllerConfig) *AgentBuilder {
	b.resourceConfig = config
	return b
}

// WithAuditLogger enables audit logging with the given config.
// When enabled, all job lifecycle events will be logged.
func (b *AgentBuilder) WithAuditLogger(config *audit.LoggerConfig) *AgentBuilder {
	b.auditConfig = config
	return b
}

// WithPipeline enables the async upload pipeline.
// The pipeline allows scan results to be uploaded asynchronously in the background,
// so scans can complete immediately without waiting for uploads.
func (b *AgentBuilder) WithPipeline(config *pipeline.PipelineConfig, uploader pipeline.Uploader) *AgentBuilder {
	b.pipelineConfig = config
	b.uploader = uploader
	return b
}

// WithChunkManager enables chunked uploads for large reports.
// When enabled, large reports are automatically detected and split into chunks
// for efficient upload. The chunk manager handles compression, storage,
// retry, and background upload.
func (b *AgentBuilder) WithChunkManager(config *chunk.Config, uploader chunk.Uploader) *AgentBuilder {
	b.chunkConfig = config
	b.chunkUploader = uploader
	return b
}

// Build creates a PlatformAgent from the builder configuration.
func (b *AgentBuilder) Build() (*PlatformAgent, error) {
	if b.config.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if b.config.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	if b.config.AgentID == "" {
		return nil, fmt.Errorf("agent ID is required")
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

	agent := &PlatformAgent{
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

		agent.resourceController = resource.NewController(b.resourceConfig)
		poller.SetResourceController(agent.resourceController)
	}

	// Create audit logger if configured
	if b.auditConfig != nil {
		// Set agent ID if not already set
		if b.auditConfig.AgentID == "" {
			b.auditConfig.AgentID = b.config.AgentID
		}
		b.auditConfig.Verbose = b.config.Verbose

		logger, err := audit.NewLogger(b.auditConfig)
		if err != nil {
			return nil, fmt.Errorf("create audit logger: %w", err)
		}
		agent.auditLogger = logger
		poller.SetAuditLogger(logger)
	}

	// Create upload pipeline if configured
	if b.pipelineConfig != nil && b.uploader != nil {
		b.pipelineConfig.Verbose = b.config.Verbose

		// Wire audit logging to pipeline callbacks
		if agent.auditLogger != nil {
			originalOnCompleted := b.pipelineConfig.OnCompleted
			b.pipelineConfig.OnCompleted = func(item *pipeline.QueueItem, result *pipeline.Result) {
				agent.auditLogger.Info(audit.EventUploadCompleted, "Upload completed", map[string]interface{}{
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
				agent.auditLogger.Error(audit.EventUploadFailed, "Upload failed", err, map[string]interface{}{
					"queue_item_id": item.ID,
					"job_id":        item.JobID,
					"attempts":      item.Attempts,
				})
				if originalOnFailed != nil {
					originalOnFailed(item, err)
				}
			}
		}

		agent.uploadPipeline = pipeline.NewPipeline(b.pipelineConfig, b.uploader)
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
		if agent.auditLogger != nil {
			chunkMgr.SetCallbacks(
				// onProgress
				func(p *chunk.Progress) {
					agent.auditLogger.ChunkUploaded(p.ReportID, p.CompletedChunks, p.TotalChunks, int(p.BytesUploaded))
				},
				// onComplete
				func(reportID string) {
					agent.auditLogger.Info(audit.EventUploadCompleted, "Chunked upload completed", map[string]interface{}{
						"report_id": reportID,
					})
				},
				// onError
				func(reportID string, err error) {
					agent.auditLogger.Error(audit.EventChunkFailed, "Chunked upload failed", err, map[string]interface{}{
						"report_id": reportID,
					})
				},
			)
		}

		agent.chunkManager = chunkMgr
	}

	return agent, nil
}

// =============================================================================
// Platform Agent
// =============================================================================

// PlatformAgent represents a fully configured platform agent.
type PlatformAgent struct {
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

// Start starts the platform agent (lease manager + job poller).
func (a *PlatformAgent) Start(ctx context.Context) error {
	if a.config.Verbose {
		fmt.Printf("[agent] Starting platform agent %s\n", a.config.AgentID)
	}

	// Start resource controller if configured
	if a.resourceController != nil {
		if err := a.resourceController.Start(ctx); err != nil {
			return fmt.Errorf("start resource controller: %w", err)
		}
		if a.config.Verbose {
			fmt.Printf("[agent] Resource controller started\n")
		}
	}

	// Start audit logger if configured
	if a.auditLogger != nil {
		a.auditLogger.Start()
		a.auditLogger.Info(audit.EventAgentStart, "Platform agent starting", map[string]interface{}{
			"agent_id": a.config.AgentID,
		})
		if a.config.Verbose {
			fmt.Printf("[agent] Audit logger started\n")
		}
	}

	// Start upload pipeline if configured
	if a.uploadPipeline != nil {
		if err := a.uploadPipeline.Start(ctx); err != nil {
			a.stopHelpers()
			return fmt.Errorf("start upload pipeline: %w", err)
		}
		if a.config.Verbose {
			fmt.Printf("[agent] Upload pipeline started\n")
		}
	}

	// Start chunk manager if configured
	if a.chunkManager != nil {
		if err := a.chunkManager.Start(ctx); err != nil {
			a.stopHelpers()
			return fmt.Errorf("start chunk manager: %w", err)
		}
		if a.config.Verbose {
			fmt.Printf("[agent] Chunk manager started\n")
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
		fmt.Printf("[agent] Platform agent started\n")
	}

	return nil
}

// stopHelpers stops resource controller, audit logger, pipeline, and chunk manager.
func (a *PlatformAgent) stopHelpers() {
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

// Stop stops the platform agent gracefully.
func (a *PlatformAgent) Stop(ctx context.Context, timeout time.Duration) error {
	if a.config.Verbose {
		fmt.Printf("[agent] Stopping platform agent...\n")
	}

	// Log agent stop event
	if a.auditLogger != nil {
		a.auditLogger.Info(audit.EventAgentStop, "Platform agent stopping", map[string]interface{}{
			"agent_id": a.config.AgentID,
		})
	}

	// Stop poller first (stop accepting new jobs)
	if err := a.poller.Stop(timeout); err != nil {
		if a.config.Verbose {
			fmt.Printf("[agent] Warning: poller stop error: %v\n", err)
		}
	}

	// Then release lease
	if err := a.leaseManager.Stop(ctx); err != nil {
		if a.config.Verbose {
			fmt.Printf("[agent] Warning: lease release error: %v\n", err)
		}
	}

	// Stop helpers (resource controller, audit logger)
	a.stopHelpers()

	if a.config.Verbose {
		fmt.Printf("[agent] Platform agent stopped\n")
	}

	return nil
}

// Status returns the current agent status.
func (a *PlatformAgent) Status() *AgentStatus {
	leaseStatus := a.leaseManager.GetStatus()

	return &AgentStatus{
		AgentID:     a.config.AgentID,
		Running:     leaseStatus.Running,
		Healthy:     leaseStatus.Healthy,
		CurrentJobs: a.poller.CurrentJobCount(),
		LastRenew:   leaseStatus.LastRenewTime,
		LastError:   leaseStatus.LastError,
	}
}

// AgentStatus represents the current agent status.
type AgentStatus struct {
	AgentID     string
	Running     bool
	Healthy     bool
	CurrentJobs int
	LastRenew   time.Time
	LastError   error

	// Resource status (if controller is enabled)
	ResourceStatus *resource.ControllerStatus
}

// ResourceController returns the resource controller if configured.
func (a *PlatformAgent) ResourceController() *resource.Controller {
	return a.resourceController
}

// AuditLogger returns the audit logger if configured.
func (a *PlatformAgent) AuditLogger() *audit.Logger {
	return a.auditLogger
}

// ExtendedStatus returns the full agent status including resource metrics.
func (a *PlatformAgent) ExtendedStatus() *AgentStatus {
	status := a.Status()

	if a.resourceController != nil {
		status.ResourceStatus = a.resourceController.GetStatus()
	}

	return status
}

// Pipeline returns the upload pipeline if configured.
func (a *PlatformAgent) Pipeline() *pipeline.Pipeline {
	return a.uploadPipeline
}

// SubmitReport queues a report for async upload via the pipeline.
// Returns immediately after queueing. Use Pipeline().GetStats() to monitor progress.
// Returns an error if the pipeline is not configured.
func (a *PlatformAgent) SubmitReport(report *ctis.Report, opts ...pipeline.SubmitOption) (string, error) {
	if a.uploadPipeline == nil {
		return "", fmt.Errorf("upload pipeline not configured")
	}
	return a.uploadPipeline.Submit(report, opts...)
}

// FlushPipeline waits for all pending uploads to complete.
// Returns an error if the pipeline is not configured or if the context is canceled.
func (a *PlatformAgent) FlushPipeline(ctx context.Context) error {
	if a.uploadPipeline == nil {
		return nil // No pipeline, nothing to flush
	}
	return a.uploadPipeline.Flush(ctx)
}

// PipelineStats returns the current pipeline statistics.
// Returns nil if the pipeline is not configured.
func (a *PlatformAgent) PipelineStats() *pipeline.Stats {
	if a.uploadPipeline == nil {
		return nil
	}
	return a.uploadPipeline.GetStats()
}

// ChunkManager returns the chunk manager if configured.
func (a *PlatformAgent) ChunkManager() *chunk.Manager {
	return a.chunkManager
}

// NeedsChunking checks if a report should be uploaded via chunking.
// Returns false if chunk manager is not configured.
func (a *PlatformAgent) NeedsChunking(report *ctis.Report) bool {
	if a.chunkManager == nil {
		return false
	}
	return a.chunkManager.NeedsChunking(report)
}

// SubmitChunkedReport queues a large report for chunked upload.
// The report will be split into chunks, compressed, and uploaded in the background.
// Returns an error if the chunk manager is not configured.
func (a *PlatformAgent) SubmitChunkedReport(ctx context.Context, report *ctis.Report) (*chunk.Report, error) {
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
func (a *PlatformAgent) SmartSubmitReport(ctx context.Context, report *ctis.Report, opts ...pipeline.SubmitOption) (string, *chunk.Report, error) {
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
