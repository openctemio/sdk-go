// Package pipeline provides async pipeline for separating scan and upload.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Result represents an upload result.
type Result struct {
	ID              string    `json:"id"`
	ReportID        string    `json:"report_id"`
	Status          string    `json:"status"` // pending, uploading, completed, failed
	FindingsCreated int       `json:"findings_created"`
	AssetsCreated   int       `json:"assets_created"`
	Error           string    `json:"error,omitempty"`
	SubmittedAt     time.Time `json:"submitted_at"`
	CompletedAt     time.Time `json:"completed_at,omitempty"`
	DurationMs      int64     `json:"duration_ms,omitempty"`
}

// Uploader is the interface for uploading reports.
type Uploader interface {
	Upload(ctx context.Context, report *ctis.Report) (*Result, error)
}

// PipelineConfig configures the upload pipeline.
type PipelineConfig struct {
	// QueueSize is the maximum number of pending uploads.
	// Default: 1000
	QueueSize int

	// Workers is the number of concurrent upload workers.
	// Default: 3
	Workers int

	// RetryAttempts is the number of retry attempts for failed uploads.
	// Default: 3
	RetryAttempts int

	// RetryDelay is the base delay between retries.
	// Default: 5 seconds (exponential backoff applied)
	RetryDelay time.Duration

	// UploadTimeout is the timeout for each upload attempt.
	// Default: 2 minutes
	UploadTimeout time.Duration

	// OnSubmitted is called when a report is queued.
	OnSubmitted func(item *QueueItem)

	// OnCompleted is called when an upload completes.
	OnCompleted func(item *QueueItem, result *Result)

	// OnFailed is called when an upload fails after all retries.
	OnFailed func(item *QueueItem, err error)

	// Verbose enables debug logging.
	Verbose bool
}

// DefaultPipelineConfig returns sensible defaults.
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		QueueSize:     1000,
		Workers:       3,
		RetryAttempts: 3,
		RetryDelay:    5 * time.Second,
		UploadTimeout: 2 * time.Minute,
	}
}

// QueueItem represents a pending upload.
type QueueItem struct {
	ID          string       `json:"id"`
	Report      *ctis.Report `json:"-"` // Not serialized
	ReportJSON  []byte       `json:"report_json,omitempty"`
	JobID       string       `json:"job_id,omitempty"`
	TenantID    string       `json:"tenant_id,omitempty"`
	ToolName    string       `json:"tool_name"`
	SubmittedAt time.Time    `json:"submitted_at"`
	Attempts    int          `json:"attempts"`
	LastError   string       `json:"last_error,omitempty"`
	Priority    int          `json:"priority"` // Higher = more urgent
}

// Pipeline manages async upload of scan results.
// This allows scans to complete immediately while uploads happen in background.
type Pipeline struct {
	config   *PipelineConfig
	uploader Uploader

	queue chan *QueueItem

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Stats
	submitted  int64
	completed  int64
	failed     int64
	inProgress int32
	totalBytes int64
}

// NewPipeline creates a new upload pipeline.
func NewPipeline(config *PipelineConfig, uploader Uploader) *Pipeline {
	if config == nil {
		config = DefaultPipelineConfig()
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 1000
	}
	if config.Workers <= 0 {
		config.Workers = 3
	}
	if config.RetryAttempts <= 0 {
		config.RetryAttempts = 3
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.UploadTimeout <= 0 {
		config.UploadTimeout = 2 * time.Minute
	}

	return &Pipeline{
		config:   config,
		uploader: uploader,
		queue:    make(chan *QueueItem, config.QueueSize),
		stopCh:   make(chan struct{}),
	}
}

// Start begins the upload workers.
func (p *Pipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = true
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	// Start workers
	for i := 0; i < p.config.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	if p.config.Verbose {
		fmt.Printf("[pipeline] Started with %d workers, queue size %d\n",
			p.config.Workers, p.config.QueueSize)
	}

	return nil
}

// Stop gracefully stops the pipeline.
// Waits for in-progress uploads to complete.
func (p *Pipeline) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	close(p.stopCh)
	p.mu.Unlock()

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if p.config.Verbose {
			fmt.Printf("[pipeline] Stopped gracefully\n")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Submit queues a report for async upload.
// Returns immediately after queueing.
func (p *Pipeline) Submit(report *ctis.Report, opts ...SubmitOption) (string, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()

	if !running {
		return "", fmt.Errorf("pipeline not running")
	}

	item := &QueueItem{
		ID:          generateID(),
		Report:      report,
		SubmittedAt: time.Now(),
	}

	// Apply options
	for _, opt := range opts {
		opt(item)
	}

	// Get tool name from report
	if report.Tool != nil {
		item.ToolName = report.Tool.Name
	}

	// Calculate report size
	if reportJSON, err := json.Marshal(report); err == nil {
		atomic.AddInt64(&p.totalBytes, int64(len(reportJSON)))
	}

	// Try to queue
	select {
	case p.queue <- item:
		atomic.AddInt64(&p.submitted, 1)

		if p.config.OnSubmitted != nil {
			p.config.OnSubmitted(item)
		}

		if p.config.Verbose {
			fmt.Printf("[pipeline] Report %s queued (tool=%s, findings=%d)\n",
				item.ID, item.ToolName, len(report.Findings))
		}

		return item.ID, nil
	default:
		return "", fmt.Errorf("queue full (size=%d)", p.config.QueueSize)
	}
}

// SubmitOption is an option for Submit.
type SubmitOption func(*QueueItem)

// WithJobID sets the job ID for tracking.
func WithJobID(jobID string) SubmitOption {
	return func(item *QueueItem) {
		item.JobID = jobID
	}
}

// WithTenantID sets the tenant ID.
func WithTenantID(tenantID string) SubmitOption {
	return func(item *QueueItem) {
		item.TenantID = tenantID
	}
}

// WithPriority sets the priority (higher = more urgent).
func WithPriority(priority int) SubmitOption {
	return func(item *QueueItem) {
		item.Priority = priority
	}
}

// QueueLength returns the current queue length.
func (p *Pipeline) QueueLength() int {
	return len(p.queue)
}

// Stats returns pipeline statistics.
type Stats struct {
	Submitted   int64 `json:"submitted"`
	Completed   int64 `json:"completed"`
	Failed      int64 `json:"failed"`
	InProgress  int   `json:"in_progress"`
	QueueLength int   `json:"queue_length"`
	TotalBytes  int64 `json:"total_bytes"`
}

// GetStats returns current pipeline statistics.
func (p *Pipeline) GetStats() *Stats {
	return &Stats{
		Submitted:   atomic.LoadInt64(&p.submitted),
		Completed:   atomic.LoadInt64(&p.completed),
		Failed:      atomic.LoadInt64(&p.failed),
		InProgress:  int(atomic.LoadInt32(&p.inProgress)),
		QueueLength: len(p.queue),
		TotalBytes:  atomic.LoadInt64(&p.totalBytes),
	}
}

// worker processes upload queue items.
func (p *Pipeline) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	if p.config.Verbose {
		fmt.Printf("[pipeline] Worker %d started\n", id)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			// Drain remaining items before stopping
			for {
				select {
				case item := <-p.queue:
					p.processItem(ctx, item)
				default:
					return
				}
			}
		case item := <-p.queue:
			p.processItem(ctx, item)
		}
	}
}

// processItem handles a single upload.
func (p *Pipeline) processItem(ctx context.Context, item *QueueItem) {
	atomic.AddInt32(&p.inProgress, 1)
	defer atomic.AddInt32(&p.inProgress, -1)

	var lastErr error
	for attempt := 0; attempt <= p.config.RetryAttempts; attempt++ {
		item.Attempts = attempt + 1

		// Apply backoff for retries
		if attempt > 0 {
			// Cap the shift to avoid overflow (max ~32 retries is more than enough)
			shift := min(attempt-1, 30)
			backoff := p.config.RetryDelay * time.Duration(1<<shift) //nolint:gosec // shift is capped
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		// Create context with timeout
		uploadCtx, cancel := context.WithTimeout(ctx, p.config.UploadTimeout)

		result, err := p.uploader.Upload(uploadCtx, item.Report)
		cancel()

		if err == nil {
			// Success
			atomic.AddInt64(&p.completed, 1)

			if p.config.OnCompleted != nil {
				p.config.OnCompleted(item, result)
			}

			if p.config.Verbose {
				fmt.Printf("[pipeline] Upload completed: %s (findings=%d, attempt=%d)\n",
					item.ID, result.FindingsCreated, attempt+1)
			}

			return
		}

		lastErr = err
		item.LastError = err.Error()

		if p.config.Verbose {
			fmt.Printf("[pipeline] Upload failed: %s (attempt %d/%d): %v\n",
				item.ID, attempt+1, p.config.RetryAttempts+1, err)
		}
	}

	// All retries exhausted
	atomic.AddInt64(&p.failed, 1)

	if p.config.OnFailed != nil {
		p.config.OnFailed(item, lastErr)
	}

	if p.config.Verbose {
		fmt.Printf("[pipeline] Upload permanently failed: %s after %d attempts\n",
			item.ID, item.Attempts)
	}
}

// Flush blocks until the queue is empty.
func (p *Pipeline) Flush(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if len(p.queue) == 0 && atomic.LoadInt32(&p.inProgress) == 0 {
				return nil
			}
		}
	}
}

// generateID generates a unique ID.
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())
}
