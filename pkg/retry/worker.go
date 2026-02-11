// Package retry provides persistent retry queue functionality for failed API operations.
package retry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ReportPusher is the interface for pushing reports to the server.
// This is typically implemented by the Client.
type ReportPusher interface {
	// PushReport pushes a CTIS report to the server.
	PushReport(ctx context.Context, report *ctis.Report) error
}

// FingerprintChecker is the interface for checking if fingerprints already exist on the server.
// This is used by the retry worker to avoid re-uploading data that already exists.
type FingerprintChecker interface {
	// CheckFingerprints checks which fingerprints already exist on the server.
	// Returns two slices: existing fingerprints and missing fingerprints.
	CheckFingerprints(ctx context.Context, fingerprints []string) (*FingerprintCheckResult, error)
}

// FingerprintCheckResult contains the result of a fingerprint check.
type FingerprintCheckResult struct {
	Existing []string // Fingerprints that already exist on the server
	Missing  []string // Fingerprints that don't exist on the server
}

// SmartPusher combines ReportPusher with FingerprintChecker for intelligent retry.
// If the pusher also implements FingerprintChecker, the retry worker will
// check fingerprints before uploading to avoid duplicate uploads.
type SmartPusher interface {
	ReportPusher
	FingerprintChecker
}

// RetryWorker processes the retry queue in the background.
// It periodically checks the queue for items ready to retry and
// attempts to push them to the server.
type RetryWorker struct {
	queue   RetryQueue
	pusher  ReportPusher
	backoff *BackoffConfig

	// Configuration
	interval    time.Duration
	batchSize   int
	maxAttempts int
	ttl         time.Duration

	// State
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex

	// Callbacks
	onSuccess func(item *QueueItem, result *RetryResult)
	onFail    func(item *QueueItem, result *RetryResult)
	onExhaust func(item *QueueItem) // Called when item exhausts all retries

	// Statistics
	stats   WorkerStats
	statsMu sync.RWMutex

	verbose bool
}

// WorkerStats contains statistics about the retry worker.
type WorkerStats struct {
	// Lifetime statistics
	TotalAttempts   int64         `json:"total_attempts"`
	SuccessfulPush  int64         `json:"successful_pushes"`
	FailedAttempts  int64         `json:"failed_attempts"`
	ExhaustedItems  int64         `json:"exhausted_items"`
	TotalDuration   time.Duration `json:"total_duration"`
	LastProcessedAt time.Time     `json:"last_processed_at"`

	// Current state
	IsRunning   bool      `json:"is_running"`
	StartedAt   time.Time `json:"started_at"`
	LastCheckAt time.Time `json:"last_check_at"`
}

// RetryWorkerConfig configures the retry worker.
type RetryWorkerConfig struct {
	// Interval is how often to check the queue for items to retry.
	// Default: 5 minutes
	Interval time.Duration `yaml:"interval" json:"interval"`

	// BatchSize is the maximum number of items to process per check.
	// Default: 10
	BatchSize int `yaml:"batch_size" json:"batch_size"`

	// MaxAttempts is the maximum number of retry attempts per item.
	// Default: 10
	MaxAttempts int `yaml:"max_attempts" json:"max_attempts"`

	// TTL is how long to keep items in the queue before expiring.
	// Default: 7 days
	TTL time.Duration `yaml:"ttl" json:"ttl"`

	// Backoff configures the retry backoff behavior.
	// Default: exponential backoff with 5-minute base
	Backoff *BackoffConfig `yaml:"backoff" json:"backoff"`

	// Verbose enables verbose logging.
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// DefaultRetryWorkerConfig returns a configuration with default values.
func DefaultRetryWorkerConfig() *RetryWorkerConfig {
	return &RetryWorkerConfig{
		Interval:    DefaultRetryInterval,
		BatchSize:   DefaultBatchSize,
		MaxAttempts: DefaultMaxAttempts,
		TTL:         DefaultTTL,
		Backoff:     DefaultBackoffConfig(),
		Verbose:     false,
	}
}

// NewRetryWorker creates a new retry worker.
func NewRetryWorker(cfg *RetryWorkerConfig, queue RetryQueue, pusher ReportPusher) *RetryWorker {
	if cfg == nil {
		cfg = DefaultRetryWorkerConfig()
	}

	// Apply defaults
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultRetryInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Backoff == nil {
		cfg.Backoff = DefaultBackoffConfig()
	}

	return &RetryWorker{
		queue:       queue,
		pusher:      pusher,
		backoff:     cfg.Backoff,
		interval:    cfg.Interval,
		batchSize:   cfg.BatchSize,
		maxAttempts: cfg.MaxAttempts,
		ttl:         cfg.TTL,
		stopCh:      make(chan struct{}),
		verbose:     cfg.Verbose,
	}
}

// Start starts the background retry worker.
// It returns immediately and processes the queue in a goroutine.
func (w *RetryWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return fmt.Errorf("worker is already running")
	}

	w.running = true
	w.stopCh = make(chan struct{})

	w.statsMu.Lock()
	w.stats.IsRunning = true
	w.stats.StartedAt = time.Now()
	w.statsMu.Unlock()

	w.wg.Add(1)
	go w.run(ctx)

	if w.verbose {
		fmt.Printf("[retry-worker] Started (interval: %v, batch: %d, max attempts: %d)\n",
			w.interval, w.batchSize, w.maxAttempts)
	}

	return nil
}

// Stop stops the background retry worker gracefully.
// It waits for the current batch to complete.
func (w *RetryWorker) Stop(ctx context.Context) error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	close(w.stopCh)
	w.mu.Unlock()

	// Wait for worker to finish with timeout
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if w.verbose {
			fmt.Printf("[retry-worker] Stopped gracefully\n")
		}
	case <-ctx.Done():
		return fmt.Errorf("stop timed out: %w", ctx.Err())
	}

	w.statsMu.Lock()
	w.stats.IsRunning = false
	w.statsMu.Unlock()

	return nil
}

// IsRunning returns true if the worker is currently running.
func (w *RetryWorker) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

// Stats returns the current worker statistics.
func (w *RetryWorker) Stats() WorkerStats {
	w.statsMu.RLock()
	defer w.statsMu.RUnlock()
	return w.stats
}

// ProcessNow immediately processes the queue (for testing or manual triggers).
// This is a synchronous operation.
func (w *RetryWorker) ProcessNow(ctx context.Context) error {
	return w.processBatch(ctx)
}

// OnSuccess sets a callback to be called after each successful retry.
func (w *RetryWorker) OnSuccess(fn func(item *QueueItem, result *RetryResult)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onSuccess = fn
}

// OnFail sets a callback to be called after each failed retry.
func (w *RetryWorker) OnFail(fn func(item *QueueItem, result *RetryResult)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onFail = fn
}

// OnExhaust sets a callback to be called when an item exhausts all retries.
func (w *RetryWorker) OnExhaust(fn func(item *QueueItem)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onExhaust = fn
}

// run is the main worker loop.
func (w *RetryWorker) run(ctx context.Context) {
	defer w.wg.Done()

	// Create a ticker for periodic processing
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Process immediately on start
	if err := w.processBatch(ctx); err != nil {
		if w.verbose {
			fmt.Printf("[retry-worker] Initial batch error: %v\n", err)
		}
	}

	// Periodic cleanup
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.processBatch(ctx); err != nil {
				if w.verbose {
					fmt.Printf("[retry-worker] Batch error: %v\n", err)
				}
			}
		case <-cleanupTicker.C:
			if removed, err := w.queue.Cleanup(ctx, w.ttl); err != nil {
				if w.verbose {
					fmt.Printf("[retry-worker] Cleanup error: %v\n", err)
				}
			} else if removed > 0 && w.verbose {
				fmt.Printf("[retry-worker] Cleaned up %d expired items\n", removed)
			}
		}
	}
}

// processBatch processes a batch of items from the queue.
func (w *RetryWorker) processBatch(ctx context.Context) error {
	w.statsMu.Lock()
	w.stats.LastCheckAt = time.Now()
	w.statsMu.Unlock()

	// Get items ready for retry
	items, err := w.queue.Peek(ctx, w.batchSize)
	if err != nil {
		return fmt.Errorf("failed to peek queue: %w", err)
	}

	if len(items) == 0 {
		return nil
	}

	if w.verbose {
		fmt.Printf("[retry-worker] Processing %d items\n", len(items))
	}

	// Check if pusher supports fingerprint checking (connectivity + dedup check)
	var existingFingerprints map[string]bool
	if checker, ok := w.pusher.(FingerprintChecker); ok {
		existingFingerprints, err = w.checkFingerprintsBatch(ctx, checker, items)
		if err != nil {
			// If fingerprint check fails, it likely means connectivity issue
			// Skip this batch and wait for next interval
			if w.verbose {
				fmt.Printf("[retry-worker] Connectivity check failed, skipping batch: %v\n", err)
			}
			return nil // Don't return error to avoid noise in logs
		}
	}

	for _, item := range items {
		select {
		case <-w.stopCh:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if this item's fingerprint already exists on server
		if existingFingerprints != nil && item.Fingerprint != "" {
			if existingFingerprints[item.Fingerprint] {
				// Data already exists on server, mark as success without uploading
				if w.verbose {
					fmt.Printf("[retry-worker] Item %s already exists on server (fingerprint: %s), skipping upload\n",
						item.ID[:8], item.Fingerprint[:16])
				}

				// Remove from queue
				if err := w.queue.Delete(ctx, item.ID); err != nil {
					if w.verbose {
						fmt.Printf("[retry-worker] Failed to delete already-uploaded item %s: %v\n", item.ID[:8], err)
					}
				}

				w.statsMu.Lock()
				w.stats.SuccessfulPush++
				w.stats.LastProcessedAt = time.Now()
				w.statsMu.Unlock()

				// Create a success result for callback
				result := &RetryResult{
					ItemID:    item.ID,
					Attempt:   item.Attempts,
					Success:   true,
					Timestamp: time.Now(),
				}
				if w.onSuccess != nil {
					w.onSuccess(item, result)
				}

				continue
			}
		}

		// Process the item (upload to server)
		result := w.processItem(ctx, item)

		if result.Success {
			// Remove from queue on success
			if err := w.queue.Delete(ctx, item.ID); err != nil {
				if w.verbose {
					fmt.Printf("[retry-worker] Failed to delete successful item %s: %v\n", item.ID[:8], err)
				}
			}

			w.statsMu.Lock()
			w.stats.SuccessfulPush++
			w.stats.LastProcessedAt = time.Now()
			w.statsMu.Unlock()

			if w.onSuccess != nil {
				w.onSuccess(item, result)
			}

			if w.verbose {
				fmt.Printf("[retry-worker] Successfully pushed item %s (attempt %d)\n",
					item.ID[:8], result.Attempt)
			}
		} else {
			// Update item for next retry
			item.Attempts++
			item.LastError = result.Error
			item.LastAttempt = result.Timestamp

			if item.HasExhaustedRetries() || item.Attempts >= w.maxAttempts {
				// Mark as permanently failed
				if err := w.queue.MarkFailed(ctx, item.ID, result.Error); err != nil {
					if w.verbose {
						fmt.Printf("[retry-worker] Failed to mark item %s as failed: %v\n", item.ID[:8], err)
					}
				}

				w.statsMu.Lock()
				w.stats.ExhaustedItems++
				w.statsMu.Unlock()

				if w.onExhaust != nil {
					w.onExhaust(item)
				}

				if w.verbose {
					fmt.Printf("[retry-worker] Item %s exhausted all retries (%d attempts)\n",
						item.ID[:8], item.Attempts)
				}
			} else {
				// Schedule next retry
				nextRetry := w.backoff.NextRetry(item.Attempts)
				if err := w.queue.Requeue(ctx, item.ID, nextRetry); err != nil {
					if w.verbose {
						fmt.Printf("[retry-worker] Failed to requeue item %s: %v\n", item.ID[:8], err)
					}
				}

				if w.verbose {
					fmt.Printf("[retry-worker] Item %s scheduled for retry at %v (attempt %d/%d)\n",
						item.ID[:8], nextRetry.Format(time.RFC3339), item.Attempts, w.maxAttempts)
				}
			}

			w.statsMu.Lock()
			w.stats.FailedAttempts++
			w.statsMu.Unlock()

			if w.onFail != nil {
				w.onFail(item, result)
			}
		}

		w.statsMu.Lock()
		w.stats.TotalAttempts++
		w.stats.TotalDuration += result.Duration
		w.statsMu.Unlock()
	}

	return nil
}

// processItem attempts to push a single item.
func (w *RetryWorker) processItem(ctx context.Context, item *QueueItem) *RetryResult {
	start := time.Now()
	result := &RetryResult{
		ItemID:    item.ID,
		Attempt:   item.Attempts + 1,
		Timestamp: start,
	}

	if item.Report == nil {
		result.Error = "item has no report"
		result.Duration = time.Since(start)
		return result
	}

	// Attempt to push
	err := w.pusher.PushReport(ctx, item.Report)
	result.Duration = time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		result.Success = true
	}

	return result
}

// TriggerCleanup manually triggers a cleanup of expired items.
func (w *RetryWorker) TriggerCleanup(ctx context.Context) (int, error) {
	return w.queue.Cleanup(ctx, w.ttl)
}

// QueueStats returns the current queue statistics.
func (w *RetryWorker) QueueStats(ctx context.Context) (*QueueStats, error) {
	return w.queue.Stats(ctx)
}

// checkFingerprintsBatch checks which fingerprints from the batch already exist on the server.
// This serves two purposes:
// 1. Connectivity check - if this fails, we know the server is unreachable
// 2. Deduplication - skip uploading data that already exists
// Returns a map of fingerprint -> exists (true if already on server)
func (w *RetryWorker) checkFingerprintsBatch(ctx context.Context, checker FingerprintChecker, items []*QueueItem) (map[string]bool, error) {
	// Collect unique fingerprints from items
	fingerprints := make([]string, 0, len(items))
	seen := make(map[string]bool)

	for _, item := range items {
		if item.Fingerprint != "" && !seen[item.Fingerprint] {
			fingerprints = append(fingerprints, item.Fingerprint)
			seen[item.Fingerprint] = true
		}
	}

	if len(fingerprints) == 0 {
		// No fingerprints to check, return empty map
		return map[string]bool{}, nil
	}

	if w.verbose {
		fmt.Printf("[retry-worker] Checking %d fingerprints with server...\n", len(fingerprints))
	}

	// Check fingerprints with server
	result, err := checker.CheckFingerprints(ctx, fingerprints)
	if err != nil {
		return nil, fmt.Errorf("fingerprint check failed: %w", err)
	}

	// Build result map
	existingMap := make(map[string]bool, len(fingerprints))
	for _, fp := range result.Existing {
		existingMap[fp] = true
	}

	if w.verbose && len(result.Existing) > 0 {
		fmt.Printf("[retry-worker] Found %d items already on server, %d need upload\n",
			len(result.Existing), len(result.Missing))
	}

	return existingMap, nil
}
