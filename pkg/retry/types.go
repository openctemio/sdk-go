// Package retry provides persistent retry queue functionality for failed API operations.
//
// The retry package implements a store-and-forward pattern to ensure that scan data
// is never lost due to temporary network failures or server unavailability.
//
// Key components:
//   - RetryQueue: Interface for queue implementations
//   - FileRetryQueue: File-based persistent queue (no external dependencies)
//   - RetryWorker: Background processor that retries queued items
//
// Example usage:
//
//	queue, _ := retry.NewFileRetryQueue(&retry.FileQueueConfig{
//	    Dir: "/var/lib/openctem/retry-queue",
//	})
//
//	worker := retry.NewRetryWorker(&retry.RetryWorkerConfig{
//	    Interval: 5 * time.Minute,
//	}, queue, pusher)
//
//	worker.Start(ctx)
//	defer worker.Stop(ctx)
package retry

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ItemType defines the type of queued item.
type ItemType string

const (
	// ItemTypeFindings represents scan findings to be pushed.
	ItemTypeFindings ItemType = "findings"

	// ItemTypeAssets represents assets to be pushed.
	ItemTypeAssets ItemType = "assets"

	// ItemTypeHeartbeat represents a heartbeat message.
	ItemTypeHeartbeat ItemType = "heartbeat"
)

// ItemStatus represents the status of a queue item.
type ItemStatus string

const (
	// ItemStatusPending indicates the item is waiting for retry.
	ItemStatusPending ItemStatus = "pending"

	// ItemStatusProcessing indicates the item is currently being processed.
	ItemStatusProcessing ItemStatus = "processing"

	// ItemStatusFailed indicates the item has exhausted all retry attempts.
	ItemStatusFailed ItemStatus = "failed"
)

// QueueItem represents an item in the retry queue.
type QueueItem struct {
	// Identification
	ID          string     `json:"id"`          // Unique identifier (UUID)
	Type        ItemType   `json:"type"`        // Type of item (findings, assets, heartbeat)
	Fingerprint string     `json:"fingerprint"` // Content fingerprint for deduplication
	Status      ItemStatus `json:"status"`      // Current status

	// Payload
	Report *ctis.Report `json:"report"` // The CTIS report to push

	// Retry tracking
	Attempts    int       `json:"attempts"`     // Number of retry attempts made
	MaxAttempts int       `json:"max_attempts"` // Maximum retry attempts allowed
	LastError   string    `json:"last_error"`   // Last error message
	LastAttempt time.Time `json:"last_attempt"` // Timestamp of last attempt
	NextRetry   time.Time `json:"next_retry"`   // Scheduled next retry time

	// Metadata
	CreatedAt   time.Time `json:"created_at"`   // When item was first queued
	UpdatedAt   time.Time `json:"updated_at"`   // Last update timestamp
	AgentID     string    `json:"agent_id"`     // Source agent ID
	ScannerName string    `json:"scanner_name"` // Source scanner name
	TargetPath  string    `json:"target_path"`  // Scan target path
}

// IsExpired checks if the item has exceeded its TTL.
func (item *QueueItem) IsExpired(ttl time.Duration) bool {
	return time.Since(item.CreatedAt) > ttl
}

// IsReadyForRetry checks if the item is ready to be retried.
func (item *QueueItem) IsReadyForRetry() bool {
	return item.Status == ItemStatusPending && time.Now().After(item.NextRetry)
}

// HasExhaustedRetries checks if the item has used all retry attempts.
func (item *QueueItem) HasExhaustedRetries() bool {
	return item.Attempts >= item.MaxAttempts
}

// QueueStats provides statistics about the retry queue.
type QueueStats struct {
	TotalItems      int       `json:"total_items"`       // Total items in queue
	PendingItems    int       `json:"pending_items"`     // Items waiting for retry
	ProcessingItems int       `json:"processing_items"`  // Items currently being processed
	FailedItems     int       `json:"failed_items"`      // Items that exhausted retries
	OldestItem      time.Time `json:"oldest_item"`       // Creation time of oldest item
	NewestItem      time.Time `json:"newest_item"`       // Creation time of newest item
	LastRetry       time.Time `json:"last_retry"`        // Last retry attempt time
	TotalRetries    int64     `json:"total_retries"`     // Total retry attempts made
	SuccessfulPush  int64     `json:"successful_pushes"` // Successful pushes from retry
}

// RetryResult represents the result of a retry operation.
type RetryResult struct {
	ItemID    string        `json:"item_id"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Attempt   int           `json:"attempt"`
	Timestamp time.Time     `json:"timestamp"`
}

// DefaultMaxAttempts is the default maximum number of retry attempts.
const DefaultMaxAttempts = 10

// DefaultTTL is the default time-to-live for queue items (7 days).
const DefaultTTL = 7 * 24 * time.Hour

// DefaultRetryInterval is the default interval between retry checks.
const DefaultRetryInterval = 5 * time.Minute

// DefaultBatchSize is the default number of items to process per batch.
const DefaultBatchSize = 10

// DefaultMaxQueueSize is the default maximum number of items in the queue.
const DefaultMaxQueueSize = 1000
