// Package retry provides persistent retry queue functionality for failed API operations.
package retry

import (
	"context"
	"errors"
	"time"
)

// Common errors for retry queue operations.
var (
	// ErrQueueFull is returned when the queue has reached its maximum capacity.
	ErrQueueFull = errors.New("retry queue is full")

	// ErrQueueClosed is returned when operations are attempted on a closed queue.
	ErrQueueClosed = errors.New("retry queue is closed")

	// ErrItemNotFound is returned when the requested item doesn't exist.
	ErrItemNotFound = errors.New("queue item not found")

	// ErrDuplicateItem is returned when attempting to enqueue a duplicate item.
	ErrDuplicateItem = errors.New("duplicate item already in queue")

	// ErrInvalidItem is returned when the queue item is invalid.
	ErrInvalidItem = errors.New("invalid queue item")
)

// RetryQueue defines the interface for retry queue implementations.
// Implementations must be safe for concurrent use.
type RetryQueue interface {
	// Enqueue adds an item to the queue.
	// Returns the item ID on success.
	// Returns ErrQueueFull if the queue has reached its maximum capacity.
	// Returns ErrDuplicateItem if an item with the same fingerprint exists.
	Enqueue(ctx context.Context, item *QueueItem) (string, error)

	// Dequeue removes and returns the next item ready for retry.
	// Returns nil, nil if no items are ready for retry.
	// The item's status should be set to ItemStatusProcessing.
	Dequeue(ctx context.Context) (*QueueItem, error)

	// Peek returns items ready for retry without removing them.
	// Items are returned in order of priority (oldest NextRetry first).
	Peek(ctx context.Context, limit int) ([]*QueueItem, error)

	// Get retrieves an item by ID without removing it.
	// Returns ErrItemNotFound if the item doesn't exist.
	Get(ctx context.Context, id string) (*QueueItem, error)

	// Update updates an existing item in the queue.
	// Typically called after a retry attempt to update attempt count, error, etc.
	// Returns ErrItemNotFound if the item doesn't exist.
	Update(ctx context.Context, item *QueueItem) error

	// Delete removes an item from the queue.
	// Typically called after successful push or when item should be discarded.
	// Returns ErrItemNotFound if the item doesn't exist.
	Delete(ctx context.Context, id string) error

	// MarkFailed marks an item as permanently failed.
	// Called when an item has exhausted all retry attempts.
	MarkFailed(ctx context.Context, id string, lastError string) error

	// Requeue moves an item back to pending status for retry.
	// Called when a processing item needs to be retried.
	Requeue(ctx context.Context, id string, nextRetry time.Time) error

	// Size returns the total number of items in the queue.
	Size(ctx context.Context) (int, error)

	// Stats returns detailed statistics about the queue.
	Stats(ctx context.Context) (*QueueStats, error)

	// Cleanup removes expired items (older than TTL) and permanently failed items.
	// Returns the number of items removed.
	Cleanup(ctx context.Context, ttl time.Duration) (int, error)

	// List returns items matching the given filter.
	List(ctx context.Context, filter ListFilter) ([]*QueueItem, error)

	// Close closes the queue and releases any resources.
	// After Close is called, all other methods should return ErrQueueClosed.
	Close() error
}

// ListFilter defines options for filtering queue items.
type ListFilter struct {
	// Status filters by item status. Empty means all statuses.
	Status ItemStatus

	// Type filters by item type. Empty means all types.
	Type ItemType

	// Limit is the maximum number of items to return. 0 means no limit.
	Limit int

	// Offset is the number of items to skip. Used for pagination.
	Offset int

	// ReadyOnly if true, only returns items ready for retry (NextRetry <= now).
	ReadyOnly bool

	// OrderBy specifies the field to order by. Default is "created_at".
	OrderBy string

	// OrderDesc if true, orders in descending order.
	OrderDesc bool
}

// Pusher is the interface that wraps the basic Push method.
// This is used by RetryWorker to push items to the server.
type Pusher interface {
	// PushReport pushes a report to the server.
	// Returns nil on success.
	PushReport(ctx context.Context, report any) error
}

// RetryCallback is a function called after each retry attempt.
type RetryCallback func(result *RetryResult)

// QueueConfig contains common configuration for queue implementations.
type QueueConfig struct {
	// MaxSize is the maximum number of items allowed in the queue.
	// Default is DefaultMaxQueueSize (1000).
	MaxSize int

	// Deduplication enables fingerprint-based deduplication.
	// Default is true.
	Deduplication bool

	// Verbose enables verbose logging.
	Verbose bool
}

// DefaultQueueConfig returns a QueueConfig with default values.
func DefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		MaxSize:       DefaultMaxQueueSize,
		Deduplication: true,
		Verbose:       false,
	}
}

// Validate validates the queue configuration.
func (c *QueueConfig) Validate() error {
	if c.MaxSize <= 0 {
		c.MaxSize = DefaultMaxQueueSize
	}
	return nil
}
