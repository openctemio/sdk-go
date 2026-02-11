// Package retry provides persistent retry queue functionality for failed API operations.
package retry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FileRetryQueue implements RetryQueue using JSON files.
// Each queue item is stored as a separate JSON file in a directory.
// This provides simplicity, durability, and no external dependencies.
//
// File naming convention: {timestamp}_{id}.json
// This allows natural sorting by creation time when listing files.
type FileRetryQueue struct {
	dir     string
	config  *QueueConfig
	backoff *BackoffConfig

	mu     sync.RWMutex
	closed bool

	// In-memory fingerprint index for fast deduplication
	fingerprints map[string]string // fingerprint -> item ID

	verbose bool
}

// FileQueueConfig configures the file-based retry queue.
type FileQueueConfig struct {
	// Dir is the directory to store queue files.
	// Default: ~/.openctem/retry-queue
	Dir string

	// MaxSize is the maximum number of items in the queue.
	// Default: 1000
	MaxSize int

	// Deduplication enables fingerprint-based deduplication.
	// Default: true
	Deduplication bool

	// Backoff configures the retry backoff behavior.
	// Default: exponential backoff with 5-minute base
	Backoff *BackoffConfig

	// Verbose enables verbose logging.
	Verbose bool
}

// NewFileRetryQueue creates a new file-based retry queue.
func NewFileRetryQueue(cfg *FileQueueConfig) (*FileRetryQueue, error) {
	if cfg == nil {
		cfg = &FileQueueConfig{}
	}

	// Set defaults
	if cfg.Dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		cfg.Dir = filepath.Join(home, ".openctem", "retry-queue")
	}

	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxQueueSize
	}

	if cfg.Backoff == nil {
		cfg.Backoff = DefaultBackoffConfig()
	}

	// Ensure directory exists
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create queue directory: %w", err)
	}

	fq := &FileRetryQueue{
		dir: cfg.Dir,
		config: &QueueConfig{
			MaxSize:       cfg.MaxSize,
			Deduplication: cfg.Deduplication,
			Verbose:       cfg.Verbose,
		},
		backoff:      cfg.Backoff,
		fingerprints: make(map[string]string),
		verbose:      cfg.Verbose,
	}

	// Build fingerprint index from existing files
	if err := fq.buildFingerprintIndex(); err != nil {
		return nil, fmt.Errorf("failed to build fingerprint index: %w", err)
	}

	return fq, nil
}

// buildFingerprintIndex scans existing files and builds the fingerprint index.
func (fq *FileRetryQueue) buildFingerprintIndex() error {
	files, err := fq.listFiles()
	if err != nil {
		return err
	}

	for _, file := range files {
		item, err := fq.readFile(file)
		if err != nil {
			// Skip corrupted files
			if fq.verbose {
				fmt.Printf("[retry] Warning: skipping corrupted file %s: %v\n", file, err)
			}
			continue
		}

		if item.Fingerprint != "" {
			fq.fingerprints[item.Fingerprint] = item.ID
		}
	}

	if fq.verbose {
		fmt.Printf("[retry] Loaded %d items from queue directory\n", len(files))
	}

	return nil
}

// Enqueue adds an item to the queue.
func (fq *FileRetryQueue) Enqueue(ctx context.Context, item *QueueItem) (string, error) {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return "", ErrQueueClosed
	}

	// Validate item
	if item == nil {
		return "", ErrInvalidItem
	}

	// Check queue size
	size, err := fq.sizeUnsafe()
	if err != nil {
		return "", fmt.Errorf("failed to check queue size: %w", err)
	}
	if size >= fq.config.MaxSize {
		return "", ErrQueueFull
	}

	// Generate ID if not set
	if item.ID == "" {
		item.ID = uuid.New().String()
	}

	// Generate fingerprint if not set
	if item.Fingerprint == "" && item.Report != nil {
		item.Fingerprint = fq.generateFingerprint(item)
	}

	// Check for duplicates
	if fq.config.Deduplication && item.Fingerprint != "" {
		if existingID, exists := fq.fingerprints[item.Fingerprint]; exists {
			if fq.verbose {
				fmt.Printf("[retry] Duplicate item rejected (fingerprint: %s, existing: %s)\n",
					item.Fingerprint[:16], existingID[:8])
			}
			return existingID, ErrDuplicateItem
		}
	}

	// Set defaults
	now := time.Now()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now

	if item.Status == "" {
		item.Status = ItemStatusPending
	}

	if item.MaxAttempts <= 0 {
		item.MaxAttempts = DefaultMaxAttempts
	}

	if item.NextRetry.IsZero() {
		item.NextRetry = now // Ready immediately for first attempt
	}

	// Write to file
	if err := fq.writeFile(item); err != nil {
		return "", fmt.Errorf("failed to write queue item: %w", err)
	}

	// Update fingerprint index
	if item.Fingerprint != "" {
		fq.fingerprints[item.Fingerprint] = item.ID
	}

	if fq.verbose {
		fmt.Printf("[retry] Enqueued item %s (type: %s)\n", item.ID[:8], item.Type)
	}

	return item.ID, nil
}

// Dequeue removes and returns the next item ready for retry.
func (fq *FileRetryQueue) Dequeue(ctx context.Context) (*QueueItem, error) {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return nil, ErrQueueClosed
	}

	// Get items ready for retry
	items, err := fq.listReadyItemsUnsafe(1)
	if err != nil {
		return nil, err
	}

	if len(items) == 0 {
		return nil, nil
	}

	item := items[0]

	// Update status to processing
	item.Status = ItemStatusProcessing
	item.UpdatedAt = time.Now()

	if err := fq.writeFile(item); err != nil {
		return nil, fmt.Errorf("failed to update item status: %w", err)
	}

	return item, nil
}

// Peek returns items ready for retry without removing them.
func (fq *FileRetryQueue) Peek(ctx context.Context, limit int) ([]*QueueItem, error) {
	fq.mu.RLock()
	defer fq.mu.RUnlock()

	if fq.closed {
		return nil, ErrQueueClosed
	}

	return fq.listReadyItemsUnsafe(limit)
}

// Get retrieves an item by ID without removing it.
func (fq *FileRetryQueue) Get(ctx context.Context, id string) (*QueueItem, error) {
	fq.mu.RLock()
	defer fq.mu.RUnlock()

	if fq.closed {
		return nil, ErrQueueClosed
	}

	return fq.getByIDUnsafe(id)
}

// Update updates an existing item in the queue.
func (fq *FileRetryQueue) Update(ctx context.Context, item *QueueItem) error {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return ErrQueueClosed
	}

	if item == nil {
		return ErrInvalidItem
	}

	// Check if item exists
	existing, err := fq.getByIDUnsafe(item.ID)
	if err != nil {
		return err
	}

	// Update fingerprint index if changed
	if existing.Fingerprint != item.Fingerprint {
		if existing.Fingerprint != "" {
			delete(fq.fingerprints, existing.Fingerprint)
		}
		if item.Fingerprint != "" {
			fq.fingerprints[item.Fingerprint] = item.ID
		}
	}

	item.UpdatedAt = time.Now()

	return fq.writeFile(item)
}

// Delete removes an item from the queue.
func (fq *FileRetryQueue) Delete(ctx context.Context, id string) error {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return ErrQueueClosed
	}

	return fq.deleteUnsafe(id)
}

// MarkFailed marks an item as permanently failed.
func (fq *FileRetryQueue) MarkFailed(ctx context.Context, id string, lastError string) error {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return ErrQueueClosed
	}

	item, err := fq.getByIDUnsafe(id)
	if err != nil {
		return err
	}

	item.Status = ItemStatusFailed
	item.LastError = lastError
	item.UpdatedAt = time.Now()

	return fq.writeFile(item)
}

// Requeue moves an item back to pending status for retry.
func (fq *FileRetryQueue) Requeue(ctx context.Context, id string, nextRetry time.Time) error {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return ErrQueueClosed
	}

	item, err := fq.getByIDUnsafe(id)
	if err != nil {
		return err
	}

	item.Status = ItemStatusPending
	item.NextRetry = nextRetry
	item.UpdatedAt = time.Now()

	return fq.writeFile(item)
}

// Size returns the total number of items in the queue.
func (fq *FileRetryQueue) Size(ctx context.Context) (int, error) {
	fq.mu.RLock()
	defer fq.mu.RUnlock()

	if fq.closed {
		return 0, ErrQueueClosed
	}

	return fq.sizeUnsafe()
}

// Stats returns detailed statistics about the queue.
func (fq *FileRetryQueue) Stats(ctx context.Context) (*QueueStats, error) {
	fq.mu.RLock()
	defer fq.mu.RUnlock()

	if fq.closed {
		return nil, ErrQueueClosed
	}

	files, err := fq.listFiles()
	if err != nil {
		return nil, err
	}

	stats := &QueueStats{}

	for _, file := range files {
		item, err := fq.readFile(file)
		if err != nil {
			continue
		}

		stats.TotalItems++

		switch item.Status {
		case ItemStatusPending:
			stats.PendingItems++
		case ItemStatusProcessing:
			stats.ProcessingItems++
		case ItemStatusFailed:
			stats.FailedItems++
		}

		if stats.OldestItem.IsZero() || item.CreatedAt.Before(stats.OldestItem) {
			stats.OldestItem = item.CreatedAt
		}
		if item.CreatedAt.After(stats.NewestItem) {
			stats.NewestItem = item.CreatedAt
		}
		if item.LastAttempt.After(stats.LastRetry) {
			stats.LastRetry = item.LastAttempt
		}

		stats.TotalRetries += int64(item.Attempts)
	}

	return stats, nil
}

// Cleanup removes expired items and permanently failed items.
func (fq *FileRetryQueue) Cleanup(ctx context.Context, ttl time.Duration) (int, error) {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	if fq.closed {
		return 0, ErrQueueClosed
	}

	files, err := fq.listFiles()
	if err != nil {
		return 0, err
	}

	removed := 0
	now := time.Now()

	for _, file := range files {
		item, err := fq.readFile(file)
		if err != nil {
			// Remove corrupted files
			_ = os.Remove(file)
			removed++
			continue
		}

		// Remove expired items
		if item.IsExpired(ttl) {
			if err := fq.deleteUnsafe(item.ID); err == nil {
				removed++
				if fq.verbose {
					fmt.Printf("[retry] Cleaned up expired item %s (age: %v)\n",
						item.ID[:8], now.Sub(item.CreatedAt))
				}
			}
			continue
		}

		// Remove permanently failed items older than TTL/2
		if item.Status == ItemStatusFailed && now.Sub(item.CreatedAt) > ttl/2 {
			if err := fq.deleteUnsafe(item.ID); err == nil {
				removed++
				if fq.verbose {
					fmt.Printf("[retry] Cleaned up failed item %s\n", item.ID[:8])
				}
			}
		}
	}

	return removed, nil
}

// List returns items matching the given filter.
func (fq *FileRetryQueue) List(ctx context.Context, filter ListFilter) ([]*QueueItem, error) {
	fq.mu.RLock()
	defer fq.mu.RUnlock()

	if fq.closed {
		return nil, ErrQueueClosed
	}

	files, err := fq.listFiles()
	if err != nil {
		return nil, err
	}

	var items []*QueueItem
	now := time.Now()

	for _, file := range files {
		item, err := fq.readFile(file)
		if err != nil {
			continue
		}

		// Apply filters
		if filter.Status != "" && item.Status != filter.Status {
			continue
		}
		if filter.Type != "" && item.Type != filter.Type {
			continue
		}
		if filter.ReadyOnly && (item.Status != ItemStatusPending || !now.After(item.NextRetry)) {
			continue
		}

		items = append(items, item)
	}

	// Sort
	orderBy := filter.OrderBy
	if orderBy == "" {
		orderBy = "created_at"
	}

	sort.Slice(items, func(i, j int) bool {
		var less bool
		switch orderBy {
		case "next_retry":
			less = items[i].NextRetry.Before(items[j].NextRetry)
		case "attempts":
			less = items[i].Attempts < items[j].Attempts
		default: // created_at
			less = items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		if filter.OrderDesc {
			return !less
		}
		return less
	})

	// Apply pagination
	if filter.Offset > 0 {
		if filter.Offset >= len(items) {
			return []*QueueItem{}, nil
		}
		items = items[filter.Offset:]
	}
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}

	return items, nil
}

// Close closes the queue and releases resources.
func (fq *FileRetryQueue) Close() error {
	fq.mu.Lock()
	defer fq.mu.Unlock()

	fq.closed = true
	fq.fingerprints = nil

	if fq.verbose {
		fmt.Printf("[retry] Queue closed\n")
	}

	return nil
}

// Internal helper methods (must be called with lock held)

func (fq *FileRetryQueue) sizeUnsafe() (int, error) {
	files, err := fq.listFiles()
	if err != nil {
		return 0, err
	}
	return len(files), nil
}

func (fq *FileRetryQueue) getByIDUnsafe(id string) (*QueueItem, error) {
	files, err := fq.listFiles()
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if strings.Contains(filepath.Base(file), id) {
			return fq.readFile(file)
		}
	}

	return nil, ErrItemNotFound
}

func (fq *FileRetryQueue) deleteUnsafe(id string) error {
	files, err := fq.listFiles()
	if err != nil {
		return err
	}

	for _, file := range files {
		if strings.Contains(filepath.Base(file), id) {
			item, err := fq.readFile(file)
			if err == nil && item.Fingerprint != "" {
				delete(fq.fingerprints, item.Fingerprint)
			}
			return os.Remove(file)
		}
	}

	return ErrItemNotFound
}

func (fq *FileRetryQueue) listReadyItemsUnsafe(limit int) ([]*QueueItem, error) {
	files, err := fq.listFiles()
	if err != nil {
		return nil, err
	}

	var items []*QueueItem
	now := time.Now()

	for _, file := range files {
		item, err := fq.readFile(file)
		if err != nil {
			continue
		}

		if item.IsReadyForRetry() {
			items = append(items, item)
		}
	}

	// Sort by NextRetry (oldest first)
	sort.Slice(items, func(i, j int) bool {
		return items[i].NextRetry.Before(items[j].NextRetry)
	})

	// Also prioritize by attempts (fewer attempts first)
	sort.SliceStable(items, func(i, j int) bool {
		// If both are past due, prioritize older items
		if now.After(items[i].NextRetry) && now.After(items[j].NextRetry) {
			return items[i].Attempts < items[j].Attempts
		}
		return false
	})

	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	return items, nil
}

// File operations

func (fq *FileRetryQueue) listFiles() ([]string, error) {
	entries, err := os.ReadDir(fq.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		files = append(files, filepath.Join(fq.dir, entry.Name()))
	}

	// Sort by filename (which includes timestamp for natural ordering)
	sort.Strings(files)

	return files, nil
}

func (fq *FileRetryQueue) readFile(path string) (*QueueItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var item QueueItem
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("failed to parse queue item: %w", err)
	}

	return &item, nil
}

func (fq *FileRetryQueue) writeFile(item *QueueItem) error {
	// Generate filename: {timestamp}_{id}.json
	filename := fmt.Sprintf("%d_%s.json", item.CreatedAt.UnixNano(), item.ID)
	path := filepath.Join(fq.dir, filename)

	// Check if file already exists with different name (ID match)
	files, _ := fq.listFiles()
	for _, file := range files {
		if strings.Contains(filepath.Base(file), item.ID) && file != path {
			// Remove old file
			_ = os.Remove(file)
			break
		}
	}

	data, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal queue item: %w", err)
	}

	// Write atomically using temp file
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func (fq *FileRetryQueue) generateFingerprint(item *QueueItem) string {
	// Generate fingerprint based on report content
	if item.Report == nil {
		return ""
	}

	data, err := json.Marshal(item.Report)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
