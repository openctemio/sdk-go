package retry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestFileRetryQueue_EnqueueDequeue(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create queue
	queue, err := NewFileRetryQueue(&FileQueueConfig{
		Dir:     tmpDir,
		Verbose: true,
	})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Create test item
	item := &QueueItem{
		Type: ItemTypeFindings,
		Report: &ctis.Report{
			Version: "1.0",
			Tool:    &ctis.Tool{Name: "test-scanner", Version: "1.0"},
			Findings: []ctis.Finding{
				{
					RuleID:   "TEST-001",
					Title:    "Test Finding",
					Severity: ctis.SeverityHigh,
				},
			},
		},
		AgentID:     "test-agent",
		ScannerName: "test-scanner",
		TargetPath:  "/test/path",
	}

	// Enqueue
	id, err := queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty ID")
	}

	// Check size
	size, err := queue.Size(ctx)
	if err != nil {
		t.Fatalf("Failed to get size: %v", err)
	}
	if size != 1 {
		t.Fatalf("Expected size 1, got %d", size)
	}

	// Dequeue
	dequeued, err := queue.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Failed to dequeue: %v", err)
	}
	if dequeued == nil {
		t.Fatal("Expected non-nil item")
	}
	if dequeued.ID != id {
		t.Fatalf("Expected ID %s, got %s", id, dequeued.ID)
	}
	if dequeued.Status != ItemStatusProcessing {
		t.Fatalf("Expected status %s, got %s", ItemStatusProcessing, dequeued.Status)
	}
}

func TestFileRetryQueue_Deduplication(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queue, err := NewFileRetryQueue(&FileQueueConfig{
		Dir:           tmpDir,
		Deduplication: true,
	})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Create item with fingerprint
	item := &QueueItem{
		Type:        ItemTypeFindings,
		Fingerprint: "test-fingerprint-123",
		Report:      &ctis.Report{Version: "1.0"},
	}

	// First enqueue should succeed
	_, err = queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("First enqueue failed: %v", err)
	}

	// Second enqueue should fail with duplicate error
	item2 := &QueueItem{
		Type:        ItemTypeFindings,
		Fingerprint: "test-fingerprint-123", // Same fingerprint
		Report:      &ctis.Report{Version: "1.0"},
	}

	_, err = queue.Enqueue(ctx, item2)
	if err != ErrDuplicateItem {
		t.Fatalf("Expected ErrDuplicateItem, got %v", err)
	}

	// Size should still be 1
	size, err := queue.Size(ctx)
	if err != nil {
		t.Fatalf("Failed to get size: %v", err)
	}
	if size != 1 {
		t.Fatalf("Expected size 1, got %d", size)
	}
}

func TestFileRetryQueue_Stats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queue, err := NewFileRetryQueue(&FileQueueConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Add some items
	for i := range 3 {
		item := &QueueItem{
			Type:   ItemTypeFindings,
			Report: &ctis.Report{Version: "1.0"},
		}
		if i == 2 {
			item.Type = ItemTypeAssets
		}
		_, err := queue.Enqueue(ctx, item)
		if err != nil {
			t.Fatalf("Failed to enqueue: %v", err)
		}
	}

	stats, err := queue.Stats(ctx)
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if stats.TotalItems != 3 {
		t.Fatalf("Expected 3 items, got %d", stats.TotalItems)
	}
	if stats.PendingItems != 3 {
		t.Fatalf("Expected 3 pending items, got %d", stats.PendingItems)
	}
}

func TestBackoffConfig_NextRetry(t *testing.T) {
	cfg := DefaultBackoffConfig()
	cfg.BaseInterval = 1 * time.Minute
	cfg.Jitter = 0 // Disable jitter for predictable tests

	tests := []struct {
		attempts int
		expected time.Duration
	}{
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 16 * time.Minute},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			interval := cfg.calculateInterval(tt.attempts)
			if interval != tt.expected {
				t.Errorf("Attempt %d: expected %v, got %v", tt.attempts, tt.expected, interval)
			}
		})
	}
}

func TestBackoffConfig_MaxInterval(t *testing.T) {
	cfg := DefaultBackoffConfig()
	cfg.BaseInterval = 1 * time.Hour
	cfg.MaxInterval = 24 * time.Hour
	cfg.Jitter = 0

	// With exponential backoff: 1h * 2^9 = 512h, but should be capped at 24h
	interval := cfg.calculateInterval(10)
	if interval != 24*time.Hour {
		t.Errorf("Expected max interval 24h, got %v", interval)
	}
}

func TestQueueItem_Helpers(t *testing.T) {
	now := time.Now()

	item := &QueueItem{
		Status:      ItemStatusPending,
		Attempts:    3,
		MaxAttempts: 5,
		CreatedAt:   now.Add(-1 * time.Hour),
		NextRetry:   now.Add(-1 * time.Minute), // Past due
	}

	// Should be ready for retry
	if !item.IsReadyForRetry() {
		t.Error("Expected item to be ready for retry")
	}

	// Should not have exhausted retries
	if item.HasExhaustedRetries() {
		t.Error("Expected item to not have exhausted retries")
	}

	// Update attempts to max
	item.Attempts = 5
	if !item.HasExhaustedRetries() {
		t.Error("Expected item to have exhausted retries")
	}

	// Check expiration
	if item.IsExpired(30 * time.Minute) {
		// Created 1 hour ago, TTL 30 min - should be expired
	} else {
		t.Error("Expected item to be expired with 30 min TTL")
	}

	if item.IsExpired(2 * time.Hour) {
		t.Error("Expected item to not be expired with 2 hour TTL")
	}
}

func TestFileRetryQueue_Persistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ctx := context.Background()

	// Create queue and add item
	queue1, err := NewFileRetryQueue(&FileQueueConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	item := &QueueItem{
		Type:   ItemTypeFindings,
		Report: &ctis.Report{Version: "1.0"},
	}
	id, err := queue1.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Close queue
	queue1.Close()

	// Reopen queue - should load existing items
	queue2, err := NewFileRetryQueue(&FileQueueConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to reopen queue: %v", err)
	}
	defer queue2.Close()

	// Verify item exists
	size, err := queue2.Size(ctx)
	if err != nil {
		t.Fatalf("Failed to get size: %v", err)
	}
	if size != 1 {
		t.Fatalf("Expected size 1 after reopen, got %d", size)
	}

	// Get the item
	retrieved, err := queue2.Get(ctx, id)
	if err != nil {
		t.Fatalf("Failed to get item: %v", err)
	}
	if retrieved.ID != id {
		t.Fatalf("Expected ID %s, got %s", id, retrieved.ID)
	}
}

func TestFileRetryQueue_Cleanup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queue, err := NewFileRetryQueue(&FileQueueConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Add an item
	item := &QueueItem{
		Type:      ItemTypeFindings,
		Report:    &ctis.Report{Version: "1.0"},
		CreatedAt: time.Now().Add(-2 * time.Hour), // Created 2 hours ago
	}
	_, err = queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Cleanup with 1 hour TTL should remove the item
	removed, err := queue.Cleanup(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if removed != 1 {
		t.Fatalf("Expected 1 item removed, got %d", removed)
	}

	// Queue should be empty
	size, err := queue.Size(ctx)
	if err != nil {
		t.Fatalf("Failed to get size: %v", err)
	}
	if size != 0 {
		t.Fatalf("Expected empty queue, got size %d", size)
	}
}

func TestFileRetryQueue_List(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queue, err := NewFileRetryQueue(&FileQueueConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Add items of different types
	types := []ItemType{ItemTypeFindings, ItemTypeAssets, ItemTypeFindings}
	for _, itemType := range types {
		item := &QueueItem{
			Type:   itemType,
			Report: &ctis.Report{Version: "1.0"},
		}
		_, err := queue.Enqueue(ctx, item)
		if err != nil {
			t.Fatalf("Failed to enqueue: %v", err)
		}
	}

	// List all
	all, err := queue.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("Expected 3 items, got %d", len(all))
	}

	// Filter by type
	findings, err := queue.List(ctx, ListFilter{Type: ItemTypeFindings})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	// Test pagination
	limited, err := queue.List(ctx, ListFilter{Limit: 2})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("Expected 2 items with limit, got %d", len(limited))
	}
}

// Mock pusher for testing RetryWorker
type mockPusher struct {
	pushCount int
	failUntil int
}

func (m *mockPusher) PushReport(ctx context.Context, report *ctis.Report) error {
	m.pushCount++
	if m.pushCount <= m.failUntil {
		return context.DeadlineExceeded // Simulate timeout
	}
	return nil
}

func TestRetryWorker_ProcessBatch(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "retry-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queue, err := NewFileRetryQueue(&FileQueueConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Add an item
	item := &QueueItem{
		Type:   ItemTypeFindings,
		Report: &ctis.Report{Version: "1.0"},
	}
	_, err = queue.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Failed to enqueue: %v", err)
	}

	// Create worker with mock pusher that succeeds
	pusher := &mockPusher{failUntil: 0}
	worker := NewRetryWorker(&RetryWorkerConfig{
		Interval:    1 * time.Second,
		BatchSize:   10,
		MaxAttempts: 3,
		Verbose:     true,
	}, queue, pusher)

	// Process batch
	err = worker.ProcessNow(ctx)
	if err != nil {
		t.Fatalf("ProcessNow failed: %v", err)
	}

	// Item should be removed after successful push
	size, err := queue.Size(ctx)
	if err != nil {
		t.Fatalf("Failed to get size: %v", err)
	}
	if size != 0 {
		t.Fatalf("Expected empty queue after successful push, got size %d", size)
	}

	// Verify pusher was called
	if pusher.pushCount != 1 {
		t.Fatalf("Expected 1 push, got %d", pusher.pushCount)
	}
}

func TestFileRetryQueue_MaxSize(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "retry-queue-test-maxsize")
	os.RemoveAll(tmpDir)
	defer os.RemoveAll(tmpDir)

	queue, err := NewFileRetryQueue(&FileQueueConfig{
		Dir:     tmpDir,
		MaxSize: 3,
	})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	defer queue.Close()

	ctx := context.Background()

	// Add items up to max
	for i := range 3 {
		item := &QueueItem{
			Type:   ItemTypeFindings,
			Report: &ctis.Report{Version: "1.0"},
		}
		_, err := queue.Enqueue(ctx, item)
		if err != nil {
			t.Fatalf("Failed to enqueue item %d: %v", i, err)
		}
	}

	// Next enqueue should fail
	item := &QueueItem{
		Type:   ItemTypeFindings,
		Report: &ctis.Report{Version: "1.0"},
	}
	_, err = queue.Enqueue(ctx, item)
	if err != ErrQueueFull {
		t.Fatalf("Expected ErrQueueFull, got %v", err)
	}
}
