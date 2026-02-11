package pipeline

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// mockUploader implements Uploader for testing
type mockUploader struct {
	uploadFunc func(ctx context.Context, report *ctis.Report) (*Result, error)
	uploads    int32
}

func (m *mockUploader) Upload(ctx context.Context, report *ctis.Report) (*Result, error) {
	atomic.AddInt32(&m.uploads, 1)
	if m.uploadFunc != nil {
		return m.uploadFunc(ctx, report)
	}
	return &Result{
		Status:          "completed",
		FindingsCreated: len(report.Findings),
		AssetsCreated:   len(report.Assets),
	}, nil
}

func TestNewPipeline(t *testing.T) {
	uploader := &mockUploader{}

	tests := []struct {
		name   string
		config *PipelineConfig
		want   struct {
			queueSize int
			workers   int
		}
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
			want: struct {
				queueSize int
				workers   int
			}{1000, 3},
		},
		{
			name: "custom config",
			config: &PipelineConfig{
				QueueSize: 500,
				Workers:   5,
			},
			want: struct {
				queueSize int
				workers   int
			}{500, 5},
		},
		{
			name: "zero values get defaults",
			config: &PipelineConfig{
				QueueSize: 0,
				Workers:   0,
			},
			want: struct {
				queueSize int
				workers   int
			}{1000, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(tt.config, uploader)
			if p == nil {
				t.Fatal("NewPipeline returned nil")
			}

			if cap(p.queue) != tt.want.queueSize {
				t.Errorf("QueueSize = %d, want %d", cap(p.queue), tt.want.queueSize)
			}

			if p.config.Workers != tt.want.workers {
				t.Errorf("Workers = %d, want %d", p.config.Workers, tt.want.workers)
			}
		})
	}
}

func TestPipeline_StartStop(t *testing.T) {
	uploader := &mockUploader{}
	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   2,
	}, uploader)

	ctx := context.Background()

	// Start pipeline
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify running
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()
	if !running {
		t.Error("Pipeline should be running")
	}

	// Start again should be no-op
	if err := p.Start(ctx); err != nil {
		t.Errorf("Second start should not error: %v", err)
	}

	// Stop pipeline
	if err := p.Stop(ctx); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	p.mu.RLock()
	running = p.running
	p.mu.RUnlock()
	if running {
		t.Error("Pipeline should not be running after stop")
	}
}

func TestPipeline_Submit(t *testing.T) {
	uploader := &mockUploader{}
	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   2,
	}, uploader)

	ctx := context.Background()

	// Submit before start should fail
	_, err := p.Submit(&ctis.Report{})
	if err == nil {
		t.Error("Submit before start should fail")
	}

	// Start pipeline
	p.Start(ctx)
	defer p.Stop(ctx)

	// Submit should work
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "test-tool"},
		Findings: []ctis.Finding{
			{Title: "Finding 1"},
			{Title: "Finding 2"},
		},
	}

	id, err := p.Submit(report)
	if err != nil {
		t.Errorf("Submit failed: %v", err)
	}
	if id == "" {
		t.Error("Submit should return non-empty ID")
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&uploader.uploads) != 1 {
		t.Errorf("Expected 1 upload, got %d", uploader.uploads)
	}
}

func TestPipeline_SubmitWithOptions(t *testing.T) {
	uploader := &mockUploader{}

	var mu sync.Mutex
	var submittedItem *QueueItem

	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   2,
		OnSubmitted: func(item *QueueItem) {
			mu.Lock()
			submittedItem = item
			mu.Unlock()
		},
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "test-tool"},
	}

	_, err := p.Submit(report,
		WithJobID("job-123"),
		WithTenantID("tenant-456"),
		WithPriority(10),
	)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if submittedItem == nil {
		t.Fatal("OnSubmitted not called")
	}
	if submittedItem.JobID != "job-123" {
		t.Errorf("JobID = %s, want job-123", submittedItem.JobID)
	}
	if submittedItem.TenantID != "tenant-456" {
		t.Errorf("TenantID = %s, want tenant-456", submittedItem.TenantID)
	}
	if submittedItem.Priority != 10 {
		t.Errorf("Priority = %d, want 10", submittedItem.Priority)
	}
}

func TestPipeline_QueueFull(t *testing.T) {
	blockCh := make(chan struct{})
	uploader := &mockUploader{
		uploadFunc: func(ctx context.Context, report *ctis.Report) (*Result, error) {
			<-blockCh // Block forever until closed
			return &Result{Status: "completed"}, nil
		},
	}

	p := NewPipeline(&PipelineConfig{
		QueueSize: 2,
		Workers:   1,
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer func() {
		close(blockCh)
		p.Stop(ctx)
	}()

	// Submit until queue is full
	// Queue size = 2, Workers = 1
	// First submit: goes to worker (processing)
	// Second submit: goes to queue slot 1
	// Third submit: goes to queue slot 2
	// Fourth submit: queue full, should fail
	for i := 0; i < 5; i++ {
		_, err := p.Submit(&ctis.Report{})
		if i >= 3 && err == nil {
			t.Errorf("Submit %d should fail when queue is full", i)
		}
	}
}

func TestPipeline_Flush(t *testing.T) {
	processed := int32(0)
	uploader := &mockUploader{
		uploadFunc: func(ctx context.Context, report *ctis.Report) (*Result, error) {
			time.Sleep(50 * time.Millisecond)
			atomic.AddInt32(&processed, 1)
			return &Result{Status: "completed"}, nil
		},
	}

	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   2,
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	// Submit multiple reports
	for i := 0; i < 5; i++ {
		p.Submit(&ctis.Report{})
	}

	// Flush and wait
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := p.Flush(flushCtx)
	if err != nil {
		t.Errorf("Flush failed: %v", err)
	}

	if atomic.LoadInt32(&processed) != 5 {
		t.Errorf("Expected 5 processed, got %d", processed)
	}
}

func TestPipeline_Retry(t *testing.T) {
	attempts := int32(0)
	uploader := &mockUploader{
		uploadFunc: func(ctx context.Context, report *ctis.Report) (*Result, error) {
			n := atomic.AddInt32(&attempts, 1)
			if n < 3 {
				return nil, errors.New("temporary error")
			}
			return &Result{Status: "completed"}, nil
		},
	}

	var mu sync.Mutex
	var completedItem *QueueItem
	var completedResult *Result

	p := NewPipeline(&PipelineConfig{
		QueueSize:     10,
		Workers:       1,
		RetryAttempts: 3,
		RetryDelay:    10 * time.Millisecond,
		OnCompleted: func(item *QueueItem, result *Result) {
			mu.Lock()
			completedItem = item
			completedResult = result
			mu.Unlock()
		},
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	p.Submit(&ctis.Report{})

	// Wait for retries
	time.Sleep(500 * time.Millisecond)

	if atomic.LoadInt32(&attempts) < 3 {
		t.Errorf("Expected at least 3 attempts, got %d", attempts)
	}

	mu.Lock()
	defer mu.Unlock()
	if completedItem == nil {
		t.Error("OnCompleted should have been called")
	}
	if completedResult == nil || completedResult.Status != "completed" {
		t.Error("Should have succeeded after retries")
	}
}

func TestPipeline_RetryExhausted(t *testing.T) {
	uploader := &mockUploader{
		uploadFunc: func(ctx context.Context, report *ctis.Report) (*Result, error) {
			return nil, errors.New("permanent error")
		},
	}

	var mu sync.Mutex
	var failedItem *QueueItem
	var failedErr error

	p := NewPipeline(&PipelineConfig{
		QueueSize:     10,
		Workers:       1,
		RetryAttempts: 2,
		RetryDelay:    10 * time.Millisecond,
		OnFailed: func(item *QueueItem, err error) {
			mu.Lock()
			failedItem = item
			failedErr = err
			mu.Unlock()
		},
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	p.Submit(&ctis.Report{})

	// Wait for retries
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	if failedItem == nil {
		t.Error("OnFailed should have been called")
	}
	if failedErr == nil {
		t.Error("failedErr should not be nil")
	}
	mu.Unlock()

	stats := p.GetStats()
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
}

func TestPipeline_GetStats(t *testing.T) {
	uploader := &mockUploader{}
	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   2,
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	// Submit some reports
	for i := 0; i < 3; i++ {
		p.Submit(&ctis.Report{})
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	stats := p.GetStats()

	if stats.Submitted != 3 {
		t.Errorf("Submitted = %d, want 3", stats.Submitted)
	}
	if stats.Completed != 3 {
		t.Errorf("Completed = %d, want 3", stats.Completed)
	}
}

func TestPipeline_QueueLength(t *testing.T) {
	blockCh := make(chan struct{})
	uploader := &mockUploader{
		uploadFunc: func(ctx context.Context, report *ctis.Report) (*Result, error) {
			<-blockCh
			return &Result{Status: "completed"}, nil
		},
	}

	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   1,
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer func() {
		close(blockCh)
		p.Stop(ctx)
	}()

	// Submit a few items
	p.Submit(&ctis.Report{})
	p.Submit(&ctis.Report{})
	p.Submit(&ctis.Report{})

	// Give time for worker to pick up one
	time.Sleep(50 * time.Millisecond)

	// Queue should have 2 (one is being processed)
	queueLen := p.QueueLength()
	if queueLen != 2 {
		t.Errorf("QueueLength = %d, want 2", queueLen)
	}
}

func TestPipeline_Callbacks(t *testing.T) {
	uploader := &mockUploader{}

	var mu sync.Mutex
	var submittedCalled, completedCalled bool
	var submittedItem, completedItem *QueueItem

	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   1,
		OnSubmitted: func(item *QueueItem) {
			mu.Lock()
			submittedCalled = true
			submittedItem = item
			mu.Unlock()
		},
		OnCompleted: func(item *QueueItem, result *Result) {
			mu.Lock()
			completedCalled = true
			completedItem = item
			mu.Unlock()
		},
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	p.Submit(&ctis.Report{Tool: &ctis.Tool{Name: "test"}})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if !submittedCalled {
		t.Error("OnSubmitted should have been called")
	}
	if !completedCalled {
		t.Error("OnCompleted should have been called")
	}
	if submittedItem == nil || submittedItem.ToolName != "test" {
		t.Error("submittedItem should have correct tool name")
	}
	if completedItem == nil {
		t.Error("completedItem should not be nil")
	}
}

func TestPipeline_ConcurrentSubmit(t *testing.T) {
	uploader := &mockUploader{}
	p := NewPipeline(&PipelineConfig{
		QueueSize: 100,
		Workers:   5,
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)
	defer p.Stop(ctx)

	var wg sync.WaitGroup
	submitted := int32(0)

	// Submit from multiple goroutines
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Submit(&ctis.Report{}); err == nil {
				atomic.AddInt32(&submitted, 1)
			}
		}()
	}

	wg.Wait()

	if atomic.LoadInt32(&submitted) != 50 {
		t.Errorf("Submitted = %d, want 50", submitted)
	}

	// Wait for processing
	p.Flush(ctx)

	stats := p.GetStats()
	if stats.Completed != 50 {
		t.Errorf("Completed = %d, want 50", stats.Completed)
	}
}

func TestPipeline_StopDrainsQueue(t *testing.T) {
	processed := int32(0)
	uploader := &mockUploader{
		uploadFunc: func(ctx context.Context, report *ctis.Report) (*Result, error) {
			atomic.AddInt32(&processed, 1)
			return &Result{Status: "completed"}, nil
		},
	}

	p := NewPipeline(&PipelineConfig{
		QueueSize: 10,
		Workers:   2,
	}, uploader)

	ctx := context.Background()
	p.Start(ctx)

	// Submit items
	for i := 0; i < 5; i++ {
		p.Submit(&ctis.Report{})
	}

	// Stop should drain remaining items
	p.Stop(ctx)

	if atomic.LoadInt32(&processed) != 5 {
		t.Errorf("Processed = %d, want 5 (queue should be drained on stop)", processed)
	}
}
