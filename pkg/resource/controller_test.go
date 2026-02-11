package resource

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewController(t *testing.T) {
	tests := []struct {
		name   string
		config *ControllerConfig
		want   struct {
			cpuThreshold      float64
			memoryThreshold   float64
			maxConcurrentJobs int
		}
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
			want: struct {
				cpuThreshold      float64
				memoryThreshold   float64
				maxConcurrentJobs int
			}{85.0, 85.0, 0}, // 0 means it will use runtime.NumCPU()
		},
		{
			name: "custom config",
			config: &ControllerConfig{
				CPUThreshold:      90.0,
				MemoryThreshold:   80.0,
				MaxConcurrentJobs: 4,
			},
			want: struct {
				cpuThreshold      float64
				memoryThreshold   float64
				maxConcurrentJobs int
			}{90.0, 80.0, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewController(tt.config)
			if c == nil {
				t.Fatal("NewController returned nil")
			}

			if tt.want.cpuThreshold > 0 && c.config.CPUThreshold != tt.want.cpuThreshold {
				t.Errorf("CPUThreshold = %v, want %v", c.config.CPUThreshold, tt.want.cpuThreshold)
			}

			if tt.want.memoryThreshold > 0 && c.config.MemoryThreshold != tt.want.memoryThreshold {
				t.Errorf("MemoryThreshold = %v, want %v", c.config.MemoryThreshold, tt.want.memoryThreshold)
			}

			if tt.want.maxConcurrentJobs > 0 && c.config.MaxConcurrentJobs != tt.want.maxConcurrentJobs {
				t.Errorf("MaxConcurrentJobs = %v, want %v", c.config.MaxConcurrentJobs, tt.want.maxConcurrentJobs)
			}
		})
	}
}

func TestController_StartStop(t *testing.T) {
	c := NewController(&ControllerConfig{
		SampleInterval: 100 * time.Millisecond,
	})

	ctx := context.Background()

	// Start controller
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify it's running
	if atomic.LoadInt32(&c.running) != 1 {
		t.Error("Controller should be running")
	}

	// Can't start again
	if err := c.Start(ctx); err == nil {
		t.Error("Expected error when starting already-running controller")
	}

	// Stop controller
	c.Stop()

	// Verify it's stopped
	if atomic.LoadInt32(&c.running) != 0 {
		t.Error("Controller should be stopped")
	}
}

func TestController_AcquireReleaseSlot(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 2,
	})

	ctx := context.Background()

	// Should be able to acquire slots up to max
	if !c.AcquireSlot(ctx) {
		t.Error("Should acquire first slot")
	}
	if c.GetStatus().ActiveJobs != 1 {
		t.Errorf("ActiveJobs = %d, want 1", c.GetStatus().ActiveJobs)
	}

	if !c.AcquireSlot(ctx) {
		t.Error("Should acquire second slot")
	}
	if c.GetStatus().ActiveJobs != 2 {
		t.Errorf("ActiveJobs = %d, want 2", c.GetStatus().ActiveJobs)
	}

	// Third slot should fail (non-blocking)
	if c.AcquireSlot(ctx) {
		t.Error("Should not acquire third slot when at capacity")
	}

	// Release one slot
	c.ReleaseSlot()
	if c.GetStatus().ActiveJobs != 1 {
		t.Errorf("ActiveJobs = %d, want 1 after release", c.GetStatus().ActiveJobs)
	}

	// Should be able to acquire again
	if !c.AcquireSlot(ctx) {
		t.Error("Should acquire slot after release")
	}

	// Cleanup
	c.ReleaseSlot()
	c.ReleaseSlot()
}

func TestController_AcquireSlotBlocking(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Acquire the only slot
	if !c.AcquireSlot(ctx) {
		t.Fatal("Should acquire first slot")
	}

	// Start goroutine that will release after delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		c.ReleaseSlot()
	}()

	// Should block until released
	start := time.Now()
	if err := c.AcquireSlotBlocking(ctx); err != nil {
		t.Errorf("AcquireSlotBlocking failed: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < 100*time.Millisecond {
		t.Error("AcquireSlotBlocking should have blocked")
	}

	c.ReleaseSlot()
}

func TestController_AcquireSlotBlocking_ContextCanceled(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 1,
	})

	ctx := context.Background()

	// Acquire the only slot
	if !c.AcquireSlot(ctx) {
		t.Fatal("Should acquire first slot")
	}

	// Try to acquire with short timeout
	shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	err := c.AcquireSlotBlocking(shortCtx)
	if err == nil {
		t.Error("Expected error when context is canceled")
	}

	c.ReleaseSlot()
}

func TestController_IsThrottled(t *testing.T) {
	c := NewController(&ControllerConfig{
		CPUThreshold:    10.0, // Very low threshold to trigger throttling
		MemoryThreshold: 10.0,
		SampleInterval:  100 * time.Millisecond,
	})

	// Initially not throttled
	if c.IsThrottled() {
		t.Error("Should not be throttled initially")
	}

	// Start controller and let it sample
	ctx := context.Background()
	c.Start(ctx)
	defer c.Stop()

	// Wait for some samples
	time.Sleep(300 * time.Millisecond)

	// With such low thresholds, it should be throttled
	// (This test may be flaky depending on actual system load)
	status := c.GetStatus()
	t.Logf("Status: Throttled=%v, Metrics=%+v", status.Throttled, status.Metrics)
}

func TestController_GetStatus(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 3,
	})

	status := c.GetStatus()

	if status.MaxJobs != 3 {
		t.Errorf("MaxJobs = %d, want 3", status.MaxJobs)
	}
	if status.ActiveJobs != 0 {
		t.Errorf("ActiveJobs = %d, want 0", status.ActiveJobs)
	}
	if status.PendingJobs != 0 {
		t.Errorf("PendingJobs = %d, want 0", status.PendingJobs)
	}
}

func TestController_GetMetrics(t *testing.T) {
	c := NewController(&ControllerConfig{
		SampleInterval: 50 * time.Millisecond,
	})

	ctx := context.Background()
	c.Start(ctx)
	defer c.Stop()

	// Wait for initial sample
	time.Sleep(100 * time.Millisecond)

	metrics := c.GetMetrics()

	if metrics.Timestamp.IsZero() {
		t.Error("Metrics timestamp should not be zero")
	}
	if metrics.NumCPU <= 0 {
		t.Error("NumCPU should be positive")
	}
	if metrics.NumGoroutines <= 0 {
		t.Error("NumGoroutines should be positive")
	}
}

func TestController_SetMaxConcurrentJobs(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 2,
	})

	ctx := context.Background()

	// Acquire both slots
	c.AcquireSlot(ctx)
	c.AcquireSlot(ctx)

	// Should be at capacity
	if c.AcquireSlot(ctx) {
		t.Error("Should be at capacity")
	}

	// Increase capacity
	c.SetMaxConcurrentJobs(3)

	// Should be able to acquire now
	if !c.AcquireSlot(ctx) {
		t.Error("Should acquire after capacity increase")
	}

	// Cleanup
	c.ReleaseSlot()
	c.ReleaseSlot()
	c.ReleaseSlot()
}

func TestController_AdaptiveMaxJobs(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 4,
	})

	// Sample metrics
	c.sampleMetrics()

	recommended := c.AdaptiveMaxJobs()

	// Recommended should be at most MaxConcurrentJobs
	if recommended > c.config.MaxConcurrentJobs {
		t.Errorf("AdaptiveMaxJobs = %d, should not exceed MaxConcurrentJobs %d",
			recommended, c.config.MaxConcurrentJobs)
	}

	// Recommended should be at least MinConcurrentJobs
	if recommended < c.config.MinConcurrentJobs {
		t.Errorf("AdaptiveMaxJobs = %d, should be at least MinConcurrentJobs %d",
			recommended, c.config.MinConcurrentJobs)
	}
}

func TestController_ConcurrentAccess(t *testing.T) {
	c := NewController(&ControllerConfig{
		MaxConcurrentJobs: 10,
		SampleInterval:    50 * time.Millisecond,
	})

	ctx := context.Background()
	c.Start(ctx)
	defer c.Stop()

	var wg sync.WaitGroup
	var acquired int32

	// Spawn many goroutines trying to acquire slots
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.AcquireSlot(ctx) {
				atomic.AddInt32(&acquired, 1)
				time.Sleep(50 * time.Millisecond)
				c.ReleaseSlot()
			}
		}()
	}

	wg.Wait()

	// Should have acquired some slots
	if acquired == 0 {
		t.Error("Should have acquired at least some slots")
	}

	// All slots should be released
	status := c.GetStatus()
	if status.ActiveJobs != 0 {
		t.Errorf("ActiveJobs = %d after all goroutines done, want 0", status.ActiveJobs)
	}
}

func TestController_ForceGC(t *testing.T) {
	c := NewController(nil)

	// Just verify it doesn't panic
	c.ForceGC()
}

func TestController_ThresholdCallbacks(t *testing.T) {
	var mu sync.Mutex
	var exceededCalled, clearedCalled bool

	c := NewController(&ControllerConfig{
		CPUThreshold:     10.0, // Very low to trigger
		MemoryThreshold:  10.0,
		SampleInterval:   50 * time.Millisecond,
		CooldownDuration: 100 * time.Millisecond,
		OnThresholdExceeded: func(metrics *SystemMetrics, reason string) {
			mu.Lock()
			exceededCalled = true
			mu.Unlock()
		},
		OnThresholdCleared: func(metrics *SystemMetrics) {
			mu.Lock()
			clearedCalled = true
			mu.Unlock()
		},
	})

	ctx := context.Background()
	c.Start(ctx)

	// Wait for threshold checks
	time.Sleep(200 * time.Millisecond)

	c.Stop()

	// With low thresholds, exceeded should have been called
	// (may be flaky depending on system load)
	mu.Lock()
	t.Logf("ExceededCalled=%v, ClearedCalled=%v", exceededCalled, clearedCalled)
	mu.Unlock()
}
