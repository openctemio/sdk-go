package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultLoggerConfig(t *testing.T) {
	cfg := DefaultLoggerConfig()

	if cfg == nil {
		t.Fatal("DefaultLoggerConfig returned nil")
	}

	if cfg.MaxSizeMB != 100 {
		t.Errorf("MaxSizeMB = %d, want 100", cfg.MaxSizeMB)
	}

	if cfg.MaxAgeDays != 30 {
		t.Errorf("MaxAgeDays = %d, want 30", cfg.MaxAgeDays)
	}

	if cfg.BufferSize != 100 {
		t.Errorf("BufferSize = %d, want 100", cfg.BufferSize)
	}

	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", cfg.FlushInterval)
	}

	if !strings.Contains(cfg.LogFile, ".openctem") {
		t.Errorf("LogFile should contain .openctem directory")
	}
}

func TestNewLogger(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, err := NewLogger(&LoggerConfig{
		AgentID:  "test-agent",
		TenantID: "test-tenant",
		LogFile:  logFile,
	})

	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	defer logger.Stop()

	if logger.config.AgentID != "test-agent" {
		t.Errorf("AgentID = %s, want test-agent", logger.config.AgentID)
	}

	// Log file should be created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file should be created")
	}
}

func TestNewLogger_NilConfig(t *testing.T) {
	logger, err := NewLogger(nil)
	if err != nil {
		t.Fatalf("NewLogger with nil config should work: %v", err)
	}

	defer logger.Stop()

	if logger.config == nil {
		t.Error("Logger should have default config")
	}
}

func TestNewLogger_InvalidPath(t *testing.T) {
	_, err := NewLogger(&LoggerConfig{
		LogFile: "/nonexistent/deeply/nested/path/audit.log",
	})

	// This may or may not fail depending on permissions
	// Just verify we don't panic
	t.Logf("NewLogger with invalid path: %v", err)
}

func TestLogger_StartStop(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := NewLogger(&LoggerConfig{
		LogFile:       filepath.Join(tmpDir, "test.log"),
		FlushInterval: 50 * time.Millisecond,
	})

	// Start logger
	logger.Start()

	if !logger.running {
		t.Error("Logger should be running after Start")
	}

	// Start again should be no-op
	logger.Start()

	// Stop logger
	err := logger.Stop()
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	if logger.running {
		t.Error("Logger should not be running after Stop")
	}
}

func TestLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		AgentID:       "test-agent",
		TenantID:      "test-tenant",
		LogFile:       logFile,
		BufferSize:    1, // Small buffer to trigger immediate flush
		FlushInterval: 5 * time.Second,
	})

	logger.Start()

	// Log an event
	logger.Log(Event{
		Type:     EventJobStarted,
		Severity: SeverityInfo,
		JobID:    "job-123",
		Message:  "Test job started",
		Details: map[string]interface{}{
			"key": "value",
		},
	})

	// Wait for flush
	time.Sleep(100 * time.Millisecond)

	logger.Stop()

	// Read log file
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Parse the JSON line
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("Failed to parse log event: %v (data: %s)", err, string(data))
	}

	if event.Type != EventJobStarted {
		t.Errorf("Type = %s, want %s", event.Type, EventJobStarted)
	}

	if event.AgentID != "test-agent" {
		t.Errorf("AgentID = %s, want test-agent", event.AgentID)
	}

	if event.TenantID != "test-tenant" {
		t.Errorf("TenantID = %s, want test-tenant", event.TenantID)
	}

	if event.JobID != "job-123" {
		t.Errorf("JobID = %s, want job-123", event.JobID)
	}
}

func TestLogger_Info(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.Info(EventScanStarted, "Scan started", map[string]interface{}{
		"target": "/path/to/project",
	})

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Severity != SeverityInfo {
		t.Errorf("Severity = %s, want %s", event.Severity, SeverityInfo)
	}
}

func TestLogger_Error(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.Error(EventScanFailed, "Scan failed", errors.New("test error"), nil)

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Severity != SeverityError {
		t.Errorf("Severity = %s, want %s", event.Severity, SeverityError)
	}

	if event.Error != "test error" {
		t.Errorf("Error = %s, want test error", event.Error)
	}
}

func TestLogger_JobStarted(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.JobStarted("job-123", "scan", map[string]interface{}{
		"tool": "semgrep",
	})

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Type != EventJobStarted {
		t.Errorf("Type = %s, want %s", event.Type, EventJobStarted)
	}

	if event.JobID != "job-123" {
		t.Errorf("JobID = %s, want job-123", event.JobID)
	}

	if event.Details["job_type"] != "scan" {
		t.Errorf("job_type = %v, want scan", event.Details["job_type"])
	}
}

func TestLogger_JobCompleted(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.JobCompleted("job-123", 5*time.Second, map[string]interface{}{
		"findings_count": 10,
	})

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Type != EventJobCompleted {
		t.Errorf("Type = %s, want %s", event.Type, EventJobCompleted)
	}

	if event.Duration != 5*time.Second {
		t.Errorf("Duration = %v, want 5s", event.Duration)
	}
}

func TestLogger_JobFailed(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.JobFailed("job-123", errors.New("execution failed"), nil)

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Type != EventJobFailed {
		t.Errorf("Type = %s, want %s", event.Type, EventJobFailed)
	}

	if event.Error != "execution failed" {
		t.Errorf("Error = %s, want execution failed", event.Error)
	}
}

func TestLogger_ChunkUploaded(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.ChunkUploaded("report-123", 2, 5, 1024)

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Type != EventChunkUploaded {
		t.Errorf("Type = %s, want %s", event.Type, EventChunkUploaded)
	}

	if event.ReportID != "report-123" {
		t.Errorf("ReportID = %s, want report-123", event.ReportID)
	}

	// Check message format
	if !strings.Contains(event.Message, "3/5") {
		t.Errorf("Message should contain chunk index: %s", event.Message)
	}
}

func TestLogger_ResourceThrottle(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	logger.ResourceThrottle("CPU too high", map[string]interface{}{
		"cpu_percent": 95.5,
	})

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Type != EventResourceThrottle {
		t.Errorf("Type = %s, want %s", event.Type, EventResourceThrottle)
	}

	if event.Severity != SeverityWarning {
		t.Errorf("Severity = %s, want %s", event.Severity, SeverityWarning)
	}
}

func TestLogger_Flush(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:       logFile,
		BufferSize:    100, // Large buffer
		FlushInterval: 1 * time.Hour,
	})
	logger.Start()

	// Log some events
	for i := 0; i < 10; i++ {
		logger.Info(EventJobStarted, "Test", nil)
	}

	// Manual flush
	logger.Flush()

	// Verify events were written
	data, _ := os.ReadFile(logFile)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	if len(lines) != 10 {
		t.Errorf("Expected 10 events, got %d", len(lines))
	}

	logger.Stop()
}

func TestLogger_BufferFlush(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:       logFile,
		BufferSize:    5, // Small buffer
		FlushInterval: 1 * time.Hour,
	})
	logger.Start()

	// Log more than buffer size
	for i := 0; i < 10; i++ {
		logger.Info(EventJobStarted, "Test", nil)
	}

	// Wait for automatic flush
	time.Sleep(100 * time.Millisecond)

	logger.Stop()

	// All events should be written
	data, _ := os.ReadFile(logFile)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	if len(lines) != 10 {
		t.Errorf("Expected 10 events, got %d", len(lines))
	}
}

func TestLogger_WithContext(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	ctx := context.Background()
	ctxLogger := logger.WithContext(ctx, "job-123", "report-456")

	ctxLogger.Info(EventScanStarted, "Scan started", nil)

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.JobID != "job-123" {
		t.Errorf("JobID = %s, want job-123", event.JobID)
	}

	if event.ReportID != "report-456" {
		t.Errorf("ReportID = %s, want report-456", event.ReportID)
	}
}

func TestLogger_ConcurrentLogging(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:       logFile,
		BufferSize:    10,
		FlushInterval: 50 * time.Millisecond,
	})
	logger.Start()

	var wg sync.WaitGroup
	numGoroutines := 10
	eventsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				logger.Info(EventJobStarted, "Concurrent test", map[string]interface{}{
					"goroutine": id,
					"event":     j,
				})
			}
		}(i)
	}

	wg.Wait()

	// Explicitly flush before stopping to ensure all buffered events are written
	logger.Flush()
	logger.Stop()

	// Verify all events were logged
	data, _ := os.ReadFile(logFile)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	expected := numGoroutines * eventsPerGoroutine
	if len(lines) != expected {
		t.Errorf("Expected %d events, got %d", expected, len(lines))
	}
}

func TestLogger_RemoteSender(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})

	var remoteSent []Event
	var mu sync.Mutex

	logger.SetRemoteSender(func(events []Event) error {
		mu.Lock()
		remoteSent = append(remoteSent, events...)
		mu.Unlock()
		return nil
	})

	logger.Start()

	logger.Info(EventJobStarted, "Test", nil)

	time.Sleep(100 * time.Millisecond)
	logger.Stop()

	mu.Lock()
	count := len(remoteSent)
	mu.Unlock()

	if count != 1 {
		t.Errorf("Remote sender received %d events, want 1", count)
	}
}

func TestContextLogger_Info(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	ctx := context.Background()
	ctxLogger := logger.WithContext(ctx, "job-123", "report-456")

	ctxLogger.Info(EventScanStarted, "Test", map[string]interface{}{"key": "value"})

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Severity != SeverityInfo {
		t.Errorf("Severity = %s, want %s", event.Severity, SeverityInfo)
	}
}

func TestContextLogger_Error(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	logger, _ := NewLogger(&LoggerConfig{
		LogFile:    logFile,
		BufferSize: 1,
	})
	logger.Start()

	ctx := context.Background()
	ctxLogger := logger.WithContext(ctx, "job-123", "report-456")

	ctxLogger.Error(EventScanFailed, "Test error", errors.New("test"), nil)

	time.Sleep(50 * time.Millisecond)
	logger.Stop()

	data, _ := os.ReadFile(logFile)
	var event Event
	json.Unmarshal(data, &event)

	if event.Severity != SeverityError {
		t.Errorf("Severity = %s, want %s", event.Severity, SeverityError)
	}

	if event.Error != "test" {
		t.Errorf("Error = %s, want test", event.Error)
	}
}

func TestEventTypes(t *testing.T) {
	// Verify event type constants are unique
	types := []EventType{
		EventAgentStart, EventAgentStop, EventAgentError,
		EventJobReceived, EventJobStarted, EventJobCompleted, EventJobFailed, EventJobTimeout,
		EventScanStarted, EventScanCompleted, EventScanFailed,
		EventUploadStarted, EventUploadCompleted, EventUploadFailed, EventUploadRetry,
		EventChunkCreated, EventChunkUploaded, EventChunkFailed, EventChunkCleanup,
		EventResourceThrottle, EventResourceResume, EventResourceWarning,
		EventAuthFailed, EventRateLimited, EventValidationError,
	}

	seen := make(map[EventType]bool)
	for _, et := range types {
		if seen[et] {
			t.Errorf("Duplicate event type: %s", et)
		}
		seen[et] = true
	}
}

func TestSeverityLevels(t *testing.T) {
	// Verify severity levels are valid
	levels := []Severity{
		SeverityDebug, SeverityInfo, SeverityWarning, SeverityError, SeverityCritical,
	}

	for _, s := range levels {
		if s == "" {
			t.Error("Severity should not be empty")
		}
	}
}
