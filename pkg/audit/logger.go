// Package audit provides structured audit logging for agent operations.
//
// All critical agent operations should be logged via this package to enable:
// - Security monitoring and incident response
// - Debugging and troubleshooting
// - Compliance and audit trails
// - Remote log collection (when configured)
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType represents the type of audit event.
type EventType string

const (
	// Lifecycle events
	EventAgentStart EventType = "agent_start"
	EventAgentStop  EventType = "agent_stop"
	EventAgentError EventType = "agent_error"

	// Job events
	EventJobReceived  EventType = "job_received"
	EventJobStarted   EventType = "job_started"
	EventJobCompleted EventType = "job_completed"
	EventJobFailed    EventType = "job_failed"
	EventJobTimeout   EventType = "job_timeout"

	// Scan events
	EventScanStarted   EventType = "scan_started"
	EventScanCompleted EventType = "scan_completed"
	EventScanFailed    EventType = "scan_failed"

	// Upload events
	EventUploadStarted   EventType = "upload_started"
	EventUploadCompleted EventType = "upload_completed"
	EventUploadFailed    EventType = "upload_failed"
	EventUploadRetry     EventType = "upload_retry"

	// Chunk events
	EventChunkCreated  EventType = "chunk_created"
	EventChunkUploaded EventType = "chunk_uploaded"
	EventChunkFailed   EventType = "chunk_failed"
	EventChunkCleanup  EventType = "chunk_cleanup"

	// Resource events
	EventResourceThrottle EventType = "resource_throttle"
	EventResourceResume   EventType = "resource_resume"
	EventResourceWarning  EventType = "resource_warning"

	// Security events
	EventAuthFailed      EventType = "auth_failed"
	EventRateLimited     EventType = "rate_limited"
	EventValidationError EventType = "validation_error"
)

// Severity represents log severity level.
type Severity string

const (
	SeverityDebug    Severity = "DEBUG"
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARN"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

// Event represents an audit event.
type Event struct {
	Timestamp time.Time              `json:"timestamp"`
	Type      EventType              `json:"type"`
	Severity  Severity               `json:"severity"`
	AgentID   string                 `json:"agent_id,omitempty"`
	TenantID  string                 `json:"tenant_id,omitempty"`
	JobID     string                 `json:"job_id,omitempty"`
	ReportID  string                 `json:"report_id,omitempty"`
	Message   string                 `json:"message"`
	Error     string                 `json:"error,omitempty"`
	Duration  time.Duration          `json:"duration_ms,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// LoggerConfig configures the audit logger.
type LoggerConfig struct {
	// AgentID is the agent identifier included in all events.
	AgentID string

	// TenantID is the tenant identifier (if known).
	TenantID string

	// LogFile is the path to the audit log file.
	// Default: ~/.openctem/audit.log
	LogFile string

	// MaxSizeMB is the maximum log file size before rotation.
	// Default: 100MB
	MaxSizeMB int

	// MaxAgeDays is the maximum age of log files before deletion.
	// Default: 30 days
	MaxAgeDays int

	// RemoteEndpoint is the URL for remote log collection (optional).
	RemoteEndpoint string

	// BufferSize is the number of events to buffer before flushing.
	// Default: 100
	BufferSize int

	// FlushInterval is how often to flush buffered events.
	// Default: 5 seconds
	FlushInterval time.Duration

	// Verbose enables console output of audit events.
	Verbose bool
}

// DefaultLoggerConfig returns sensible defaults.
func DefaultLoggerConfig() *LoggerConfig {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}

	return &LoggerConfig{
		LogFile:       filepath.Join(home, ".openctem", "audit.log"),
		MaxSizeMB:     100,
		MaxAgeDays:    30,
		BufferSize:    100,
		FlushInterval: 5 * time.Second,
	}
}

// Logger is the audit logger.
type Logger struct {
	config *LoggerConfig
	file   *os.File
	mu     sync.Mutex

	buffer   []Event
	bufferMu sync.Mutex

	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Callbacks for remote sending
	remoteSender func([]Event) error
}

// NewLogger creates a new audit logger.
func NewLogger(config *LoggerConfig) (*Logger, error) {
	if config == nil {
		config = DefaultLoggerConfig()
	}

	// Apply defaults for zero values
	if config.LogFile == "" {
		config.LogFile = DefaultLoggerConfig().LogFile
	}
	if config.BufferSize <= 0 {
		config.BufferSize = 100
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 5 * time.Second
	}

	// Ensure log directory exists
	dir := filepath.Dir(config.LogFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	// Open log file for append (0640 = owner read/write, group read)
	file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	l := &Logger{
		config: config,
		file:   file,
		buffer: make([]Event, 0, config.BufferSize),
		stopCh: make(chan struct{}),
	}

	return l, nil
}

// Start begins background flushing.
func (l *Logger) Start() {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return
	}
	l.running = true
	l.stopCh = make(chan struct{})
	l.mu.Unlock()

	l.wg.Add(1)
	go l.flushLoop()
}

// Stop stops the logger and flushes remaining events.
func (l *Logger) Stop() error {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return nil
	}
	l.running = false
	close(l.stopCh)
	l.mu.Unlock()

	l.wg.Wait()

	// Final flush
	l.Flush()

	// Close file
	return l.file.Close()
}

// Log records an audit event.
func (l *Logger) Log(event Event) {
	event.Timestamp = time.Now()
	if event.AgentID == "" {
		event.AgentID = l.config.AgentID
	}
	if event.TenantID == "" {
		event.TenantID = l.config.TenantID
	}

	l.bufferMu.Lock()
	l.buffer = append(l.buffer, event)
	shouldFlush := len(l.buffer) >= l.config.BufferSize
	l.bufferMu.Unlock()

	if l.config.Verbose {
		l.printEvent(event)
	}

	if shouldFlush {
		go l.Flush()
	}
}

// Convenience methods for common event types

// Info logs an informational event.
func (l *Logger) Info(eventType EventType, message string, details map[string]interface{}) {
	l.Log(Event{
		Type:     eventType,
		Severity: SeverityInfo,
		Message:  message,
		Details:  details,
	})
}

// Error logs an error event.
func (l *Logger) Error(eventType EventType, message string, err error, details map[string]interface{}) {
	event := Event{
		Type:     eventType,
		Severity: SeverityError,
		Message:  message,
		Details:  details,
	}
	if err != nil {
		event.Error = err.Error()
	}
	l.Log(event)
}

// JobStarted logs a job start event.
func (l *Logger) JobStarted(jobID, jobType string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["job_type"] = jobType
	l.Log(Event{
		Type:     EventJobStarted,
		Severity: SeverityInfo,
		JobID:    jobID,
		Message:  fmt.Sprintf("Job started: %s", jobType),
		Details:  details,
	})
}

// JobCompleted logs a job completion event.
func (l *Logger) JobCompleted(jobID string, duration time.Duration, details map[string]interface{}) {
	l.Log(Event{
		Type:     EventJobCompleted,
		Severity: SeverityInfo,
		JobID:    jobID,
		Message:  "Job completed successfully",
		Duration: duration,
		Details:  details,
	})
}

// JobFailed logs a job failure event.
func (l *Logger) JobFailed(jobID string, err error, details map[string]interface{}) {
	event := Event{
		Type:     EventJobFailed,
		Severity: SeverityError,
		JobID:    jobID,
		Message:  "Job failed",
		Details:  details,
	}
	if err != nil {
		event.Error = err.Error()
	}
	l.Log(event)
}

// ChunkUploaded logs a chunk upload event.
func (l *Logger) ChunkUploaded(reportID string, chunkIndex, totalChunks int, size int) {
	l.Log(Event{
		Type:     EventChunkUploaded,
		Severity: SeverityInfo,
		ReportID: reportID,
		Message:  fmt.Sprintf("Chunk %d/%d uploaded", chunkIndex+1, totalChunks),
		Details: map[string]interface{}{
			"chunk_index":  chunkIndex,
			"total_chunks": totalChunks,
			"size_bytes":   size,
		},
	})
}

// ResourceThrottle logs a resource throttling event.
func (l *Logger) ResourceThrottle(reason string, metrics map[string]interface{}) {
	l.Log(Event{
		Type:     EventResourceThrottle,
		Severity: SeverityWarning,
		Message:  "Resource throttling activated: " + reason,
		Details:  metrics,
	})
}

// Flush writes buffered events to disk.
func (l *Logger) Flush() {
	l.bufferMu.Lock()
	if len(l.buffer) == 0 {
		l.bufferMu.Unlock()
		return
	}
	events := l.buffer
	l.buffer = make([]Event, 0, l.config.BufferSize)
	l.bufferMu.Unlock()

	// Write to file
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			continue
		}
		_, _ = l.file.Write(data)
		_, _ = l.file.Write([]byte("\n"))
	}

	// Sync to disk
	_ = l.file.Sync()

	// Send to remote if configured
	if l.remoteSender != nil {
		go l.remoteSender(events) //nolint:errcheck // async send, errors handled internally
	}
}

// flushLoop periodically flushes buffered events.
func (l *Logger) flushLoop() {
	defer l.wg.Done()

	ticker := time.NewTicker(l.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.Flush()
		}
	}
}

// printEvent prints an event to console in human-readable format.
func (l *Logger) printEvent(event Event) {
	timestamp := event.Timestamp.Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] [%s] %s: %s\n", timestamp, event.Severity, event.Type, event.Message)
	if event.Error != "" {
		fmt.Printf("  Error: %s\n", event.Error)
	}
}

// SetRemoteSender sets the callback for sending events to a remote endpoint.
func (l *Logger) SetRemoteSender(sender func([]Event) error) {
	l.remoteSender = sender
}

// WithContext returns a context-aware logger wrapper.
func (l *Logger) WithContext(ctx context.Context, jobID, reportID string) *ContextLogger {
	return &ContextLogger{
		logger:   l,
		ctx:      ctx,
		jobID:    jobID,
		reportID: reportID,
	}
}

// ContextLogger wraps Logger with context information.
type ContextLogger struct {
	logger   *Logger
	ctx      context.Context
	jobID    string
	reportID string
}

// Info logs an info event with context.
func (cl *ContextLogger) Info(eventType EventType, message string, details map[string]interface{}) {
	cl.logger.Log(Event{
		Type:     eventType,
		Severity: SeverityInfo,
		JobID:    cl.jobID,
		ReportID: cl.reportID,
		Message:  message,
		Details:  details,
	})
}

// Error logs an error event with context.
func (cl *ContextLogger) Error(eventType EventType, message string, err error, details map[string]interface{}) {
	event := Event{
		Type:     eventType,
		Severity: SeverityError,
		JobID:    cl.jobID,
		ReportID: cl.reportID,
		Message:  message,
		Details:  details,
	}
	if err != nil {
		event.Error = err.Error()
	}
	cl.logger.Log(event)
}
