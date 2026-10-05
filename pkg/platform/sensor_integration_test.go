package platform

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/audit" //nolint:staticcheck // the removed platform-mode client; removed with it
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/pipeline" //nolint:staticcheck // the removed platform-mode client; removed with it
	"github.com/openctemio/sdk-go/pkg/resource"
)

// mockJobExecutor implements JobExecutor for testing
type mockJobExecutor struct {
	executeFunc func(ctx context.Context, job *JobInfo) (*JobResult, error)
}

func (m *mockJobExecutor) Execute(ctx context.Context, job *JobInfo) (*JobResult, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, job)
	}
	return &JobResult{
		JobID:  job.ID,
		Status: "completed",
	}, nil
}

// mockPipelineUploader implements pipeline.Uploader for testing
type mockPipelineUploader struct {
	uploadFunc func(ctx context.Context, report *ctis.Report) (*pipeline.Result, error)
	uploads    int
	mu         sync.Mutex
}

func (m *mockPipelineUploader) Upload(ctx context.Context, report *ctis.Report) (*pipeline.Result, error) {
	m.mu.Lock()
	m.uploads++
	m.mu.Unlock()
	if m.uploadFunc != nil {
		return m.uploadFunc(ctx, report)
	}
	return &pipeline.Result{
		Status:          "completed",
		FindingsCreated: len(report.Findings),
	}, nil
}

func (m *mockPipelineUploader) getUploads() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uploads
}

func TestSensorBuilder_WithResourceController(t *testing.T) {
	executor := &mockJobExecutor{}

	sensor, err := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-sensor-id").
		WithExecutor(executor).
		WithMaxJobs(4).
		WithResourceController(&resource.ControllerConfig{
			CPUThreshold:      80.0,
			MemoryThreshold:   80.0,
			MaxConcurrentJobs: 4,
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if sensor.ResourceController() == nil {
		t.Error("Expected resource controller to be created")
	}

	// Verify the controller has correct max jobs
	status := sensor.ResourceController().GetStatus()
	if status.MaxJobs != 4 {
		t.Errorf("MaxJobs = %d, want 4", status.MaxJobs)
	}
}

func TestSensorBuilder_WithAuditLogger(t *testing.T) {
	// Create temp directory for audit log
	tmpDir, err := os.MkdirTemp("", "sensor-audit-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}

	sensor, err := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-sensor-id").
		WithExecutor(executor).
		WithAuditLogger(&audit.LoggerConfig{
			LogFile:       filepath.Join(tmpDir, "audit.log"),
			BufferSize:    10,
			FlushInterval: 100 * time.Millisecond,
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if sensor.AuditLogger() == nil {
		t.Error("Expected audit logger to be created")
	}
}

func TestSensorBuilder_WithPipeline(t *testing.T) {
	executor := &mockJobExecutor{}
	uploader := &mockPipelineUploader{}

	sensor, err := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-sensor-id").
		WithExecutor(executor).
		WithPipeline(&pipeline.PipelineConfig{
			QueueSize: 100,
			Workers:   2,
		}, uploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if sensor.Pipeline() == nil {
		t.Error("Expected pipeline to be created")
	}
}

func TestSensorBuilder_FullIntegration(t *testing.T) {
	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "sensor-full-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}
	pipelineUploader := &mockPipelineUploader{}
	sensor, err := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-sensor-id").
		WithExecutor(executor).
		WithMaxJobs(4).
		WithVerbose(false).
		WithResourceController(&resource.ControllerConfig{
			CPUThreshold:    85.0,
			MemoryThreshold: 85.0,
		}).
		WithAuditLogger(&audit.LoggerConfig{
			LogFile:       filepath.Join(tmpDir, "audit.log"),
			BufferSize:    10,
			FlushInterval: 100 * time.Millisecond,
		}).
		WithPipeline(&pipeline.PipelineConfig{
			QueueSize: 100,
			Workers:   2,
		}, pipelineUploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify all components are created
	if sensor.ResourceController() == nil {
		t.Error("Expected resource controller to be created")
	}
	if sensor.AuditLogger() == nil {
		t.Error("Expected audit logger to be created")
	}
	if sensor.Pipeline() == nil {
		t.Error("Expected pipeline to be created")
	}
}

func TestPlatformSensor_SubmitReport(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "sensor-submit-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}
	pipelineUploader := &mockPipelineUploader{}

	sensor, err := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-sensor-id").
		WithExecutor(executor).
		WithPipeline(&pipeline.PipelineConfig{
			QueueSize: 100,
			Workers:   2,
		}, pipelineUploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Start the pipeline
	ctx := context.Background()
	sensor.uploadPipeline.Start(ctx)
	defer sensor.uploadPipeline.Stop(ctx)

	// Submit a report
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "test-tool"},
		Findings: []ctis.Finding{
			{Title: "Finding 1"},
			{Title: "Finding 2"},
		},
	}

	id, err := sensor.SubmitReport(report, pipeline.WithJobID("test-job"))
	if err != nil {
		t.Fatalf("SubmitReport failed: %v", err)
	}
	if id == "" {
		t.Error("Expected non-empty report ID")
	}

	// Wait for upload
	time.Sleep(100 * time.Millisecond)

	if pipelineUploader.getUploads() != 1 {
		t.Errorf("Expected 1 upload, got %d", pipelineUploader.getUploads())
	}
}

func TestPlatformSensor_ExtendedStatus(t *testing.T) {
	executor := &mockJobExecutor{}

	sensor, err := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-sensor-id").
		WithExecutor(executor).
		WithResourceController(&resource.ControllerConfig{
			MaxConcurrentJobs: 4,
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	status := sensor.ExtendedStatus()
	if status == nil {
		t.Fatal("Expected non-nil status")
	}
	if status.ResourceStatus == nil {
		t.Error("Expected ResourceStatus to be populated")
	}
	if status.ResourceStatus.MaxJobs != 4 {
		t.Errorf("MaxJobs = %d, want 4", status.ResourceStatus.MaxJobs)
	}
}

func TestSensorBuilder_ValidationErrors(t *testing.T) {
	executor := &mockJobExecutor{}

	tests := []struct {
		name    string
		builder *SensorBuilder
		wantErr string
	}{
		{
			name:    "missing base URL",
			builder: NewSensorBuilder().WithCredentials("", "key", "id").WithExecutor(executor),
			wantErr: "base URL is required",
		},
		{
			name:    "missing API key",
			builder: NewSensorBuilder().WithCredentials("http://localhost", "", "id").WithExecutor(executor),
			wantErr: "API key is required",
		},
		{
			name:    "missing sensor ID",
			builder: NewSensorBuilder().WithCredentials("http://localhost", "key", "").WithExecutor(executor),
			wantErr: "sensor ID is required",
		},
		{
			name:    "missing executor",
			builder: NewSensorBuilder().WithCredentials("http://localhost", "key", "id"),
			wantErr: "executor is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.builder.Build()
			if err == nil {
				t.Error("Expected error, got nil")
				return
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSensorBuilder_FluentAPI(t *testing.T) {
	executor := &mockJobExecutor{}

	// Test that all builder methods return the builder for chaining
	builder := NewSensorBuilder().
		WithCredentials("http://localhost:8080", "key", "id").
		WithExecutor(executor).
		WithLeaseDuration(60*time.Second).
		WithRenewInterval(20*time.Second).
		WithMaxJobs(4).
		WithPollTimeout(30*time.Second).
		WithCapabilities("sast", "sca").
		WithVerbose(true).
		OnLeaseExpired(func() {}).
		OnJobStarted(func(*JobInfo) {}).
		OnJobCompleted(func(*JobInfo, *JobResult) {})

	if builder == nil {
		t.Fatal("Builder should not be nil")
	}

	sensor, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if sensor.config.Verbose != true {
		t.Error("Verbose should be true")
	}
}
