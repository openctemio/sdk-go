package platform

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/audit"
	"github.com/openctemio/sdk-go/pkg/chunk"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/pipeline"
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

// mockChunkUploader implements chunk.Uploader for testing
type mockChunkUploader struct {
	uploadFunc func(ctx context.Context, data *chunk.ChunkData) error
	uploads    int
}

func (m *mockChunkUploader) UploadChunk(ctx context.Context, data *chunk.ChunkData) error {
	m.uploads++
	if m.uploadFunc != nil {
		return m.uploadFunc(ctx, data)
	}
	return nil
}

func TestAgentBuilder_WithResourceController(t *testing.T) {
	executor := &mockJobExecutor{}

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
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

	if agent.ResourceController() == nil {
		t.Error("Expected resource controller to be created")
	}

	// Verify the controller has correct max jobs
	status := agent.ResourceController().GetStatus()
	if status.MaxJobs != 4 {
		t.Errorf("MaxJobs = %d, want 4", status.MaxJobs)
	}
}

func TestAgentBuilder_WithAuditLogger(t *testing.T) {
	// Create temp directory for audit log
	tmpDir, err := os.MkdirTemp("", "agent-audit-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
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

	if agent.AuditLogger() == nil {
		t.Error("Expected audit logger to be created")
	}
}

func TestAgentBuilder_WithPipeline(t *testing.T) {
	executor := &mockJobExecutor{}
	uploader := &mockPipelineUploader{}

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
		WithExecutor(executor).
		WithPipeline(&pipeline.PipelineConfig{
			QueueSize: 100,
			Workers:   2,
		}, uploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if agent.Pipeline() == nil {
		t.Error("Expected pipeline to be created")
	}
}

func TestAgentBuilder_WithChunkManager(t *testing.T) {
	// Create temp directory for chunk storage
	tmpDir, err := os.MkdirTemp("", "agent-chunk-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}
	chunkUploader := &mockChunkUploader{}

	chunkConfig := chunk.DefaultConfig()
	chunkConfig.DatabasePath = filepath.Join(tmpDir, "chunks.db")

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
		WithExecutor(executor).
		WithChunkManager(chunkConfig, chunkUploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if agent.ChunkManager() == nil {
		t.Error("Expected chunk manager to be created")
	}
}

func TestAgentBuilder_FullIntegration(t *testing.T) {
	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "agent-full-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}
	pipelineUploader := &mockPipelineUploader{}
	chunkUploader := &mockChunkUploader{}

	chunkConfig := chunk.DefaultConfig()
	chunkConfig.DatabasePath = filepath.Join(tmpDir, "chunks.db")

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
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
		WithChunkManager(chunkConfig, chunkUploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify all components are created
	if agent.ResourceController() == nil {
		t.Error("Expected resource controller to be created")
	}
	if agent.AuditLogger() == nil {
		t.Error("Expected audit logger to be created")
	}
	if agent.Pipeline() == nil {
		t.Error("Expected pipeline to be created")
	}
	if agent.ChunkManager() == nil {
		t.Error("Expected chunk manager to be created")
	}
}

func TestPlatformAgent_SubmitReport(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "agent-submit-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}
	pipelineUploader := &mockPipelineUploader{}

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
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
	agent.uploadPipeline.Start(ctx)
	defer agent.uploadPipeline.Stop(ctx)

	// Submit a report
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "test-tool"},
		Findings: []ctis.Finding{
			{Title: "Finding 1"},
			{Title: "Finding 2"},
		},
	}

	id, err := agent.SubmitReport(report, pipeline.WithJobID("test-job"))
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

func TestPlatformAgent_NeedsChunking(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "agent-chunk-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	executor := &mockJobExecutor{}
	chunkUploader := &mockChunkUploader{}

	chunkConfig := chunk.DefaultConfig()
	chunkConfig.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	chunkConfig.MinFindingsForChunking = 10 // Low threshold for testing

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
		WithExecutor(executor).
		WithChunkManager(chunkConfig, chunkUploader).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Small report - shouldn't need chunking
	smallReport := &ctis.Report{
		Tool:     &ctis.Tool{Name: "test-tool"},
		Findings: []ctis.Finding{{Title: "Finding 1"}},
	}
	if agent.NeedsChunking(smallReport) {
		t.Error("Small report should not need chunking")
	}

	// Large report - should need chunking
	largeReport := &ctis.Report{
		Tool:     &ctis.Tool{Name: "test-tool"},
		Findings: make([]ctis.Finding, 20), // 20 findings > threshold of 10
	}
	for i := range largeReport.Findings {
		largeReport.Findings[i].Title = "Finding"
	}
	if !agent.NeedsChunking(largeReport) {
		t.Error("Large report should need chunking")
	}
}

func TestPlatformAgent_ExtendedStatus(t *testing.T) {
	executor := &mockJobExecutor{}

	agent, err := NewAgentBuilder().
		WithCredentials("http://localhost:8080", "test-api-key", "test-agent-id").
		WithExecutor(executor).
		WithResourceController(&resource.ControllerConfig{
			MaxConcurrentJobs: 4,
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	status := agent.ExtendedStatus()
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

func TestAgentBuilder_ValidationErrors(t *testing.T) {
	executor := &mockJobExecutor{}

	tests := []struct {
		name    string
		builder *AgentBuilder
		wantErr string
	}{
		{
			name:    "missing base URL",
			builder: NewAgentBuilder().WithCredentials("", "key", "id").WithExecutor(executor),
			wantErr: "base URL is required",
		},
		{
			name:    "missing API key",
			builder: NewAgentBuilder().WithCredentials("http://localhost", "", "id").WithExecutor(executor),
			wantErr: "API key is required",
		},
		{
			name:    "missing agent ID",
			builder: NewAgentBuilder().WithCredentials("http://localhost", "key", "").WithExecutor(executor),
			wantErr: "agent ID is required",
		},
		{
			name:    "missing executor",
			builder: NewAgentBuilder().WithCredentials("http://localhost", "key", "id"),
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

func TestAgentBuilder_FluentAPI(t *testing.T) {
	executor := &mockJobExecutor{}

	// Test that all builder methods return the builder for chaining
	builder := NewAgentBuilder().
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

	agent, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if agent.config.Verbose != true {
		t.Error("Verbose should be true")
	}
}
