package chunk

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// mockUploader implements the Uploader interface for testing.
type mockUploader struct {
	uploads     int64
	failCount   int
	failedSoFar int
}

func (m *mockUploader) UploadChunk(ctx context.Context, data *ChunkData) error {
	if m.failCount > 0 && m.failedSoFar < m.failCount {
		m.failedSoFar++
		return ctx.Err() // Simulate error
	}
	atomic.AddInt64(&m.uploads, 1)
	return nil
}

func (m *mockUploader) UploadCount() int {
	return int(atomic.LoadInt64(&m.uploads))
}

func TestManager_SubmitReport_Small(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.MinFindingsForChunking = 100
	cfg.MinAssetsForChunking = 50

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// Create small report (no chunking needed)
	report := createTestReport(10, 5)

	ctx := context.Background()
	r, err := mgr.SubmitReport(ctx, report)
	if err != nil {
		t.Fatalf("SubmitReport: %v", err)
	}

	if r.TotalChunks != 1 {
		t.Errorf("Expected 1 chunk for small report, got %d", r.TotalChunks)
	}

	if r.Status != ReportStatusPending {
		t.Errorf("Expected status pending, got %s", r.Status)
	}
}

func TestManager_SubmitReport_Large(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.MinFindingsForChunking = 100
	cfg.MaxFindingsPerChunk = 50

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// Create large report (chunking needed)
	report := createTestReportWithAssetRefs(200, 10)

	ctx := context.Background()
	r, err := mgr.SubmitReport(ctx, report)
	if err != nil {
		t.Fatalf("SubmitReport: %v", err)
	}

	if r.TotalChunks < 2 {
		t.Errorf("Expected multiple chunks for large report, got %d", r.TotalChunks)
	}

	t.Logf("Report submitted: %d chunks, original size: %d, compressed size: %d",
		r.TotalChunks, r.OriginalSize, r.CompressedSize)
}

func TestManager_ProcessPending(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.MinFindingsForChunking = 100
	cfg.MaxFindingsPerChunk = 50

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// Set up mock uploader
	uploader := &mockUploader{}
	mgr.SetUploader(uploader)

	// Create and submit large report
	report := createTestReportWithAssetRefs(200, 10)

	ctx := context.Background()
	r, err := mgr.SubmitReport(ctx, report)
	if err != nil {
		t.Fatalf("SubmitReport: %v", err)
	}

	// Process all pending chunks
	if err := mgr.ProcessPending(ctx); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}

	// Check upload count
	if uploader.UploadCount() != r.TotalChunks {
		t.Errorf("Expected %d uploads, got %d", r.TotalChunks, uploader.UploadCount())
	}

	// Check progress
	progress, err := mgr.GetProgress(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetProgress: %v", err)
	}

	if progress.CompletedChunks != r.TotalChunks {
		t.Errorf("Expected %d completed chunks, got %d", r.TotalChunks, progress.CompletedChunks)
	}

	t.Logf("Progress: %d/%d chunks completed (%.1f%%)",
		progress.CompletedChunks, progress.TotalChunks, progress.PercentComplete)
}

func TestManager_Callbacks(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.MinFindingsForChunking = 100
	cfg.MaxFindingsPerChunk = 50

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// Set up mock uploader
	uploader := &mockUploader{}
	mgr.SetUploader(uploader)

	// Track callbacks
	var progressCount int
	var completedReportID string

	mgr.SetCallbacks(
		func(p *Progress) {
			progressCount++
		},
		func(reportID string) {
			completedReportID = reportID
		},
		nil,
	)

	// Create and submit large report
	report := createTestReportWithAssetRefs(200, 10)

	ctx := context.Background()
	r, err := mgr.SubmitReport(ctx, report)
	if err != nil {
		t.Fatalf("SubmitReport: %v", err)
	}

	// Process all pending chunks
	if err := mgr.ProcessPending(ctx); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}

	// Verify callbacks were called
	if progressCount == 0 {
		t.Error("Expected progress callbacks to be called")
	}

	if completedReportID != r.ID {
		t.Errorf("Expected completion callback with report ID %s, got %s", r.ID, completedReportID)
	}

	t.Logf("Callbacks: %d progress updates, completed report: %s", progressCount, completedReportID)
}

func TestManager_NeedsChunking(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.MinFindingsForChunking = 100
	cfg.MinAssetsForChunking = 50

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	tests := []struct {
		name     string
		findings int
		assets   int
		expected bool
	}{
		{"small report", 10, 5, false},
		{"at findings threshold", 100, 10, true},
		{"at assets threshold", 10, 50, true},
		{"large report", 500, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := createTestReport(tt.findings, tt.assets)
			result := mgr.NeedsChunking(report)
			if result != tt.expected {
				t.Errorf("NeedsChunking(%d findings, %d assets) = %v, want %v",
					tt.findings, tt.assets, result, tt.expected)
			}
		})
	}
}

func TestManager_StartStop(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.UploadDelayMs = 10 // Fast for testing

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// Set up mock uploader
	uploader := &mockUploader{}
	mgr.SetUploader(uploader)

	ctx := context.Background()

	// Start the manager
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if !mgr.IsRunning() {
		t.Error("Expected manager to be running")
	}

	// Stop the manager
	mgr.Stop()

	if mgr.IsRunning() {
		t.Error("Expected manager to be stopped")
	}
}

func TestManager_Stats(t *testing.T) {
	// Create temp directory for SQLite
	tmpDir, err := os.MkdirTemp("", "chunk-manager-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(tmpDir, "chunks.db")
	cfg.MinFindingsForChunking = 100
	cfg.MaxFindingsPerChunk = 50

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// Set up mock uploader
	uploader := &mockUploader{}
	mgr.SetUploader(uploader)

	// Create and submit reports with unique IDs
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		report := createTestReportWithAssetRefs(200, 10)
		// Make sure each report has a unique ID
		report.Metadata.ID = "test-report-" + string(rune('a'+i))
		if _, err := mgr.SubmitReport(ctx, report); err != nil {
			t.Fatalf("SubmitReport: %v", err)
		}
	}

	// Process all pending
	if err := mgr.ProcessPending(ctx); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}

	// Get stats
	stats, err := mgr.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	if stats.TotalReports != 3 {
		t.Errorf("Expected 3 total reports, got %d", stats.TotalReports)
	}

	if stats.CompletedReports != 3 {
		t.Errorf("Expected 3 completed reports, got %d", stats.CompletedReports)
	}

	t.Logf("Stats: %d reports, %d chunks, %d bytes stored",
		stats.TotalReports, stats.TotalChunks, stats.TotalStorageBytes)
}

// Helper functions createTestReport and createTestReportWithAssetRefs
// are defined in splitter_test.go
