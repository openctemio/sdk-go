package chunk

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/sdk-go/pkg/compress"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Uploader is the interface for uploading chunks.
type Uploader interface {
	// UploadChunk uploads a single chunk.
	UploadChunk(ctx context.Context, data *ChunkData) error
}

// Manager handles chunking, storage, and upload coordination.
type Manager struct {
	cfg        *Config
	storage    *Storage
	splitter   *Splitter
	compressor *compress.Compressor
	uploader   Uploader

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Callbacks
	onProgress func(*Progress)
	onComplete func(reportID string)
	onError    func(reportID string, err error)

	verbose bool
}

// NewManager creates a new chunk manager.
func NewManager(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Initialize storage
	storage, err := NewStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("init storage: %w", err)
	}

	// Initialize compressor
	compressor := compress.NewCompressor(compress.AlgorithmZSTD, compress.Level(cfg.CompressionLevel))

	return &Manager{
		cfg:        cfg,
		storage:    storage,
		splitter:   NewSplitter(cfg),
		compressor: compressor,
		stopCh:     make(chan struct{}),
	}, nil
}

// SetUploader configures the uploader.
func (m *Manager) SetUploader(uploader Uploader) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploader = uploader
}

// SetCallbacks sets the callback functions.
func (m *Manager) SetCallbacks(onProgress func(*Progress), onComplete func(string), onError func(string, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onProgress = onProgress
	m.onComplete = onComplete
	m.onError = onError
}

// SetVerbose enables verbose logging.
func (m *Manager) SetVerbose(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verbose = v
}

// NeedsChunking checks if a report needs to be chunked.
func (m *Manager) NeedsChunking(report *ctis.Report) bool {
	return m.splitter.NeedsChunking(report)
}

// SubmitReport queues a report for chunked upload.
// Returns immediately after storing chunks to SQLite.
func (m *Manager) SubmitReport(ctx context.Context, report *ctis.Report) (*Report, error) {
	// Split report into chunks
	chunkDataList, err := m.splitter.Split(report)
	if err != nil {
		return nil, fmt.Errorf("split report: %w", err)
	}

	reportID := chunkDataList[0].ReportID
	now := time.Now()

	// Calculate original size
	originalData, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	originalSize := len(originalData)

	// Create report record
	r := &Report{
		ID:                    reportID,
		OriginalFindingsCount: len(report.Findings),
		OriginalAssetsCount:   len(report.Assets),
		OriginalSize:          originalSize,
		TotalChunks:           len(chunkDataList),
		Status:                ReportStatusPending,
		CompressionAlgo:       string(m.compressor.Algorithm()),
		CreatedAt:             now,
		UpdatedAt:             now,
		Metadata: &Metadata{
			ScanID: reportID,
		},
	}

	if report.Tool != nil {
		r.Metadata.ToolName = report.Tool.Name
		r.Metadata.ToolVersion = report.Tool.Version
	}

	// Store report
	if err := m.storage.SaveReport(ctx, r); err != nil {
		return nil, fmt.Errorf("save report: %w", err)
	}

	// Store chunks
	totalCompressedSize := 0
	for i, chunkData := range chunkDataList {
		// Serialize chunk data
		data, err := json.Marshal(chunkData)
		if err != nil {
			return nil, fmt.Errorf("marshal chunk %d: %w", i, err)
		}

		// Compress chunk data
		compressed, err := m.compressor.Compress(data)
		if err != nil {
			return nil, fmt.Errorf("compress chunk %d: %w", i, err)
		}

		chunk := &Chunk{
			ID:               uuid.New().String(),
			ReportID:         reportID,
			ChunkIndex:       i,
			TotalChunks:      len(chunkDataList),
			Data:             compressed,
			UncompressedSize: len(data),
			CompressedSize:   len(compressed),
			Status:           ChunkStatusPending,
			CreatedAt:        now,
		}

		if err := m.storage.SaveChunk(ctx, chunk); err != nil {
			return nil, fmt.Errorf("save chunk %d: %w", i, err)
		}

		totalCompressedSize += len(compressed)
	}

	// Update report with compressed size
	r.CompressedSize = totalCompressedSize
	if err := m.storage.SaveReport(ctx, r); err != nil {
		return nil, fmt.Errorf("update report size: %w", err)
	}

	if m.verbose {
		fmt.Printf("[chunk] Report %s queued: %d chunks, %d bytes -> %d bytes\n",
			reportID, len(chunkDataList), originalSize, totalCompressedSize)
	}

	return r, nil
}

// Start begins background upload processing.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	if m.uploader == nil {
		m.mu.Unlock()
		return fmt.Errorf("uploader not configured")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.wg.Add(1)
	go m.uploadLoop(ctx)

	return nil
}

// Stop gracefully stops the upload process.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	m.wg.Wait()
}

// IsRunning returns whether the manager is running.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetProgress returns upload progress for a report.
func (m *Manager) GetProgress(ctx context.Context, reportID string) (*Progress, error) {
	report, err := m.storage.GetReport(ctx, reportID)
	if err != nil {
		return nil, err
	}
	if report == nil {
		return nil, fmt.Errorf("report not found: %s", reportID)
	}
	return report.CalculateProgress(), nil
}

// GetStats returns storage statistics.
func (m *Manager) GetStats(ctx context.Context) (*StorageStats, error) {
	return m.storage.GetStorageStats(ctx)
}

// uploadLoop runs the background upload process.
func (m *Manager) uploadLoop(ctx context.Context) {
	defer m.wg.Done()

	uploadDelay := time.Duration(m.cfg.UploadDelayMs) * time.Millisecond
	ticker := time.NewTicker(uploadDelay)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-cleanupTicker.C:
			m.cleanup(ctx)
		case <-ticker.C:
			m.processNextChunk(ctx)
		}
	}
}

// processNextChunk uploads the next pending chunk.
func (m *Manager) processNextChunk(ctx context.Context) {
	chunk, err := m.storage.GetNextPendingChunk(ctx)
	if err != nil {
		if m.verbose {
			fmt.Printf("[chunk] Error getting next chunk: %v\n", err)
		}
		return
	}
	if chunk == nil {
		return // No pending chunks
	}

	// Update status to uploading
	if err := m.storage.UpdateChunkStatus(ctx, chunk.ID, ChunkStatusUploading, ""); err != nil {
		if m.verbose {
			fmt.Printf("[chunk] Error updating status: %v\n", err)
		}
		return
	}

	// Decompress chunk data
	decompressed, err := m.compressor.Decompress(chunk.Data)
	if err != nil {
		m.handleChunkFailure(ctx, chunk, fmt.Sprintf("decompress error: %v", err))
		return
	}

	// Unmarshal chunk data
	var chunkData ChunkData
	if err := json.Unmarshal(decompressed, &chunkData); err != nil {
		m.handleChunkFailure(ctx, chunk, fmt.Sprintf("unmarshal error: %v", err))
		return
	}

	// Upload chunk
	if err := m.uploader.UploadChunk(ctx, &chunkData); err != nil {
		m.handleChunkFailure(ctx, chunk, fmt.Sprintf("upload error: %v", err))
		return
	}

	// Mark as completed
	if err := m.storage.UpdateChunkStatus(ctx, chunk.ID, ChunkStatusCompleted, ""); err != nil {
		if m.verbose {
			fmt.Printf("[chunk] Error marking completed: %v\n", err)
		}
		return
	}

	// Increment completed count
	if err := m.storage.IncrementCompletedChunks(ctx, chunk.ReportID); err != nil {
		if m.verbose {
			fmt.Printf("[chunk] Error incrementing completed: %v\n", err)
		}
		return
	}

	// Auto-cleanup: Delete chunk data immediately after successful upload
	// This prevents disk bloat on agent machines
	if m.cfg.AutoCleanupOnUpload {
		if err := m.storage.DeleteChunkData(ctx, chunk.ID); err != nil {
			if m.verbose {
				fmt.Printf("[chunk] Error deleting chunk data: %v\n", err)
			}
		} else if m.verbose {
			fmt.Printf("[chunk] Cleaned up chunk %s data after upload\n", chunk.ID)
		}
	}

	if m.verbose {
		fmt.Printf("[chunk] Chunk %d/%d uploaded for report %s\n",
			chunk.ChunkIndex+1, chunk.TotalChunks, chunk.ReportID)
	}

	// Check if report is complete
	m.checkReportCompletion(ctx, chunk.ReportID)

	// Notify progress
	m.notifyProgress(ctx, chunk.ReportID)
}

// handleChunkFailure handles a failed chunk upload.
func (m *Manager) handleChunkFailure(ctx context.Context, chunk *Chunk, errorMsg string) {
	if m.verbose {
		fmt.Printf("[chunk] Chunk %d failed for report %s: %s\n",
			chunk.ChunkIndex, chunk.ReportID, errorMsg)
	}

	// Check if can retry
	if chunk.CanRetry(m.cfg.MaxRetries) {
		// Reset to pending for retry AND increment retry_count. Plain
		// UpdateChunkStatus(pending) never bumped retry_count (it only counts
		// the 'failed' status), so CanRetry stayed true forever → a chunk that
		// kept failing was retried infinitely and ProcessPending never drained.
		_ = m.storage.RequeueForRetry(ctx, chunk.ID, errorMsg)
		return
	}

	// Mark as failed
	_ = m.storage.UpdateChunkStatus(ctx, chunk.ID, ChunkStatusFailed, errorMsg)
	_ = m.storage.IncrementFailedChunks(ctx, chunk.ReportID)

	// Check if report should be marked as failed
	m.checkReportCompletion(ctx, chunk.ReportID)
}

// checkReportCompletion checks if a report is complete or failed.
func (m *Manager) checkReportCompletion(ctx context.Context, reportID string) {
	report, err := m.storage.GetReport(ctx, reportID)
	if err != nil || report == nil {
		return
	}

	// Check if all chunks are done (completed or failed)
	totalDone := report.CompletedChunks + report.FailedChunks
	if totalDone < report.TotalChunks {
		return
	}

	// Determine final status
	var newStatus ReportStatus
	if report.FailedChunks > 0 {
		newStatus = ReportStatusFailed
	} else {
		newStatus = ReportStatusCompleted
	}

	if err := m.storage.UpdateReportStatus(ctx, reportID, newStatus); err != nil {
		return
	}

	// Notify callbacks
	m.mu.RLock()
	onComplete := m.onComplete
	onError := m.onError
	m.mu.RUnlock()

	if newStatus == ReportStatusCompleted {
		// Auto-cleanup: Delete all chunks when report completes
		if m.cfg.CleanupOnReportComplete {
			if deleted, err := m.storage.DeleteReportChunks(ctx, reportID); err != nil {
				if m.verbose {
					fmt.Printf("[chunk] Error cleaning up completed report %s: %v\n", reportID, err)
				}
			} else if m.verbose && deleted > 0 {
				fmt.Printf("[chunk] Cleaned up %d chunks for completed report %s\n", deleted, reportID)
			}
		}

		if onComplete != nil {
			onComplete(reportID)
		}
		if m.verbose {
			fmt.Printf("[chunk] Report %s completed successfully\n", reportID)
		}
	} else {
		if onError != nil {
			onError(reportID, fmt.Errorf("report failed: %d chunks failed", report.FailedChunks))
		}
		if m.verbose {
			fmt.Printf("[chunk] Report %s failed: %d/%d chunks failed\n",
				reportID, report.FailedChunks, report.TotalChunks)
		}
	}
}

// notifyProgress notifies progress callbacks.
func (m *Manager) notifyProgress(ctx context.Context, reportID string) {
	m.mu.RLock()
	onProgress := m.onProgress
	m.mu.RUnlock()

	if onProgress == nil {
		return
	}

	progress, err := m.GetProgress(ctx, reportID)
	if err != nil {
		return
	}

	onProgress(progress)
}

// cleanup removes old completed reports.
func (m *Manager) cleanup(ctx context.Context) {
	maxAge := time.Duration(m.cfg.RetentionHours) * time.Hour
	count, err := m.storage.Cleanup(ctx, maxAge)
	if err != nil {
		if m.verbose {
			fmt.Printf("[chunk] Cleanup error: %v\n", err)
		}
		return
	}

	if count > 0 && m.verbose {
		fmt.Printf("[chunk] Cleaned up %d old reports\n", count)
	}

	// Aggressive cleanup if storage exceeds limit
	if m.cfg.AggressiveCleanup && m.cfg.MaxStorageMB > 0 {
		m.aggressiveCleanup(ctx)
	}
}

// aggressiveCleanup removes data when storage exceeds limit.
func (m *Manager) aggressiveCleanup(ctx context.Context) {
	stats, err := m.storage.GetStorageStats(ctx)
	if err != nil {
		return
	}

	maxBytes := int64(m.cfg.MaxStorageMB) * 1024 * 1024
	if stats.TotalStorageBytes > maxBytes {
		// Delete oldest completed reports until under limit
		deleted, err := m.storage.CleanupToSize(ctx, maxBytes)
		if err != nil {
			if m.verbose {
				fmt.Printf("[chunk] Aggressive cleanup error: %v\n", err)
			}
			return
		}
		if deleted > 0 && m.verbose {
			fmt.Printf("[chunk] Aggressive cleanup: removed %d reports (storage was %d MB, limit %d MB)\n",
				deleted, stats.TotalStorageBytes/1024/1024, m.cfg.MaxStorageMB)
		}
	}
}

// ProcessPending processes all pending chunks immediately (for testing).
func (m *Manager) ProcessPending(ctx context.Context) error {
	if m.uploader == nil {
		return fmt.Errorf("uploader not configured")
	}

	for {
		chunk, err := m.storage.GetNextPendingChunk(ctx)
		if err != nil {
			return err
		}
		if chunk == nil {
			return nil // All done
		}
		m.processNextChunk(ctx)
	}
}

// Close releases resources.
func (m *Manager) Close() error {
	m.Stop()
	return m.storage.Close()
}
