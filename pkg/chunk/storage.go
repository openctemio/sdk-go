package chunk

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// Storage provides SQLite-based chunk storage.
type Storage struct {
	db  *sql.DB
	mu  sync.RWMutex
	cfg *Config
}

// NewStorage creates a new chunk storage.
func NewStorage(cfg *Config) (*Storage, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.DatabasePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}

	// Open database
	db, err := sql.Open("sqlite", cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure SQLite for better performance
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-64000", // 64MB cache
		"PRAGMA temp_store=MEMORY",
		"PRAGMA busy_timeout=5000",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("set pragma: %w", err)
		}
	}

	s := &Storage{
		db:  db,
		cfg: cfg,
	}

	// Initialize schema
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return s, nil
}

// initSchema creates the database tables if they don't exist.
func (s *Storage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS reports (
		id TEXT PRIMARY KEY,
		original_findings_count INTEGER NOT NULL,
		original_assets_count INTEGER NOT NULL,
		original_size INTEGER NOT NULL,
		compressed_size INTEGER NOT NULL DEFAULT 0,
		total_chunks INTEGER NOT NULL,
		completed_chunks INTEGER DEFAULT 0,
		failed_chunks INTEGER DEFAULT 0,
		status TEXT DEFAULT 'pending',
		compression_algo TEXT DEFAULT 'zstd',
		metadata TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		completed_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS chunks (
		id TEXT PRIMARY KEY,
		report_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		total_chunks INTEGER NOT NULL,
		data BLOB NOT NULL,
		uncompressed_size INTEGER NOT NULL,
		compressed_size INTEGER NOT NULL,
		status TEXT DEFAULT 'pending',
		retry_count INTEGER DEFAULT 0,
		last_error TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		uploaded_at TIMESTAMP,
		UNIQUE(report_id, chunk_index),
		FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_chunks_status ON chunks(status);
	CREATE INDEX IF NOT EXISTS idx_chunks_report_id ON chunks(report_id);
	CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
	CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveReport saves a report record.
func (s *Storage) SaveReport(ctx context.Context, report *Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	metadataJSON, err := json.Marshal(report.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO reports (
			id, original_findings_count, original_assets_count, original_size,
			compressed_size, total_chunks, completed_chunks, failed_chunks,
			status, compression_algo, metadata, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			completed_chunks = excluded.completed_chunks,
			failed_chunks = excluded.failed_chunks,
			status = excluded.status,
			updated_at = excluded.updated_at,
			completed_at = excluded.completed_at
	`,
		report.ID, report.OriginalFindingsCount, report.OriginalAssetsCount,
		report.OriginalSize, report.CompressedSize, report.TotalChunks,
		report.CompletedChunks, report.FailedChunks, report.Status,
		report.CompressionAlgo, string(metadataJSON),
		report.CreatedAt, report.UpdatedAt,
	)

	return err
}

// GetReport retrieves a report by ID.
func (s *Storage) GetReport(ctx context.Context, id string) (*Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var report Report
	var metadataJSON string
	var completedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT id, original_findings_count, original_assets_count, original_size,
			compressed_size, total_chunks, completed_chunks, failed_chunks,
			status, compression_algo, metadata, created_at, updated_at, completed_at
		FROM reports WHERE id = ?
	`, id).Scan(
		&report.ID, &report.OriginalFindingsCount, &report.OriginalAssetsCount,
		&report.OriginalSize, &report.CompressedSize, &report.TotalChunks,
		&report.CompletedChunks, &report.FailedChunks, &report.Status,
		&report.CompressionAlgo, &metadataJSON, &report.CreatedAt,
		&report.UpdatedAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if completedAt.Valid {
		report.CompletedAt = &completedAt.Time
	}

	if metadataJSON != "" {
		var metadata Metadata
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err == nil {
			report.Metadata = &metadata
		}
	}

	return &report, nil
}

// SaveChunk saves a chunk record.
func (s *Storage) SaveChunk(ctx context.Context, chunk *Chunk) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if chunk.ID == "" {
		chunk.ID = uuid.New().String()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO chunks (
			id, report_id, chunk_index, total_chunks, data,
			uncompressed_size, compressed_size, status, retry_count,
			last_error, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(report_id, chunk_index) DO UPDATE SET
			status = excluded.status,
			retry_count = excluded.retry_count,
			last_error = excluded.last_error,
			uploaded_at = excluded.uploaded_at
	`,
		chunk.ID, chunk.ReportID, chunk.ChunkIndex, chunk.TotalChunks,
		chunk.Data, chunk.UncompressedSize, chunk.CompressedSize,
		chunk.Status, chunk.RetryCount, chunk.LastError, chunk.CreatedAt,
	)

	return err
}

// GetChunk retrieves a chunk by ID.
func (s *Storage) GetChunk(ctx context.Context, id string) (*Chunk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var chunk Chunk
	var uploadedAt sql.NullTime
	var lastError sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, report_id, chunk_index, total_chunks, data,
			uncompressed_size, compressed_size, status, retry_count,
			last_error, created_at, uploaded_at
		FROM chunks WHERE id = ?
	`, id).Scan(
		&chunk.ID, &chunk.ReportID, &chunk.ChunkIndex, &chunk.TotalChunks,
		&chunk.Data, &chunk.UncompressedSize, &chunk.CompressedSize,
		&chunk.Status, &chunk.RetryCount, &lastError, &chunk.CreatedAt, &uploadedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if uploadedAt.Valid {
		chunk.UploadedAt = &uploadedAt.Time
	}
	if lastError.Valid {
		chunk.LastError = lastError.String
	}

	return &chunk, nil
}

// GetNextPendingChunk returns the next chunk ready for upload.
func (s *Storage) GetNextPendingChunk(ctx context.Context) (*Chunk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var chunk Chunk
	var uploadedAt sql.NullTime
	var lastError sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, report_id, chunk_index, total_chunks, data,
			uncompressed_size, compressed_size, status, retry_count,
			last_error, created_at, uploaded_at
		FROM chunks
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT 1
	`).Scan(
		&chunk.ID, &chunk.ReportID, &chunk.ChunkIndex, &chunk.TotalChunks,
		&chunk.Data, &chunk.UncompressedSize, &chunk.CompressedSize,
		&chunk.Status, &chunk.RetryCount, &lastError, &chunk.CreatedAt, &uploadedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if uploadedAt.Valid {
		chunk.UploadedAt = &uploadedAt.Time
	}
	if lastError.Valid {
		chunk.LastError = lastError.String
	}

	return &chunk, nil
}

// GetPendingChunks returns all pending chunks for a report.
func (s *Storage) GetPendingChunks(ctx context.Context, reportID string, limit int) ([]*Chunk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, report_id, chunk_index, total_chunks, data,
			uncompressed_size, compressed_size, status, retry_count,
			last_error, created_at, uploaded_at
		FROM chunks
		WHERE report_id = ? AND status = 'pending'
		ORDER BY chunk_index ASC
		LIMIT ?
	`, reportID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []*Chunk
	for rows.Next() {
		var chunk Chunk
		var uploadedAt sql.NullTime
		var lastError sql.NullString

		if err := rows.Scan(
			&chunk.ID, &chunk.ReportID, &chunk.ChunkIndex, &chunk.TotalChunks,
			&chunk.Data, &chunk.UncompressedSize, &chunk.CompressedSize,
			&chunk.Status, &chunk.RetryCount, &lastError, &chunk.CreatedAt, &uploadedAt,
		); err != nil {
			return nil, err
		}

		if uploadedAt.Valid {
			chunk.UploadedAt = &uploadedAt.Time
		}
		if lastError.Valid {
			chunk.LastError = lastError.String
		}

		chunks = append(chunks, &chunk)
	}

	return chunks, rows.Err()
}

// UpdateChunkStatus updates the status of a chunk.
func (s *Storage) UpdateChunkStatus(ctx context.Context, chunkID string, status ChunkStatus, lastError string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var uploadedAt interface{}
	if status == ChunkStatusCompleted {
		uploadedAt = time.Now()
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE chunks SET
			status = ?,
			last_error = ?,
			uploaded_at = ?,
			retry_count = retry_count + CASE WHEN ? = 'failed' THEN 1 ELSE 0 END
		WHERE id = ?
	`, status, lastError, uploadedAt, status, chunkID)

	return err
}

// UpdateReportStatus updates the status of a report.
func (s *Storage) UpdateReportStatus(ctx context.Context, reportID string, status ReportStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var completedAt interface{}
	if status == ReportStatusCompleted || status == ReportStatusFailed {
		completedAt = time.Now()
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE reports SET
			status = ?,
			updated_at = CURRENT_TIMESTAMP,
			completed_at = ?
		WHERE id = ?
	`, status, completedAt, reportID)

	return err
}

// IncrementCompletedChunks increments the completed chunk count.
func (s *Storage) IncrementCompletedChunks(ctx context.Context, reportID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		UPDATE reports SET
			completed_chunks = completed_chunks + 1,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, reportID)

	return err
}

// IncrementFailedChunks increments the failed chunk count.
func (s *Storage) IncrementFailedChunks(ctx context.Context, reportID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		UPDATE reports SET
			failed_chunks = failed_chunks + 1,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, reportID)

	return err
}

// GetPendingReports returns all reports with pending chunks.
func (s *Storage) GetPendingReports(ctx context.Context) ([]*Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, original_findings_count, original_assets_count, original_size,
			compressed_size, total_chunks, completed_chunks, failed_chunks,
			status, compression_algo, metadata, created_at, updated_at, completed_at
		FROM reports
		WHERE status IN ('pending', 'uploading')
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []*Report
	for rows.Next() {
		var report Report
		var metadataJSON string
		var completedAt sql.NullTime

		if err := rows.Scan(
			&report.ID, &report.OriginalFindingsCount, &report.OriginalAssetsCount,
			&report.OriginalSize, &report.CompressedSize, &report.TotalChunks,
			&report.CompletedChunks, &report.FailedChunks, &report.Status,
			&report.CompressionAlgo, &metadataJSON, &report.CreatedAt,
			&report.UpdatedAt, &completedAt,
		); err != nil {
			return nil, err
		}

		if completedAt.Valid {
			report.CompletedAt = &completedAt.Time
		}

		if metadataJSON != "" {
			var metadata Metadata
			if err := json.Unmarshal([]byte(metadataJSON), &metadata); err == nil {
				report.Metadata = &metadata
			}
		}

		reports = append(reports, &report)
	}

	return reports, rows.Err()
}

// Cleanup removes old completed reports and their chunks.
func (s *Storage) Cleanup(ctx context.Context, maxAge time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)

	result, err := s.db.ExecContext(ctx, `
		DELETE FROM reports
		WHERE status IN ('completed', 'failed')
		AND completed_at < ?
	`, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// GetStorageStats returns storage statistics.
func (s *Storage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats StorageStats

	// Count reports by status
	rows, err := s.db.QueryContext(ctx, `
		SELECT status, COUNT(*) FROM reports GROUP BY status
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		switch ReportStatus(status) {
		case ReportStatusPending:
			stats.PendingReports = count
		case ReportStatusUploading:
			stats.UploadingReports = count
		case ReportStatusCompleted:
			stats.CompletedReports = count
		case ReportStatusFailed:
			stats.FailedReports = count
		}
		stats.TotalReports += count
	}

	// Count chunks by status
	rows2, err := s.db.QueryContext(ctx, `
		SELECT status, COUNT(*) FROM chunks GROUP BY status
	`)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()

	for rows2.Next() {
		var status string
		var count int
		if err := rows2.Scan(&status, &count); err != nil {
			continue
		}
		switch ChunkStatus(status) {
		case ChunkStatusPending:
			stats.PendingChunks = count
		case ChunkStatusCompleted:
			stats.CompletedChunks = count
		case ChunkStatusFailed:
			stats.FailedChunks = count
		}
		stats.TotalChunks += count
	}

	// Get total storage size
	var totalSize sql.NullInt64
	_ = s.db.QueryRowContext(ctx, `SELECT SUM(compressed_size) FROM chunks`).Scan(&totalSize)
	if totalSize.Valid {
		stats.TotalStorageBytes = totalSize.Int64
	}

	return &stats, nil
}

// StorageStats contains storage statistics.
type StorageStats struct {
	TotalReports      int   `json:"total_reports"`
	PendingReports    int   `json:"pending_reports"`
	UploadingReports  int   `json:"uploading_reports"`
	CompletedReports  int   `json:"completed_reports"`
	FailedReports     int   `json:"failed_reports"`
	TotalChunks       int   `json:"total_chunks"`
	PendingChunks     int   `json:"pending_chunks"`
	CompletedChunks   int   `json:"completed_chunks"`
	FailedChunks      int   `json:"failed_chunks"`
	TotalStorageBytes int64 `json:"total_storage_bytes"`
}

// DeleteChunkData removes the data blob from a chunk (keeps metadata).
// This is used for immediate cleanup after successful upload.
func (s *Storage) DeleteChunkData(ctx context.Context, chunkID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		UPDATE chunks
		SET data = NULL, compressed_size = 0
		WHERE id = ?
	`, chunkID)
	return err
}

// DeleteReportChunks removes all chunk data for a report.
// Returns the number of chunks deleted.
func (s *Storage) DeleteReportChunks(ctx context.Context, reportID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `
		DELETE FROM chunks WHERE report_id = ?
	`, reportID)
	if err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	return int(count), nil
}

// CleanupToSize removes oldest completed reports until storage is under limit.
// Returns the number of reports deleted.
func (s *Storage) CleanupToSize(ctx context.Context, maxBytes int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deleted := 0

	for {
		// Check current size
		var currentSize sql.NullInt64
		_ = s.db.QueryRowContext(ctx, `SELECT SUM(compressed_size) FROM chunks`).Scan(&currentSize)
		if !currentSize.Valid || currentSize.Int64 <= maxBytes {
			break
		}

		// Find oldest completed report
		var reportID string
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM reports
			WHERE status = 'completed'
			ORDER BY completed_at ASC
			LIMIT 1
		`).Scan(&reportID)
		if err != nil {
			break // No more completed reports
		}

		// Delete chunks first
		_, err = s.db.ExecContext(ctx, `DELETE FROM chunks WHERE report_id = ?`, reportID)
		if err != nil {
			return deleted, err
		}

		// Delete report
		_, err = s.db.ExecContext(ctx, `DELETE FROM reports WHERE id = ?`, reportID)
		if err != nil {
			return deleted, err
		}

		deleted++
	}

	return deleted, nil
}

// Close closes the storage.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Close()
}
