package chunk

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ReportStatus represents the status of a chunked report.
type ReportStatus string

const (
	// ReportStatusPending indicates the report is queued for upload.
	ReportStatusPending ReportStatus = "pending"

	// ReportStatusUploading indicates chunks are being uploaded.
	ReportStatusUploading ReportStatus = "uploading"

	// ReportStatusCompleted indicates all chunks have been uploaded.
	ReportStatusCompleted ReportStatus = "completed"

	// ReportStatusFailed indicates the upload failed after all retries.
	ReportStatusFailed ReportStatus = "failed"
)

// ChunkStatus represents the status of a single chunk.
type ChunkStatus string

const (
	// ChunkStatusPending indicates the chunk is waiting for upload.
	ChunkStatusPending ChunkStatus = "pending"

	// ChunkStatusUploading indicates the chunk is currently uploading.
	ChunkStatusUploading ChunkStatus = "uploading"

	// ChunkStatusCompleted indicates the chunk was successfully uploaded.
	ChunkStatusCompleted ChunkStatus = "completed"

	// ChunkStatusFailed indicates the chunk failed after all retries.
	ChunkStatusFailed ChunkStatus = "failed"
)

// Report represents a chunked report in the database.
type Report struct {
	ID                    string       `json:"id"`
	OriginalFindingsCount int          `json:"original_findings_count"`
	OriginalAssetsCount   int          `json:"original_assets_count"`
	OriginalSize          int          `json:"original_size"`
	CompressedSize        int          `json:"compressed_size"`
	TotalChunks           int          `json:"total_chunks"`
	CompletedChunks       int          `json:"completed_chunks"`
	FailedChunks          int          `json:"failed_chunks"`
	Status                ReportStatus `json:"status"`
	CompressionAlgo       string       `json:"compression_algo"`
	CreatedAt             time.Time    `json:"created_at"`
	UpdatedAt             time.Time    `json:"updated_at"`
	CompletedAt           *time.Time   `json:"completed_at,omitempty"`
	Metadata              *Metadata    `json:"metadata,omitempty"`
}

// Metadata stores additional report context.
type Metadata struct {
	ToolName    string    `json:"tool_name,omitempty"`
	ToolVersion string    `json:"tool_version,omitempty"`
	ScanID      string    `json:"scan_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
}

// Chunk represents a single chunk of a report.
type Chunk struct {
	ID               string      `json:"id"`
	ReportID         string      `json:"report_id"`
	ChunkIndex       int         `json:"chunk_index"`
	TotalChunks      int         `json:"total_chunks"`
	Data             []byte      `json:"-"` // Compressed data (not in JSON)
	UncompressedSize int         `json:"uncompressed_size"`
	CompressedSize   int         `json:"compressed_size"`
	Status           ChunkStatus `json:"status"`
	RetryCount       int         `json:"retry_count"`
	LastError        string      `json:"last_error,omitempty"`
	CreatedAt        time.Time   `json:"created_at"`
	UploadedAt       *time.Time  `json:"uploaded_at,omitempty"`
}

// ChunkData represents the actual data in a chunk.
// This is what gets serialized, compressed, and uploaded.
type ChunkData struct {
	ReportID    string               `json:"report_id"`
	ChunkIndex  int                  `json:"chunk_index"`
	TotalChunks int                  `json:"total_chunks"`
	Tool        *ctis.Tool           `json:"tool,omitempty"`
	Metadata    *ctis.ReportMetadata `json:"metadata,omitempty"`
	Assets      []ctis.Asset         `json:"assets,omitempty"`
	Findings    []ctis.Finding       `json:"findings,omitempty"`
	IsFinal     bool                 `json:"is_final"`
}

// Progress represents upload progress for a report.
type Progress struct {
	ReportID        string  `json:"report_id"`
	TotalChunks     int     `json:"total_chunks"`
	CompletedChunks int     `json:"completed_chunks"`
	FailedChunks    int     `json:"failed_chunks"`
	PendingChunks   int     `json:"pending_chunks"`
	PercentComplete float64 `json:"percent_complete"`
	BytesUploaded   int64   `json:"bytes_uploaded"`
	BytesTotal      int64   `json:"bytes_total"`
	Status          string  `json:"status"`
}

// CalculateProgress calculates progress from a report.
func (r *Report) CalculateProgress() *Progress {
	percentComplete := 0.0
	if r.TotalChunks > 0 {
		percentComplete = float64(r.CompletedChunks) / float64(r.TotalChunks) * 100
	}

	return &Progress{
		ReportID:        r.ID,
		TotalChunks:     r.TotalChunks,
		CompletedChunks: r.CompletedChunks,
		FailedChunks:    r.FailedChunks,
		PendingChunks:   r.TotalChunks - r.CompletedChunks - r.FailedChunks,
		PercentComplete: percentComplete,
		BytesTotal:      int64(r.CompressedSize),
		Status:          string(r.Status),
	}
}

// IsComplete checks if all chunks have been uploaded.
func (r *Report) IsComplete() bool {
	return r.Status == ReportStatusCompleted ||
		(r.CompletedChunks == r.TotalChunks && r.TotalChunks > 0)
}

// HasFailed checks if the report has failed.
func (r *Report) HasFailed() bool {
	return r.Status == ReportStatusFailed
}

// CanRetry checks if there are chunks that can be retried.
func (c *Chunk) CanRetry(maxRetries int) bool {
	return c.RetryCount < maxRetries && c.Status != ChunkStatusCompleted
}
