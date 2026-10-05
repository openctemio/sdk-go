// Package chunk provides chunked upload functionality for large scan reports.
//
// The chunk package splits large reports for upload:
//
//   - SplitSegments: protocol v2 segments (RFC-026 §3.5), each a complete
//     CTIS document with the report's tool, metadata and the assets its
//     findings reference. The v2 client (pkg/client) uses it.
//   - Splitter and Manager: protocol v1 chunks (/api/v1/agent/ingest/chunk).
//     The Manager stores chunks in the durable outbox (pkg/outbox), which
//     replaced the SQLite storage of SDKs before v0.8.0.
//
// Key components:
//   - Config: Configuration for chunking behavior
//   - Splitter: Algorithm to split reports into v1 chunks
//   - Manager: Main orchestration of v1 chunking and upload
//
// Example usage:
//
//	manager, err := chunk.NewManager(chunk.DefaultConfig())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer manager.Close()
//
//	report, err := manager.SubmitReport(ctx, largeReport)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	manager.Start(ctx) // Start background upload
//
// Stability: Internal-bound (docs/STABILITY.md): public today because other
// public packages use it; it moves under internal/ before v1.0.0. Do not
// import it from a sensor.
package chunk

import (
	"os"
	"path/filepath"
)

// Config configures chunking behavior.
type Config struct {
	// Chunking thresholds - when to trigger chunking
	MinFindingsForChunking int // Minimum findings to trigger chunking (default: 2000)
	MinAssetsForChunking   int // Minimum assets to trigger chunking (default: 200)
	MinSizeForChunking     int // Minimum raw size in bytes to trigger chunking (default: 5MB)

	// Chunk size limits
	MaxFindingsPerChunk int // Max findings per chunk (default: 500)
	MaxAssetsPerChunk   int // Max assets per chunk (default: 100)
	MaxChunkSizeBytes   int // Max uncompressed size per chunk (default: 2MB)

	// Upload behavior
	UploadDelayMs        int // Delay between chunk uploads in ms (default: 100)
	MaxConcurrentUploads int // Max concurrent upload workers (default: 2)
	UploadTimeoutSeconds int // Timeout per chunk upload (default: 30)

	// Retry configuration
	MaxRetries     int // Max retries per chunk (default: 3)
	RetryBackoffMs int // Initial backoff between retries (default: 1000)

	// Storage configuration. Chunks live in a durable outbox (pkg/outbox).
	OutboxDir string // Outbox directory (default: "chunk-outbox" next to DatabasePath)
	// Deprecated: the SQLite chunk database was replaced by the outbox in
	// v0.8.0. DatabasePath now only locates the default OutboxDir (its
	// directory) and a leftover database, which is reported, not read.
	DatabasePath   string
	RetentionHours int // Deprecated: unused; the outbox caps age itself (7 days).
	MaxStorageMB   int // Max bytes the chunk outbox may hold, in MiB (default: 500)

	// Compression (chunks are always compressed before storage)
	CompressionLevel int // gzip/zstd level 1-9 (default: 3)

	// Auto-cleanup configuration
	AutoCleanupOnUpload     bool // Delete chunk data immediately after successful upload (default: true)
	CleanupOnReportComplete bool // Delete all chunks when report completes (default: true)
	CleanupIntervalMinutes  int  // How often to run cleanup in minutes (default: 15)
	AggressiveCleanup       bool // Enable aggressive cleanup when storage exceeds MaxStorageMB (default: true)
}

// DefaultConfig returns sensible defaults for most environments.
func DefaultConfig() *Config {
	return &Config{
		// Chunking thresholds
		MinFindingsForChunking: 2000,
		MinAssetsForChunking:   200,
		MinSizeForChunking:     5 * 1024 * 1024, // 5MB

		// Chunk size limits
		MaxFindingsPerChunk: 500,
		MaxAssetsPerChunk:   100,
		MaxChunkSizeBytes:   2 * 1024 * 1024, // 2MB

		// Upload behavior
		UploadDelayMs:        100,
		MaxConcurrentUploads: 2,
		UploadTimeoutSeconds: 30,

		// Retry configuration
		MaxRetries:     3,
		RetryBackoffMs: 1000,

		// Storage
		DatabasePath:   defaultDatabasePath(),
		RetentionHours: 24,
		MaxStorageMB:   500,

		// Compression
		CompressionLevel: 3,

		// Auto-cleanup (enabled by default to prevent disk bloat)
		AutoCleanupOnUpload:     true,
		CleanupOnReportComplete: true,
		CleanupIntervalMinutes:  15,
		AggressiveCleanup:       true,
	}
}

// defaultDatabasePath returns the default path for the chunk database.
func defaultDatabasePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".openctem", "chunks.db")
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.MaxFindingsPerChunk <= 0 {
		c.MaxFindingsPerChunk = 500
	}
	if c.MaxAssetsPerChunk <= 0 {
		c.MaxAssetsPerChunk = 100
	}
	if c.MaxChunkSizeBytes <= 0 {
		c.MaxChunkSizeBytes = 2 * 1024 * 1024
	}
	if c.MaxConcurrentUploads <= 0 {
		c.MaxConcurrentUploads = 2
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = 3
	}
	if c.DatabasePath == "" {
		c.DatabasePath = defaultDatabasePath()
	}
	if c.CompressionLevel <= 0 || c.CompressionLevel > 9 {
		c.CompressionLevel = 3
	}
	return nil
}
