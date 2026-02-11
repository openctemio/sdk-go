// Package chunk provides chunked upload functionality for large scan reports.
//
// The chunk package enables splitting large reports into smaller chunks for
// gradual upload, with SQLite-based local storage for persistence and
// resumability.
//
// Key components:
//   - Config: Configuration for chunking behavior
//   - Splitter: Algorithm to split reports into chunks
//   - Storage: SQLite-based chunk storage
//   - Manager: Main orchestration of chunking and upload
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

	// Storage configuration
	DatabasePath   string // SQLite database path (default: ~/.openctem/chunks.db)
	RetentionHours int    // How long to keep completed chunks (default: 24)
	MaxStorageMB   int    // Max storage for chunk DB (default: 500)

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
