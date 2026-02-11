package compress

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Strategy represents the upload strategy based on payload analysis.
type Strategy string

const (
	// StrategyDirect uploads directly without compression or chunking.
	// Used for small payloads (<500 findings, <1MB).
	StrategyDirect Strategy = "direct"

	// StrategyCompressOnly compresses the payload but uploads in a single request.
	// Used for medium payloads (500-2000 findings, 1-5MB).
	StrategyCompressOnly Strategy = "compress_only"

	// StrategyCompressAndChunk compresses then chunks the payload for gradual upload.
	// Used for large payloads (>2000 findings, >5MB).
	StrategyCompressAndChunk Strategy = "compress_and_chunk"
)

// AnalyzerConfig configures the payload analyzer thresholds.
type AnalyzerConfig struct {
	// MinFindingsForCompression is the minimum number of findings to trigger compression.
	// Default: 500
	MinFindingsForCompression int

	// MinFindingsForChunking is the minimum number of findings to trigger chunking.
	// Default: 2000
	MinFindingsForChunking int

	// MinSizeForCompression is the minimum payload size (bytes) to trigger compression.
	// Default: 1MB (1048576)
	MinSizeForCompression int

	// MinSizeForChunking is the minimum payload size (bytes) to trigger chunking.
	// Default: 5MB (5242880)
	MinSizeForChunking int

	// MaxCompressedSizeForSingleUpload is the maximum compressed size for single upload.
	// If compressed size exceeds this, chunking will be used.
	// Default: 5MB (5242880)
	MaxCompressedSizeForSingleUpload int
}

// DefaultAnalyzerConfig returns the default analyzer configuration.
func DefaultAnalyzerConfig() *AnalyzerConfig {
	return &AnalyzerConfig{
		MinFindingsForCompression:        500,
		MinFindingsForChunking:           2000,
		MinSizeForCompression:            1 * 1024 * 1024, // 1MB
		MinSizeForChunking:               5 * 1024 * 1024, // 5MB
		MaxCompressedSizeForSingleUpload: 5 * 1024 * 1024, // 5MB
	}
}

// Analyzer analyzes payloads and determines the optimal upload strategy.
type Analyzer struct {
	config     *AnalyzerConfig
	compressor *Compressor
}

// NewAnalyzer creates a new payload analyzer.
func NewAnalyzer(config *AnalyzerConfig) *Analyzer {
	if config == nil {
		config = DefaultAnalyzerConfig()
	}
	return &Analyzer{
		config:     config,
		compressor: NewCompressor(AlgorithmZSTD, LevelDefault),
	}
}

// AnalysisResult contains the result of payload analysis.
type AnalysisResult struct {
	// Strategy is the recommended upload strategy.
	Strategy Strategy `json:"strategy"`

	// Metrics about the payload.
	FindingsCount int `json:"findings_count"`
	AssetsCount   int `json:"assets_count"`
	RawSize       int `json:"raw_size"`

	// Compression estimate (only if compression recommended).
	EstimatedCompressedSize int     `json:"estimated_compressed_size,omitempty"`
	EstimatedRatio          float64 `json:"estimated_ratio,omitempty"`

	// Chunking estimate (only if chunking recommended).
	EstimatedChunks int `json:"estimated_chunks,omitempty"`

	// Reason explains why this strategy was chosen.
	Reason string `json:"reason"`
}

// Analyze analyzes a CTIS report and returns the recommended upload strategy.
func (a *Analyzer) Analyze(report *ctis.Report) (*AnalysisResult, error) {
	result := &AnalysisResult{
		FindingsCount: len(report.Findings),
		AssetsCount:   len(report.Assets),
	}

	// Serialize to get raw size
	rawData, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	result.RawSize = len(rawData)

	// Decision tree based on findings count and size
	strategy, reason := a.determineStrategy(result.FindingsCount, result.RawSize)
	result.Strategy = strategy
	result.Reason = reason

	// If compression is involved, estimate compressed size
	if strategy != StrategyDirect {
		compressedData, err := a.compressor.Compress(rawData)
		if err == nil {
			result.EstimatedCompressedSize = len(compressedData)
			result.EstimatedRatio = float64(len(compressedData)) / float64(result.RawSize)

			// Re-evaluate: if compressed size still exceeds threshold, upgrade to chunking
			if strategy == StrategyCompressOnly && len(compressedData) > a.config.MaxCompressedSizeForSingleUpload {
				result.Strategy = StrategyCompressAndChunk
				result.Reason = "compressed size exceeds single upload limit"
			}
		}
	}

	// Estimate chunks if chunking is needed
	if result.Strategy == StrategyCompressAndChunk {
		chunkSize := 2 * 1024 * 1024 // 2MB per chunk
		if result.EstimatedCompressedSize > 0 {
			result.EstimatedChunks = (result.EstimatedCompressedSize + chunkSize - 1) / chunkSize
		} else {
			// Estimate based on raw size with ~70% compression ratio
			estimatedCompressed := int(float64(result.RawSize) * 0.3)
			result.EstimatedChunks = (estimatedCompressed + chunkSize - 1) / chunkSize
		}
		if result.EstimatedChunks < 1 {
			result.EstimatedChunks = 1
		}
	}

	return result, nil
}

// determineStrategy determines the upload strategy based on metrics.
func (a *Analyzer) determineStrategy(findingsCount, rawSize int) (Strategy, string) {
	// Check chunking threshold first (larger takes precedence)
	if findingsCount >= a.config.MinFindingsForChunking {
		return StrategyCompressAndChunk, "findings count exceeds chunking threshold"
	}
	if rawSize >= a.config.MinSizeForChunking {
		return StrategyCompressAndChunk, "raw size exceeds chunking threshold"
	}

	// Check compression threshold
	if findingsCount >= a.config.MinFindingsForCompression {
		return StrategyCompressOnly, "findings count exceeds compression threshold"
	}
	if rawSize >= a.config.MinSizeForCompression {
		return StrategyCompressOnly, "raw size exceeds compression threshold"
	}

	// Small payload - direct upload
	return StrategyDirect, "payload within direct upload limits"
}

// AnalyzeBytes analyzes raw JSON bytes and returns the recommended strategy.
// This is useful when you already have serialized data.
func (a *Analyzer) AnalyzeBytes(data []byte) (*AnalysisResult, error) {
	var report ctis.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return a.Analyze(&report)
}

// QuickAnalyze performs a quick analysis based only on counts.
// This is faster but less accurate than full analysis.
func (a *Analyzer) QuickAnalyze(findingsCount, assetsCount int) Strategy {
	if findingsCount >= a.config.MinFindingsForChunking {
		return StrategyCompressAndChunk
	}
	if findingsCount >= a.config.MinFindingsForCompression {
		return StrategyCompressOnly
	}
	return StrategyDirect
}

// ShouldCompress returns true if compression should be used.
func (a *Analyzer) ShouldCompress(findingsCount, rawSize int) bool {
	return findingsCount >= a.config.MinFindingsForCompression ||
		rawSize >= a.config.MinSizeForCompression
}

// ShouldChunk returns true if chunking should be used.
func (a *Analyzer) ShouldChunk(findingsCount, rawSize int) bool {
	return findingsCount >= a.config.MinFindingsForChunking ||
		rawSize >= a.config.MinSizeForChunking
}

// DefaultAnalyzer is the default payload analyzer.
var DefaultAnalyzer = NewAnalyzer(nil)
