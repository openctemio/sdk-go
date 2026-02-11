// Package compress provides compression utilities for large payloads.
//
// The compress package supports multiple compression algorithms with a focus on
// ZSTD for optimal compression ratio and speed balance. It also provides
// payload analysis to determine the best upload strategy.
//
// Supported algorithms:
//   - ZSTD (Zstandard): Best balance of speed and compression ratio
//   - Gzip: Maximum compatibility with existing infrastructure
//
// Example usage:
//
//	compressor := compress.NewCompressor(compress.AlgorithmZSTD, compress.LevelDefault)
//	compressed, err := compressor.Compress(jsonData)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Later, decompress
//	original, err := compressor.Decompress(compressed)
package compress

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Algorithm represents a compression algorithm.
type Algorithm string

const (
	// AlgorithmZSTD is the Zstandard compression algorithm.
	// Best balance of compression ratio and speed.
	AlgorithmZSTD Algorithm = "zstd"

	// AlgorithmGzip is the gzip compression algorithm.
	// Maximum compatibility with existing infrastructure.
	AlgorithmGzip Algorithm = "gzip"

	// AlgorithmNone indicates no compression.
	AlgorithmNone Algorithm = "none"
)

// Level represents compression level.
type Level int

const (
	// LevelFastest prioritizes speed over compression ratio.
	LevelFastest Level = 1

	// LevelDefault is the default compression level (good balance).
	LevelDefault Level = 3

	// LevelBetter provides better compression at the cost of speed.
	LevelBetter Level = 6

	// LevelBest provides maximum compression (slowest).
	LevelBest Level = 9
)

// Compressor provides compression and decompression functionality.
type Compressor struct {
	algorithm Algorithm
	level     Level

	// ZSTD encoder/decoder pools for reuse
	zstdEncoderPool sync.Pool
	zstdDecoderPool sync.Pool
}

// NewCompressor creates a new compressor with the specified algorithm and level.
func NewCompressor(algorithm Algorithm, level Level) *Compressor {
	c := &Compressor{
		algorithm: algorithm,
		level:     level,
	}

	if algorithm == AlgorithmZSTD {
		c.zstdEncoderPool = sync.Pool{
			New: func() any {
				enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(int(level))))
				return enc
			},
		}
		c.zstdDecoderPool = sync.Pool{
			New: func() any {
				dec, _ := zstd.NewReader(nil)
				return dec
			},
		}
	}

	return c
}

// Algorithm returns the compression algorithm.
func (c *Compressor) Algorithm() Algorithm {
	return c.algorithm
}

// ContentEncoding returns the HTTP Content-Encoding header value.
func (c *Compressor) ContentEncoding() string {
	switch c.algorithm {
	case AlgorithmZSTD:
		return "zstd"
	case AlgorithmGzip:
		return "gzip"
	default:
		return ""
	}
}

// Compress compresses the input data.
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	switch c.algorithm {
	case AlgorithmZSTD:
		return c.compressZSTD(data)
	case AlgorithmGzip:
		return c.compressGzip(data)
	case AlgorithmNone:
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", c.algorithm)
	}
}

// Decompress decompresses the input data.
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	switch c.algorithm {
	case AlgorithmZSTD:
		return c.decompressZSTD(data)
	case AlgorithmGzip:
		return c.decompressGzip(data)
	case AlgorithmNone:
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", c.algorithm)
	}
}

// compressZSTD compresses data using ZSTD.
func (c *Compressor) compressZSTD(data []byte) ([]byte, error) {
	enc := c.zstdEncoderPool.Get().(*zstd.Encoder)
	defer c.zstdEncoderPool.Put(enc)

	var buf bytes.Buffer
	enc.Reset(&buf)

	if _, err := enc.Write(data); err != nil {
		return nil, fmt.Errorf("zstd write error: %w", err)
	}

	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("zstd close error: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressZSTD decompresses ZSTD data.
func (c *Compressor) decompressZSTD(data []byte) ([]byte, error) {
	dec := c.zstdDecoderPool.Get().(*zstd.Decoder)
	defer c.zstdDecoderPool.Put(dec)

	if err := dec.Reset(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("zstd reset error: %w", err)
	}

	result, err := io.ReadAll(dec)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress error: %w", err)
	}

	return result, nil
}

// compressGzip compresses data using gzip.
func (c *Compressor) compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	level := gzip.DefaultCompression
	if c.level <= 3 {
		level = gzip.BestSpeed
	} else if c.level >= 7 {
		level = gzip.BestCompression
	}

	writer, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("gzip writer error: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("gzip write error: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("gzip close error: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressGzip decompresses gzip data.
func (c *Compressor) decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader error: %w", err)
	}
	defer reader.Close()

	result, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress error: %w", err)
	}

	return result, nil
}

// CompressionStats holds statistics about a compression operation.
type CompressionStats struct {
	OriginalSize   int     `json:"original_size"`
	CompressedSize int     `json:"compressed_size"`
	Ratio          float64 `json:"ratio"`           // compressed/original
	Savings        float64 `json:"savings_percent"` // (1 - ratio) * 100
	Algorithm      string  `json:"algorithm"`
}

// CompressWithStats compresses data and returns statistics.
func (c *Compressor) CompressWithStats(data []byte) ([]byte, *CompressionStats, error) {
	compressed, err := c.Compress(data)
	if err != nil {
		return nil, nil, err
	}

	originalSize := len(data)
	compressedSize := len(compressed)
	ratio := float64(compressedSize) / float64(originalSize)

	stats := &CompressionStats{
		OriginalSize:   originalSize,
		CompressedSize: compressedSize,
		Ratio:          ratio,
		Savings:        (1 - ratio) * 100,
		Algorithm:      string(c.algorithm),
	}

	return compressed, stats, nil
}

// Default compressors for convenience.
var (
	// DefaultZSTD is the default ZSTD compressor.
	DefaultZSTD = NewCompressor(AlgorithmZSTD, LevelDefault)

	// DefaultGzip is the default gzip compressor.
	DefaultGzip = NewCompressor(AlgorithmGzip, LevelDefault)
)

// QuickCompress compresses data using the default ZSTD compressor.
func QuickCompress(data []byte) ([]byte, error) {
	return DefaultZSTD.Compress(data)
}

// QuickDecompress decompresses ZSTD data using the default decompressor.
func QuickDecompress(data []byte) ([]byte, error) {
	return DefaultZSTD.Decompress(data)
}
