package compress

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompressor_ZSTD(t *testing.T) {
	compressor := NewCompressor(AlgorithmZSTD, LevelDefault)

	testData := []byte(`{"findings":[{"id":"1","title":"Test Finding"}],"assets":[{"id":"asset1"}]}`)

	// Test compression
	compressed, err := compressor.Compress(testData)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	// Compressed should be smaller or at least not much larger
	t.Logf("Original size: %d, Compressed size: %d", len(testData), len(compressed))

	// Test decompression
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if !bytes.Equal(testData, decompressed) {
		t.Errorf("Decompressed data doesn't match original")
	}
}

func TestCompressor_Gzip(t *testing.T) {
	compressor := NewCompressor(AlgorithmGzip, LevelDefault)

	testData := []byte(`{"findings":[{"id":"1","title":"Test Finding"}],"assets":[{"id":"asset1"}]}`)

	// Test compression
	compressed, err := compressor.Compress(testData)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	t.Logf("Original size: %d, Compressed size: %d", len(testData), len(compressed))

	// Test decompression
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if !bytes.Equal(testData, decompressed) {
		t.Errorf("Decompressed data doesn't match original")
	}
}

func TestCompressor_None(t *testing.T) {
	compressor := NewCompressor(AlgorithmNone, LevelDefault)

	testData := []byte(`{"findings":[{"id":"1"}]}`)

	compressed, err := compressor.Compress(testData)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	if !bytes.Equal(testData, compressed) {
		t.Errorf("AlgorithmNone should return original data")
	}
}

func TestCompressor_ContentEncoding(t *testing.T) {
	tests := []struct {
		algorithm Algorithm
		expected  string
	}{
		{AlgorithmZSTD, "zstd"},
		{AlgorithmGzip, "gzip"},
		{AlgorithmNone, ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			c := NewCompressor(tt.algorithm, LevelDefault)
			if got := c.ContentEncoding(); got != tt.expected {
				t.Errorf("ContentEncoding() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCompressor_CompressWithStats(t *testing.T) {
	compressor := NewCompressor(AlgorithmZSTD, LevelDefault)

	// Create large repetitive data (compresses well)
	testData := []byte(strings.Repeat(`{"rule_id":"sql-injection","severity":"high"},`, 1000))

	compressed, stats, err := compressor.CompressWithStats(testData)
	if err != nil {
		t.Fatalf("CompressWithStats failed: %v", err)
	}

	if stats.OriginalSize != len(testData) {
		t.Errorf("OriginalSize = %d, want %d", stats.OriginalSize, len(testData))
	}

	if stats.CompressedSize != len(compressed) {
		t.Errorf("CompressedSize = %d, want %d", stats.CompressedSize, len(compressed))
	}

	if stats.Ratio <= 0 || stats.Ratio > 1 {
		t.Errorf("Ratio = %f, expected between 0 and 1", stats.Ratio)
	}

	if stats.Savings < 50 {
		t.Errorf("Expected >50%% savings on repetitive data, got %f%%", stats.Savings)
	}

	t.Logf("Stats: original=%d, compressed=%d, ratio=%.2f, savings=%.1f%%",
		stats.OriginalSize, stats.CompressedSize, stats.Ratio, stats.Savings)
}

func TestCompressor_LargeData(t *testing.T) {
	compressor := NewCompressor(AlgorithmZSTD, LevelDefault)

	// Simulate security scan with many findings
	var sb strings.Builder
	sb.WriteString(`{"findings":[`)
	for i := 0; i < 10000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"finding-`)
		sb.WriteString(string(rune('a' + (i % 26))))
		sb.WriteString(`","rule_id":"sql-injection","severity":"high","title":"SQL Injection Found"}`)
	}
	sb.WriteString(`]}`)

	testData := []byte(sb.String())
	t.Logf("Large test data size: %d bytes (%.2f MB)", len(testData), float64(len(testData))/1024/1024)

	compressed, stats, err := compressor.CompressWithStats(testData)
	if err != nil {
		t.Fatalf("CompressWithStats failed: %v", err)
	}

	t.Logf("Compressed: %d bytes (%.2f MB), savings: %.1f%%",
		stats.CompressedSize, float64(stats.CompressedSize)/1024/1024, stats.Savings)

	// Verify decompression
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if !bytes.Equal(testData, decompressed) {
		t.Error("Decompressed data doesn't match original")
	}
}

func TestQuickCompress(t *testing.T) {
	testData := []byte(`{"test":"data"}`)

	compressed, err := QuickCompress(testData)
	if err != nil {
		t.Fatalf("QuickCompress failed: %v", err)
	}

	decompressed, err := QuickDecompress(compressed)
	if err != nil {
		t.Fatalf("QuickDecompress failed: %v", err)
	}

	if !bytes.Equal(testData, decompressed) {
		t.Error("Data mismatch")
	}
}

func BenchmarkCompressor_ZSTD(b *testing.B) {
	compressor := NewCompressor(AlgorithmZSTD, LevelDefault)

	// Create realistic test data
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString(`{"id":"finding-`)
		sb.WriteString(string(rune('0' + (i % 10))))
		sb.WriteString(`","rule_id":"sql-injection","severity":"high"},`)
	}
	testData := []byte(sb.String())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := compressor.Compress(testData)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(int64(len(testData)))
}

func BenchmarkCompressor_Gzip(b *testing.B) {
	compressor := NewCompressor(AlgorithmGzip, LevelDefault)

	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString(`{"id":"finding-`)
		sb.WriteString(string(rune('0' + (i % 10))))
		sb.WriteString(`","rule_id":"sql-injection","severity":"high"},`)
	}
	testData := []byte(sb.String())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := compressor.Compress(testData)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(int64(len(testData)))
}
