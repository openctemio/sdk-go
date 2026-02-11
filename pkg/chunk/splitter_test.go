package chunk

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestSplitter_NeedsChunking(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 100
	cfg.MinAssetsForChunking = 50

	splitter := NewSplitter(cfg)

	tests := []struct {
		name     string
		findings int
		assets   int
		expected bool
	}{
		{"small report", 10, 5, false},
		{"at findings threshold", 100, 10, true},
		{"at assets threshold", 10, 50, true},
		{"above both", 200, 100, true},
		{"just under findings", 99, 10, false},
		{"just under assets", 10, 49, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := createTestReport(tt.findings, tt.assets)
			result := splitter.NeedsChunking(report)
			if result != tt.expected {
				t.Errorf("NeedsChunking() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSplitter_Split_SmallReport(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 100

	splitter := NewSplitter(cfg)
	report := createTestReport(10, 5)

	chunks, err := splitter.Split(report)
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}

	if len(chunks) != 1 {
		t.Errorf("Expected 1 chunk, got %d", len(chunks))
	}

	if len(chunks[0].Findings) != 10 {
		t.Errorf("Expected 10 findings in chunk, got %d", len(chunks[0].Findings))
	}

	if len(chunks[0].Assets) != 5 {
		t.Errorf("Expected 5 assets in chunk, got %d", len(chunks[0].Assets))
	}

	if !chunks[0].IsFinal {
		t.Error("Single chunk should be marked as final")
	}
}

func TestSplitter_Split_LargeReport(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 100
	cfg.MaxFindingsPerChunk = 50
	cfg.MaxAssetsPerChunk = 20

	splitter := NewSplitter(cfg)
	report := createTestReportWithAssetRefs(200, 10) // 200 findings across 10 assets

	chunks, err := splitter.Split(report)
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}

	if len(chunks) < 2 {
		t.Errorf("Expected multiple chunks, got %d", len(chunks))
	}

	// Verify total findings across all chunks
	totalFindings := 0
	for _, c := range chunks {
		totalFindings += len(c.Findings)
	}
	if totalFindings != 200 {
		t.Errorf("Total findings = %d, want 200", totalFindings)
	}

	// Verify first chunk has tool and metadata
	if chunks[0].Tool == nil {
		t.Error("First chunk should have Tool")
	}
	if chunks[0].Metadata == nil {
		t.Error("First chunk should have Metadata")
	}

	// Verify last chunk is marked as final
	lastChunk := chunks[len(chunks)-1]
	if !lastChunk.IsFinal {
		t.Error("Last chunk should be marked as final")
	}

	// Verify TotalChunks is set correctly in all chunks
	for i, c := range chunks {
		if c.TotalChunks != len(chunks) {
			t.Errorf("Chunk %d: TotalChunks = %d, want %d", i, c.TotalChunks, len(chunks))
		}
	}
}

func TestSplitter_Split_ChunkLimits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 10
	cfg.MaxFindingsPerChunk = 25
	cfg.MaxAssetsPerChunk = 10

	splitter := NewSplitter(cfg)
	report := createTestReportWithAssetRefs(100, 5) // 100 findings, 5 assets

	chunks, err := splitter.Split(report)
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}

	// Each chunk should respect the findings limit
	for i, c := range chunks {
		if len(c.Findings) > cfg.MaxFindingsPerChunk {
			t.Errorf("Chunk %d has %d findings, exceeds limit of %d",
				i, len(c.Findings), cfg.MaxFindingsPerChunk)
		}
	}
}

func TestSplitter_EstimateChunks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 100
	cfg.MinAssetsForChunking = 50 // Set threshold for assets
	cfg.MaxFindingsPerChunk = 50
	cfg.MaxAssetsPerChunk = 20

	splitter := NewSplitter(cfg)

	tests := []struct {
		findings int
		assets   int
		expected int
	}{
		{10, 5, 1},     // Below threshold
		{100, 10, 2},   // 100/50 = 2 chunks (findings threshold met)
		{200, 10, 4},   // 200/50 = 4 chunks
		{50, 100, 5},   // 100/20 = 5 chunks (assets dominate, assets >= 50 threshold)
		{1000, 10, 20}, // 1000/50 = 20 chunks
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := splitter.EstimateChunks(tt.findings, tt.assets)
			if result != tt.expected {
				t.Errorf("EstimateChunks(%d, %d) = %d, want %d",
					tt.findings, tt.assets, result, tt.expected)
			}
		})
	}
}

// Helper functions

func createTestReport(findings, assets int) *ctis.Report {
	report := &ctis.Report{
		Tool: &ctis.Tool{
			Name:    "test-tool",
			Version: "1.0.0",
		},
		Metadata: ctis.ReportMetadata{
			ID: "test-report-id",
		},
		Assets:   make([]ctis.Asset, assets),
		Findings: make([]ctis.Finding, findings),
	}

	for i := 0; i < assets; i++ {
		report.Assets[i] = ctis.Asset{
			ID:   "asset-" + string(rune('a'+i)),
			Type: "repository",
			Name: "Test Asset " + string(rune('A'+i)),
		}
	}

	for i := 0; i < findings; i++ {
		report.Findings[i] = ctis.Finding{
			RuleID:   "test-rule",
			Title:    "Test Finding",
			Severity: "high",
		}
	}

	return report
}

func createTestReportWithAssetRefs(findings, assets int) *ctis.Report {
	report := &ctis.Report{
		Tool: &ctis.Tool{
			Name:    "test-tool",
			Version: "1.0.0",
		},
		Metadata: ctis.ReportMetadata{
			ID: "test-report-id",
		},
		Assets:   make([]ctis.Asset, assets),
		Findings: make([]ctis.Finding, findings),
	}

	// Create assets
	for i := 0; i < assets; i++ {
		report.Assets[i] = ctis.Asset{
			ID:   "asset-" + string(rune('a'+i)),
			Type: "repository",
			Name: "Test Asset " + string(rune('A'+i)),
		}
	}

	// Create findings with asset references
	for i := 0; i < findings; i++ {
		assetIndex := i % assets
		report.Findings[i] = ctis.Finding{
			RuleID:   "test-rule-" + string(rune('0'+i%10)),
			Title:    "Test Finding",
			Severity: "high",
			AssetRef: report.Assets[assetIndex].ID,
		}
	}

	return report
}
