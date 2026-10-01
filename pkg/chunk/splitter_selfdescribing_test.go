package chunk

import (
	"fmt"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// The platform ingests every chunk as a report of its own, so every chunk must
// carry the tool, the metadata and each asset its findings reference. Before,
// only chunk 0 had the tool (later chunks were attributed to "unknown") and an
// asset went only into its first chunk (its later findings landed on a
// placeholder "scan:unknown:<report>" asset).
func TestSplit_EveryChunkIsSelfDescribing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 10
	cfg.MaxFindingsPerChunk = 50
	cfg.MaxAssetsPerChunk = 3

	// asset-big has more findings than one chunk holds; the others are small.
	report := &ctis.Report{
		Tool:     &ctis.Tool{Name: "gitleaks", Version: "8"},
		Metadata: ctis.ReportMetadata{ID: "rep-1", CoverageType: "full"},
	}
	add := func(asset string, n int) {
		report.Assets = append(report.Assets, ctis.Asset{ID: asset, Type: ctis.AssetTypeRepository, Value: "repo/" + asset})
		for i := range n {
			report.Findings = append(report.Findings, ctis.Finding{
				ID: fmt.Sprintf("%s-%d", asset, i), RuleID: "r", Title: "t", Severity: "high", AssetRef: asset,
			})
		}
	}
	add("asset-big", 130)
	for i := range 8 {
		add(fmt.Sprintf("asset-%02d", i), 12)
	}
	report.Assets = append(report.Assets, ctis.Asset{ID: "asset-unreferenced", Type: ctis.AssetTypeDomain, Value: "x.example"})

	chunks, err := NewSplitter(cfg).Split(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 3 {
		t.Fatalf("expected several chunks, got %d", len(chunks))
	}

	findings, assetsSeen := 0, map[string]bool{}
	for i, c := range chunks {
		if c.Tool == nil || c.Tool.Name != "gitleaks" {
			t.Errorf("chunk %d: tool = %+v, want gitleaks", i, c.Tool)
		}
		if c.Metadata == nil || c.Metadata.ID != "rep-1" {
			t.Errorf("chunk %d: metadata = %+v, want the report's", i, c.Metadata)
		}
		if len(c.Findings) > cfg.MaxFindingsPerChunk {
			t.Errorf("chunk %d: %d findings exceeds %d", i, len(c.Findings), cfg.MaxFindingsPerChunk)
		}
		inChunk := map[string]bool{}
		for _, a := range c.Assets {
			if inChunk[a.ID] {
				t.Errorf("chunk %d: asset %s twice", i, a.ID)
			}
			inChunk[a.ID] = true
			assetsSeen[a.ID] = true
		}
		for _, f := range c.Findings {
			if !inChunk[f.AssetRef] {
				t.Errorf("chunk %d: finding %s references asset %s, which the chunk does not carry", i, f.ID, f.AssetRef)
			}
		}
		findings += len(c.Findings)
	}
	if findings != len(report.Findings) {
		t.Errorf("findings across chunks = %d, want %d", findings, len(report.Findings))
	}
	for _, a := range report.Assets {
		if !assetsSeen[a.ID] {
			t.Errorf("asset %s is in no chunk", a.ID)
		}
	}
}

// A chunk holding only part of one asset's findings must not claim full
// coverage: the platform would auto-resolve that asset's findings still to
// come in the next chunk. The chunk with the asset's last findings keeps it.
func TestSplit_PartialAssetChunksDoNotClaimFullCoverage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinFindingsForChunking = 10
	cfg.MaxFindingsPerChunk = 40

	report := &ctis.Report{
		Tool:     &ctis.Tool{Name: "semgrep"},
		Metadata: ctis.ReportMetadata{ID: "rep-2", CoverageType: "full"},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: "repo/a"}},
	}
	for i := range 100 {
		report.Findings = append(report.Findings, ctis.Finding{ID: fmt.Sprint(i), Title: "t", Severity: "low", AssetRef: "a"})
	}

	chunks, err := NewSplitter(cfg).Split(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		want := "partial"
		if i == len(chunks)-1 {
			want = "full"
		}
		if c.Metadata.CoverageType != want {
			t.Errorf("chunk %d: coverage_type %q, want %q", i, c.Metadata.CoverageType, want)
		}
	}
	if report.Metadata.CoverageType != "full" {
		t.Error("splitting must not modify the report's own metadata")
	}
}
