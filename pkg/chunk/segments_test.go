package chunk

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

func segReport(assets, findingsPerAsset int) *ctis.Report {
	r := &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{ID: "r1", Timestamp: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), CoverageType: "full"},
		Tool:     &ctis.Tool{Name: "semgrep", Version: "1.0"},
		Dependencies: []ctis.Dependency{{
			Name: "lib", Version: "1.0",
		}},
	}
	for a := range assets {
		r.Assets = append(r.Assets, ctis.Asset{ID: fmt.Sprintf("a%d", a), Type: ctis.AssetTypeRepository, Value: fmt.Sprintf("github.com/o/r%d", a)})
		for f := range findingsPerAsset {
			r.Findings = append(r.Findings, ctis.Finding{
				ID: fmt.Sprintf("f%d-%d", a, f), Title: "t", Severity: ctis.SeverityLow,
				Type: ctis.FindingTypeVulnerability, AssetRef: fmt.Sprintf("a%d", a),
				Fingerprint: fmt.Sprintf("fp-%d-%d", a, f),
			})
		}
	}
	return r
}

// assertSegmentInvariants checks RFC-026 §3.5 for a split.
func assertSegmentInvariants(t *testing.T, orig *ctis.Report, segs []*ctis.Report, lim SegmentLimits) {
	t.Helper()
	seen := map[string]int{}
	for i, s := range segs {
		if s.Version != orig.Version || !reflect.DeepEqual(s.Tool, orig.Tool) || !reflect.DeepEqual(s.Metadata, orig.Metadata) {
			t.Fatalf("segment %d header differs from the report", i)
		}
		if len(s.Findings) > lim.MaxFindings || len(s.Assets) > lim.MaxAssets {
			t.Fatalf("segment %d over limits: %d findings, %d assets", i, len(s.Findings), len(s.Assets))
		}
		ids := map[string]bool{}
		for _, a := range s.Assets {
			ids[a.ID] = true
		}
		for _, f := range s.Findings {
			if f.AssetRef != "" && !ids[f.AssetRef] && hasAsset(orig, f.AssetRef) {
				t.Fatalf("segment %d: finding %s references asset %s it does not carry", i, f.ID, f.AssetRef)
			}
			seen[f.ID]++
		}
		if i > 0 && (s.Dependencies != nil || s.Properties != nil) {
			t.Fatalf("segment %d carries report-level data", i)
		}
	}
	for _, f := range orig.Findings {
		if seen[f.ID] != 1 {
			t.Fatalf("finding %s appears %d times", f.ID, seen[f.ID])
		}
	}
	if !reflect.DeepEqual(segs[0].Dependencies, orig.Dependencies) {
		t.Fatal("dependencies not in segment 0")
	}
}

func hasAsset(r *ctis.Report, id string) bool {
	for _, a := range r.Assets {
		if a.ID == id {
			return true
		}
	}
	return false
}

func TestSplitSegments_FitsInOne(t *testing.T) {
	r := segReport(2, 3)
	segs, err := SplitSegments(r, SegmentLimits{MaxFindings: 100, MaxAssets: 100, MaxBytes: 1 << 20})
	if err != nil || len(segs) != 1 || segs[0] != r {
		t.Fatalf("segs=%d err=%v", len(segs), err)
	}
}

func TestSplitSegments_ByFindingCount(t *testing.T) {
	r := segReport(5, 7) // 35 findings
	lim := SegmentLimits{MaxFindings: 4, MaxAssets: 100, MaxBytes: 1 << 20}
	segs, err := SplitSegments(r, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 9 {
		t.Fatalf("got %d segments for 35 findings at 4 per segment", len(segs))
	}
	assertSegmentInvariants(t, r, segs, lim)
}

func TestSplitSegments_ByAssetCountAndBytes(t *testing.T) {
	r := segReport(30, 2)
	// Unreferenced assets too.
	for i := range 10 {
		r.Assets = append(r.Assets, ctis.Asset{ID: fmt.Sprintf("lonely%d", i), Type: ctis.AssetTypeDomain, Value: fmt.Sprintf("h%d.example", i)})
	}
	lim := SegmentLimits{MaxFindings: 1000, MaxAssets: 3, MaxBytes: 4096}
	segs, err := SplitSegments(r, lim)
	if err != nil {
		t.Fatal(err)
	}
	assertSegmentInvariants(t, r, segs, lim)
	assets := map[string]bool{}
	for _, s := range segs {
		b, _ := json.Marshal(s)
		if len(b) > 2*lim.MaxBytes {
			t.Fatalf("segment of %d bytes", len(b))
		}
		for _, a := range s.Assets {
			assets[a.ID] = true
		}
	}
	if len(assets) != len(r.Assets) {
		t.Fatalf("%d of %d assets sent", len(assets), len(r.Assets))
	}
}

func TestBindFindingAssets(t *testing.T) {
	r := &ctis.Report{
		Assets:   []ctis.Asset{{Type: ctis.AssetTypeRepository, Value: "github.com/o/r"}},
		Findings: []ctis.Finding{{ID: "f1"}, {ID: "f2", AssetRef: "missing"}},
	}
	if n := BindFindingAssets(r); n != 1 {
		t.Fatalf("unresolved = %d, want 1", n)
	}
	if r.Assets[0].ID == "" || r.Findings[0].AssetRef != r.Assets[0].ID {
		t.Fatalf("finding not bound to the only asset: %+v", r.Findings[0])
	}

	// Several assets: an empty asset_ref is never guessed.
	r2 := segReport(2, 1)
	r2.Findings = append(r2.Findings, ctis.Finding{ID: "orphan", Title: "t"})
	if n := BindFindingAssets(r2); n != 1 || r2.Findings[2].AssetRef != "" {
		t.Fatalf("orphan bound or not counted: n=%d ref=%q", n, r2.Findings[2].AssetRef)
	}
	segs, err := SplitSegments(r2, SegmentLimits{MaxFindings: 1, MaxAssets: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range segs {
		for _, f := range s.Findings {
			if f.ID == "orphan" && len(s.Assets) != 0 {
				t.Fatal("an unresolved finding shares a segment with an asset it could be bound to")
			}
		}
	}
}

func TestSplitSegments_RejectsBadLimits(t *testing.T) {
	if _, err := SplitSegments(segReport(1, 1), SegmentLimits{}); err == nil {
		t.Fatal("zero limits accepted")
	}
}
