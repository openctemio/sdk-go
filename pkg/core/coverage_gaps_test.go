package core_test

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/mocks"
)

// A scan with hosts it could not fully cover completes (not failed), as
// partial coverage, and its result lists the hosts and why: a host the
// breaker gave up is never read as "no findings".
func TestExecuteScan_CoverageGaps(t *testing.T) {
	gaps := []adapt.Gap{{Host: "a.example.test", Reason: adapt.GapBreakerOpen, Detail: "given up"}}
	res := core.ScanResult{CoverageGaps: gaps, CoverageGapsTotal: 3,
		TargetRate: &adapt.Summary{Ceiling: 20, Hosts: 4, Gaps: gaps, GapsTotal: 3}}
	if got := pushedCoverage(t, res, *ctis.NewReport()); got != "partial" {
		t.Fatalf("coverage %q, want partial", got)
	}

	exec := core.NewDefaultCommandExecutor(&mocks.MockPusher{})
	reg := core.NewParserRegistry()
	reg.Register(&cannedParser{report: *ctis.NewReport()})
	exec.SetParserRegistry(reg)
	res.ScannerName, res.RawOutput = "fakescan", nil // nothing found
	exec.AddScanner(&fixedScanner{name: "fakescan", res: res})
	out, err := exec.Execute(context.Background(), scanCommand(t, "fakescan", "http://203.0.113.10"))
	if err != nil {
		t.Fatalf("a scan with coverage gaps failed: %v", err)
	}
	listed, ok := out.Metadata[core.MetaCoverageGaps].([]adapt.Gap)
	if !ok || len(listed) != 1 || listed[0].Reason != adapt.GapBreakerOpen || out.Metadata[core.MetaCoverageGapsTotal] != 3 {
		t.Fatalf("metadata %+v", out.Metadata)
	}
	sum, ok := out.Metadata[core.MetaTargetRate].(adapt.Summary)
	if !ok || sum.Ceiling != 20 || sum.Gaps != nil {
		t.Fatalf("target_rate %+v, want the summary without its gap list", out.Metadata[core.MetaTargetRate])
	}
}

func TestCoverageGapsMetadataEmpty(t *testing.T) {
	if m := core.CoverageGapsMetadata(&core.ScanResult{}); m != nil {
		t.Fatalf("metadata without gaps: %v", m)
	}
	if m := core.CoverageGapsMetadata(nil); m != nil {
		t.Fatal("nil result")
	}
}

func TestAddCoverageGapsOncePerHost(t *testing.T) {
	r := &core.ScanResult{}
	r.WithTargetRate(&adapt.Summary{Gaps: []adapt.Gap{{Host: "a", Reason: adapt.GapBlocked}}, GapsTotal: 1})
	// The tool saw a, b and 5 more it did not list.
	r.AddCoverageGaps([]adapt.Gap{{Host: "a", Reason: adapt.GapBreakerOpen}, {Host: "b", Reason: adapt.GapBreakerOpen}}, 7)
	if len(r.CoverageGaps) != 2 || r.CoverageGaps[0].Reason != adapt.GapBlocked || r.CoverageGapsTotal != 7 {
		t.Fatalf("gaps %+v total %d, want a (blocked), b; total 7", r.CoverageGaps, r.CoverageGapsTotal)
	}
	r.WithTargetRate(nil)
	if r.TargetRate == nil {
		t.Fatal("a nil summary cleared the rate")
	}
}
