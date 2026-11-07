package core

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// A code scan declares full coverage of its branch only when the run ended
// by itself: a stopped or failed run is partial, so the platform's branch
// sweep closes nothing from it (research 467 F6).
func TestFetchedSourceCoverageFollowsTheRun(t *testing.T) {
	src := &fetchedSource{repository: "github.com/example/app", branch: "main", commit: "abc"}
	if got := src.emptyReport("semgrep", true).Metadata.CoverageType; got != ctis.CoverageFull {
		t.Errorf("completed run: %q, want full", got)
	}
	if got := src.emptyReport("semgrep", false).Metadata.CoverageType; got != ctis.CoveragePartial {
		t.Errorf("stopped run: %q, want partial", got)
	}
	r := ctis.NewReport()
	src.annotate(r, false)
	if r.Metadata.CoverageType != ctis.CoveragePartial || r.Metadata.Branch == nil || r.Metadata.Branch.Name != "main" {
		t.Errorf("annotate of a stopped run: %+v", r.Metadata)
	}
}
