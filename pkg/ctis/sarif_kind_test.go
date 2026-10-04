package ctis

import (
	"os"
	"testing"
)

// Mirrors github.com/openctemio/ctis#10 (same sample, testdata/sarif/kinds.sarif).
// SARIF result.kind is carried as finding.kind in snake_case (SARIF's
// "notApplicable" becomes "not_applicable"); baselineState is matched
// case-insensitively; values outside SARIF's sets are left unset, and an absent
// kind is not defaulted to SARIF's implicit "fail".
//
// FromSARIF converts every run (the old hand copy converted only the first):
// the sample's two runs give eight findings; the first run's four are checked.
func TestFromSARIF_ResultKindAndBaselineState(t *testing.T) {
	data, err := os.ReadFile("testdata/sarif/kinds.sarif")
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultConvertOptions()
	opts.AssetValue = "github.com/example/infra"
	report, err := FromSARIF(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ kind, baseline string }{
		{"fail", "new"},
		{"review", "unchanged"},
		{"not_applicable", ""},
		{"pass", "absent"},
	}
	if len(report.Findings) != 8 {
		t.Fatalf("got %d findings, want 8 (two runs of four)", len(report.Findings))
	}
	for i, w := range want {
		f := report.Findings[i]
		if f.Kind != w.kind || f.BaselineState != w.baseline {
			t.Errorf("finding %d: kind=%q baseline_state=%q, want %q/%q", i, f.Kind, f.BaselineState, w.kind, w.baseline)
		}
	}
}

func TestNormalizeSARIFKind(t *testing.T) {
	cases := map[string]string{
		"notApplicable":  "not_applicable",
		"NotApplicable":  "not_applicable",
		"not_applicable": "not_applicable",
		"notapplicable":  "not_applicable",
		"pass":           "pass",
		"FAIL":           "fail",
		"Review":         "review",
		"open":           "open",
		"informational":  "informational",
		"":               "",
		"warning":        "",
	}
	for in, want := range cases {
		if got := NormalizeSARIFKind(in); got != want {
			t.Errorf("NormalizeSARIFKind(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NormalizeSARIFKind("\treview\n"); got != "review" {
		t.Errorf("surrounding whitespace: got %q", got)
	}
	if got := NormalizeSARIFBaselineState("Unchanged"); got != "unchanged" {
		t.Errorf("NormalizeSARIFBaselineState(Unchanged) = %q", got)
	}
	if got := NormalizeSARIFBaselineState("modified"); got != "" {
		t.Errorf("NormalizeSARIFBaselineState(modified) = %q, want unset", got)
	}
}
