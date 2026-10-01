package adapters_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapters/betterleaks"
	"github.com/openctemio/sdk-go/pkg/adapters/nuclei"
	"github.com/openctemio/sdk-go/pkg/adapters/sarif"
	"github.com/openctemio/sdk-go/pkg/adapters/semgrep"
	"github.com/openctemio/sdk-go/pkg/adapters/trivy"
	"github.com/openctemio/sdk-go/pkg/adapters/vuls"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

var update = flag.Bool("update", false, "rewrite the golden CTIS files in testdata")

// repo is the repository the sensor passes for a code scan.
var repo = &core.AdapterOptions{Repository: "github.com/example/shop", Branch: "main", CommitSHA: "3f1c2a9e"}

// goldenCases is every adapter over its fixtures. Each case's CTIS output is
// pinned in testdata/<name>.ctis.golden.json, and every finding of it must
// resolve to an asset of the same report (ctis.CheckFindingAssets), the rule
// protocol v2 ingest enforces.
var goldenCases = []struct {
	name    string
	adapter core.Adapter
	input   string
	opts    *core.AdapterOptions
}{
	{"sarif", sarif.NewAdapter(), "sarif.sarif.json", repo},
	// No options: the repository comes from versionControlProvenance.
	{"sarif-provenance", sarif.NewAdapter(), "codeql-provenance.sarif.json", nil},
	{"semgrep", semgrep.NewAdapter(), "semgrep.json", repo},
	{"betterleaks", betterleaks.NewAdapter(), "betterleaks.json", repo},
	// No options: an image scan names its own asset, the image.
	{"trivy-image", trivy.NewAdapter(), "trivy.json", nil},
	{"trivy-fs", trivy.NewAdapter(), "trivy-fs.json", repo},
	// One asset per host the results matched.
	{"nuclei", nuclei.NewAdapter(), "nuclei.jsonl", nil},
	{"vuls", vuls.NewAdapter(), "vuls.json", nil},
}

func TestAdapters_GoldenCTIS(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", tc.input))
			if err != nil {
				t.Fatal(err)
			}
			report, err := tc.adapter.Convert(context.Background(), input, tc.opts)
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if len(report.Findings) == 0 {
				t.Fatal("fixture produced no finding: the case proves nothing")
			}
			if err := ctis.CheckFindingAssets(report); err != nil {
				t.Fatalf("CheckFindingAssets: %v", err)
			}
			for i, f := range report.Findings {
				if f.AssetRef == "" {
					t.Errorf("finding %d has no explicit asset_ref", i)
				}
			}

			report.Metadata.Timestamp = time.Time{} // the only wall-clock field
			got, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')

			golden := filepath.Join("testdata", tc.name+".ctis.golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden) //nolint:gosec // test fixture path
			if err != nil {
				t.Fatalf("%v (run go test ./pkg/adapters -run TestAdapters_GoldenCTIS -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("CTIS output differs from %s (rerun with -update if the change is intended)\n--- got ---\n%s", golden, got)
			}
		})
	}
}

// Code scanners must never invent an asset: with no repository from the
// options, the log itself or CI, a report with findings is an error.
func TestAdapters_NoRepositoryIsAnError(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	cases := []struct {
		adapter core.Adapter
		input   string
	}{
		{sarif.NewAdapter(), "sarif.sarif.json"},
		{semgrep.NewAdapter(), "semgrep.json"},
		{betterleaks.NewAdapter(), "betterleaks.json"},
		{trivy.NewAdapter(), "trivy-fs.json"},
	}
	for _, tc := range cases {
		t.Run(tc.adapter.Name(), func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", tc.input))
			if err != nil {
				t.Fatal(err)
			}
			report, err := tc.adapter.Convert(context.Background(), input, nil)
			if !errors.Is(err, ctis.ErrNoAssetForFindings) {
				t.Fatalf("err = %v, want ctis.ErrNoAssetForFindings", err)
			}
			if report != nil {
				t.Errorf("report = %+v, want nil", report)
			}
		})
	}
}
