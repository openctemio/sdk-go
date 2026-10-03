package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// The converter fixtures are shared with pkg/adapters.
func sarifFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "adapters", "testdata", name)) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Every finding of the SARIF parser resolves to an asset of its own report
// (ctis.CheckFindingAssets), the rule protocol v2 ingest enforces with no
// fallback asset.
func TestSARIFParser_EveryFindingHasAnAsset(t *testing.T) {
	repo := &core.ParseOptions{AssetType: ctis.AssetTypeRepository, AssetValue: "github.com/example/shop"}
	cases := []struct {
		name  string
		input string
		opts  *core.ParseOptions
	}{
		{"repository", "sarif.sarif.json", repo},
		{"provenance", "codeql-provenance.sarif.json", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := (&core.SARIFParser{}).Parse(context.Background(), sarifFixture(t, tc.input), tc.opts)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(report.Findings) == 0 {
				t.Fatal("fixture produced no finding: the case proves nothing")
			}
			if err := ctis.CheckFindingAssets(report); err != nil {
				t.Fatal(err)
			}
			for i, f := range report.Findings {
				if f.AssetRef == "" {
					t.Errorf("finding %d has no explicit asset_ref", i)
				}
			}
		})
	}
}

// A code scan with findings and no repository (no options, nothing in the
// log, not in CI) is an error: there is no shared fake asset to fall back to.
func TestSARIFParser_NoRepositoryIsAnError(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	for _, opts := range []*core.ParseOptions{nil, {ToolName: "core-sarif"}} {
		report, err := (&core.SARIFParser{}).Parse(context.Background(), sarifFixture(t, "sarif.sarif.json"), opts)
		if !errors.Is(err, ctis.ErrNoAssetForFindings) {
			t.Fatalf("opts %+v: err = %v, want ctis.ErrNoAssetForFindings", opts, err)
		}
		if report != nil {
			t.Errorf("report = %+v, want nil", report)
		}
	}
}
