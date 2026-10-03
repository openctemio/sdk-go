package tenable

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Every finding of a converted Nessus export resolves to an asset of its own
// report (ctis.CheckFindingAssets), the rule protocol v2 ingest enforces with
// no fallback asset. The fixture is shared with pkg/adapters.
func TestConvert_EveryFindingHasAnAsset(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "adapters", "testdata", "tenable.nessus"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report, err := Convert(f, ConvertOptions{})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("fixture produced no finding: the case proves nothing")
	}
	if err := ctis.CheckFindingAssets(report); err != nil {
		t.Fatal(err)
	}
	for i, finding := range report.Findings {
		if finding.AssetRef == "" {
			t.Errorf("finding %d has no explicit asset_ref", i)
		}
	}
}
