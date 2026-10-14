package toolcli

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// The scaffold's config declares the capability's standard params. The
// platform sends them in the scan's config, so they must be scan-scoped:
// the executor refuses a scan-layer value for a sensor-scoped key.
func TestScaffold_StandardParamsAreScanScoped(t *testing.T) {
	_, m, err := Scaffold(KindExecCTIS, "scan.ports@1", "acme-ports")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := m.ConfigSchema()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range schema.Properties {
		if p.Scope != core.SettingScopeScan {
			t.Errorf("param %s: scope %q, want scan", p.Name, p.Scope)
		}
	}
	scan := core.SettingsLayer{Source: core.SettingSourceScan, Values: map[string]any{"ports": "80,443", "top_n": 100}}
	if _, err := schema.Resolve(scan); err != nil {
		t.Fatalf("a scan-level value for a standard param is refused: %v", err)
	}
}
