package toolcompat

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// A bridged scan runs in another process: the job's rule sources must
// reach it with the custom template directory, or a tenant-only job would
// run the platform's rules there.
func TestScanLocalCarriesRuleSources(t *testing.T) {
	in := &core.ScanOptions{CustomTemplateDir: "/w/tpl", RuleSources: core.RuleSourcesTenant}
	raw, err := json.Marshal(scanLocalOf(in))
	if err != nil {
		t.Fatal(err)
	}
	var back scanLocal
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got := back.options()
	if got.RuleSources != core.RuleSourcesTenant || got.CustomTemplateDir != "/w/tpl" {
		t.Fatalf("options = %+v, want tenant rule sources and the template dir", got)
	}
}
