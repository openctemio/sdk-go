package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// The posture tells the platform when tools run without the sandbox and
// whether active tools are refused for it.
func TestPostureReportsUnconfinedTools(t *testing.T) {
	t.Cleanup(func() { executor.SetCurrent(nil) })
	b, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	executor.SetCurrent(b)
	p := CurrentPosture()
	if p.Sandbox.Unconfined != executor.UnconfinedAcknowledged {
		t.Fatalf("off: %+v", p.Sandbox)
	}
	raw, _ := json.Marshal(p.Sandbox)
	if !strings.Contains(string(raw), `"unconfined":"acknowledged"`) {
		t.Fatalf("json %s", raw)
	}
	// A sandboxed host reports nothing for it.
	if raw, _ := json.Marshal(SandboxPosture{Mode: "auto", Sandboxed: true}); strings.Contains(string(raw), "unconfined") {
		t.Fatalf("sandboxed json %s", raw)
	}
}
