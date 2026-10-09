package conformance

// api RFC-040: the posture is additive. A platform that does not list
// "posture" on hello never receives it; one that does receives the platform
// TLS pin and the tool sandbox under the documented names.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

func TestPosture_ReportedOnlyWhereAnnounced(t *testing.T) {
	ctx := context.Background()
	m := &core.Manifest{Schema: core.ManifestSchema, Tools: []core.ManifestTool{{Name: "nuclei", Kind: core.ToolKindScanner, Installed: true}},
		Posture: &core.SensorPosture{PlatformTLS: &core.PlatformTLSPosture{Pin: core.TLSPinCAFile},
			Sandbox: &core.SandboxPosture{Mode: "auto", Sandboxed: true, NetworkEnforced: true}}}

	for _, announced := range []bool{false, true} {
		f := newControlFake(t)
		f.SetManifest(true)
		f.SetPosture(announced)
		c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
		t.Cleanup(func() { _ = c.Close() })
		if _, err := c.PutManifest(ctx, m); err != nil {
			t.Fatal(err)
		}
		manifests := f.Manifests()
		var body struct {
			Posture *struct {
				PlatformTLS *struct {
					Pin string `json:"pin"`
				} `json:"platform_tls"`
				Sandbox *struct {
					Mode            string `json:"mode"`
					Sandboxed       bool   `json:"sandboxed"`
					NetworkEnforced bool   `json:"network_enforced"`
				} `json:"sandbox"`
			} `json:"posture"`
		}
		raw := manifests[len(manifests)-1]
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		if !announced && body.Posture != nil {
			t.Errorf("not announced: the manifest carries posture: %s", raw)
		}
		if announced && (body.Posture == nil || body.Posture.PlatformTLS == nil || body.Posture.PlatformTLS.Pin != core.TLSPinCAFile ||
			body.Posture.Sandbox == nil || body.Posture.Sandbox.Mode != "auto" || !body.Posture.Sandbox.NetworkEnforced) {
			t.Errorf("announced: posture missing or wrong: %s", raw)
		}
		if m.Posture == nil {
			t.Fatal("PutManifest cleared the caller's manifest")
		}
	}
}
