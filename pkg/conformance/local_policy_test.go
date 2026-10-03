package conformance

// api RFC-040 §5.7: the local policy report is additive. A platform that does
// not list "local_policy" on hello never receives it (heartbeat or
// manifest); one that does receives the state, digest and summary.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

func TestLocalPolicy_ReportedOnlyWhereAnnounced(t *testing.T) {
	ctx := context.Background()
	report := &core.LocalPolicyReport{State: core.LocalPolicyStateAbsent, Warnings: []string{"no local policy"}}
	m := &core.Manifest{Schema: core.ManifestSchema, Tools: []core.ManifestTool{{Name: "nuclei", Kind: core.ToolKindScanner, Installed: true}},
		LocalPolicy: report}

	for _, announced := range []bool{false, true} {
		f := newControlFake(t)
		f.SetManifest(true)
		f.SetLocalPolicy(announced)
		c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
		t.Cleanup(func() { _ = c.Close() })

		st := status()
		st.LocalPolicy = report
		if _, err := c.SendHeartbeatWithHints(ctx, st); err != nil {
			t.Fatal(err)
		}
		if _, err := c.PutManifest(ctx, m); err != nil {
			t.Fatal(err)
		}
		beats, manifests := f.Heartbeats(), f.Manifests()
		for what, raw := range map[string]json.RawMessage{"heartbeat": beats[len(beats)-1], "manifest": manifests[len(manifests)-1]} {
			var body struct {
				LocalPolicy *core.LocalPolicyReport `json:"local_policy"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			if announced && (body.LocalPolicy == nil || body.LocalPolicy.State != core.LocalPolicyStateAbsent) {
				t.Errorf("announced: %s without local_policy: %s", what, raw)
			}
			if !announced && body.LocalPolicy != nil {
				t.Errorf("not announced: %s carries local_policy: %s", what, raw)
			}
		}
		// The caller's manifest is never modified.
		if m.LocalPolicy == nil {
			t.Fatal("PutManifest cleared the caller's manifest")
		}
	}
}
