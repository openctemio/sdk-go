package conformance

// api RFC-033: the client registers the manifest only where hello lists
// "manifest", and the heartbeat echoes the platform's digest.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

func TestManifest_RegisteredWhereServed(t *testing.T) {
	ctx := context.Background()
	m := &core.Manifest{Schema: core.ManifestSchema, Capabilities: []string{"validate"},
		Tools: []core.ManifestTool{{Name: "nuclei", Kind: core.ToolKindScanner, Installed: true, Capabilities: []string{"dast"}}}}

	// A platform without manifests: unsupported, nothing sent.
	f := newControlFake(t)
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.PutManifest(ctx, m); !errors.Is(err, core.ErrManifestUnsupported) {
		t.Fatalf("without the feature: %v", err)
	}
	if len(f.Manifests()) != 0 {
		t.Fatal("a manifest was sent to a platform that does not list it")
	}

	// With it: registered, and the digest is the platform's canonical one.
	f2 := newControlFake(t)
	f2.SetManifest(true)
	c2 := client.New(&client.Config{BaseURL: f2.URL(), APIKey: f2.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c2.Close() })
	ack, err := c2.PutManifest(ctx, m)
	if err != nil || !ack.Changed || len(ack.AcceptedTools) != 1 {
		t.Fatalf("register: %+v %v", ack, err)
	}
	if local, _ := m.Digest(); ack.Digest != local {
		t.Fatalf("platform digest %s, local %s", ack.Digest, local)
	}

	// The heartbeat echoes it; a platform that lost it asks again.
	st := status()
	st.ManifestDigest = ack.Digest
	hints, err := c2.SendHeartbeatWithHints(ctx, st)
	if err != nil || len(hints.Actions) != 0 {
		t.Fatalf("heartbeat: %+v %v", hints, err)
	}
	var body struct {
		ManifestDigest string `json:"manifest_digest"`
	}
	beats := f2.Heartbeats()
	if err := json.Unmarshal(beats[len(beats)-1], &body); err != nil || body.ManifestDigest != ack.Digest {
		t.Fatalf("heartbeat did not carry the digest: %s", beats[len(beats)-1])
	}
	f2.ForgetManifest()
	hints, err = c2.SendHeartbeatWithHints(ctx, st)
	if err != nil || len(hints.Actions) != 1 || hints.Actions[0] != core.HeartbeatActionSendManifest {
		t.Fatalf("lost digest: %+v %v", hints, err)
	}
}
