package conformance

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// PlatformSupports answers from the platform's hello: what it lists is
// supported, a name it does not list (a feature of a newer platform) is not,
// and an older platform without protocol v2, or a client set to v1,
// supports nothing.
func TestPlatformSupports(t *testing.T) {
	f := NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	c := newClient(t, f, "")
	if !c.PlatformSupports(t.Context(), protov2.FeatureHeartbeat) {
		t.Error("heartbeat listed on hello but not supported")
	}
	if c.PlatformSupports(t.Context(), "x-feature-of-a-newer-platform") {
		t.Error("an unlisted feature is supported")
	}
	if c.PlatformSupports(t.Context(), protov2.FeatureManifest) {
		t.Error("manifest is not listed (Manifest off) but is supported")
	}

	old := NewFakePlatform(false)
	t.Cleanup(old.Close)
	if newClient(t, old, "").PlatformSupports(t.Context(), protov2.FeatureResults) {
		t.Error("a platform without protocol v2 supports results v2")
	}
	if newClient(t, f, client.ProtocolV1).PlatformSupports(t.Context(), protov2.FeatureHeartbeat) {
		t.Error("a client set to protocol v1 uses a v2 feature")
	}
}
