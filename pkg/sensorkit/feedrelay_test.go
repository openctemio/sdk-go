package sensorkit

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/feedrelay"
)

// The feed relay is off unless the host operator turns it on, and only a
// shared sensor connected to a platform may relay: anywhere else the
// setting is a usage error, never a silent no-op.
func TestServeFeedRelay(t *testing.T) {
	withClient := func(shared bool) *Kit {
		k := egressKit(ScanEgressPlatform, shared)
		k.client = client.New(&client.Config{BaseURL: "https://platform.example"})
		return k
	}
	t.Setenv(EnvFeedRelay, "")
	if on, err := withClient(true).ServeFeedRelay(); on || err != nil {
		t.Fatalf("off by default: %v %v", on, err)
	}

	t.Setenv(EnvFeedRelay, "1")
	k := withClient(true)
	if on, err := k.ServeFeedRelay(); !on || err != nil || !slices.Contains(reported(k), feedrelay.Capability) {
		t.Fatalf("shared sensor: %v %v %v", on, err, reported(k))
	}
	if !slices.Contains(k.feedRelayOrigins, feedrelay.DefaultOrigins[0]) {
		t.Fatalf("origins %v", k.feedRelayOrigins)
	}

	org := withClient(false)
	if on, err := org.ServeFeedRelay(); on || err == nil || slices.Contains(reported(org), feedrelay.Capability) {
		t.Fatalf("an organization sensor must not relay: %v %v", on, err)
	}
	if on, err := egressKit(ScanEgressPlatform, true).ServeFeedRelay(); on || err == nil {
		t.Fatalf("no platform connection: %v %v", on, err)
	}

	t.Setenv(EnvFeedRelay, "yes")
	if _, err := withClient(true).ServeFeedRelay(); err == nil {
		t.Fatal("an unrecognized value was accepted")
	}
	t.Setenv(EnvFeedRelay, "1")
	t.Setenv(EnvFeedRelayOrigins, "http://mirror.example")
	if _, err := withClient(true).ServeFeedRelay(); err == nil {
		t.Fatal("a non-https extra origin was accepted")
	}
}
