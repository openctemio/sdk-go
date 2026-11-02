package sensorkit

import (
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/feedrelay"
	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// relayKit is a kit connected to a platform; shared sensors get a guard
// with a pinned job-signing key (as New gives them).
func relayKit(t *testing.T, shared, pinned bool) *Kit {
	t.Helper()
	k := egressKit(ScanEgressPlatform, shared)
	k.client = client.New(&client.Config{BaseURL: "https://platform.example"})
	if pinned {
		priv := ed25519.NewKeyFromSeed(make([]byte, 32))
		keys, err := jobsig.NewKeys(priv.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		v, err := jobsig.NewVerifier(jobsig.Config{Keys: keys})
		if err != nil {
			t.Fatal(err)
		}
		if k.s.jobs, err = core.NewSharedJobGuard(v, "11111111-0000-4000-8000-000000000001"); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

// A shared sensor with a pinned job-signing key relays by default (the
// platform offers rounds only to the sensors its super administrator
// designated); the host turns it off with 0. An organization's sensor
// never relays: silently off by default, a usage error when 1 asks for it.
func TestServeFeedRelay(t *testing.T) {
	t.Setenv(EnvFeedRelay, "")
	k := relayKit(t, true, true)
	if on, err := k.ServeFeedRelay(); !on || err != nil || !slices.Contains(reported(k), feedrelay.Capability) {
		t.Fatalf("on by default on a shared sensor: %v %v %v", on, err, reported(k))
	}
	if !slices.Contains(k.feedRelayOrigins, feedrelay.DefaultOrigins[0]) {
		t.Fatalf("origins %v", k.feedRelayOrigins)
	}
	t.Setenv(EnvFeedRelay, "auto")
	if on, err := relayKit(t, true, true).ServeFeedRelay(); !on || err != nil {
		t.Fatalf("auto: %v %v", on, err)
	}
	for name, kit := range map[string]*Kit{
		"organization sensor": relayKit(t, false, false),
		"no pinned key":       relayKit(t, true, false),
		"no platform":         egressKit(ScanEgressPlatform, true),
	} {
		t.Setenv(EnvFeedRelay, "")
		if on, err := kit.ServeFeedRelay(); on || err != nil || slices.Contains(reported(kit), feedrelay.Capability) {
			t.Errorf("%s, default: %v %v", name, on, err)
		}
		t.Setenv(EnvFeedRelay, "1")
		if on, err := kit.ServeFeedRelay(); on || err == nil || slices.Contains(reported(kit), feedrelay.Capability) {
			t.Errorf("%s, required: %v %v", name, on, err)
		}
	}

	t.Setenv(EnvFeedRelay, "0")
	off := relayKit(t, true, true)
	if on, err := off.ServeFeedRelay(); on || err != nil || slices.Contains(reported(off), feedrelay.Capability) {
		t.Fatalf("turned off by the host: %v %v", on, err)
	}
	t.Setenv(EnvFeedRelay, "1")
	if on, err := relayKit(t, true, true).ServeFeedRelay(); !on || err != nil {
		t.Fatalf("required on a shared sensor: %v %v", on, err)
	}

	t.Setenv(EnvFeedRelay, "yes")
	if _, err := relayKit(t, true, true).ServeFeedRelay(); err == nil {
		t.Fatal("an unrecognized value was accepted")
	}
	t.Setenv(EnvFeedRelay, "")
	t.Setenv(EnvFeedRelayOrigins, "http://mirror.example")
	if _, err := relayKit(t, true, true).ServeFeedRelay(); err == nil {
		t.Fatal("a non-https extra origin was accepted")
	}
}
