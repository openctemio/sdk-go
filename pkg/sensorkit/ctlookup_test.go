package sensorkit

import (
	"slices"
	"testing"

	"github.com/openctemio/contract/ctlookup"
)

// A shared sensor with a pinned job-signing key answers CT lookups by
// default and reports lookup.ct@1; the host turns it off with 0. An
// organization's sensor never does: silently off by default, a usage error
// when 1 asks for it.
func TestServeCTLookup(t *testing.T) {
	t.Setenv(EnvCTLookup, "")
	k := relayKit(t, true, true)
	if on, err := k.ServeCTLookup(); !on || err != nil || !slices.Contains(reported(k), ctlookup.Capability) || k.ctLookup == nil {
		t.Fatalf("on by default on a shared sensor: %v %v %v", on, err, reported(k))
	}

	t.Setenv(EnvCTLookup, "0")
	k = relayKit(t, true, true)
	if on, err := k.ServeCTLookup(); on || err != nil || slices.Contains(reported(k), ctlookup.Capability) {
		t.Fatalf("0 turns it off: %v %v", on, err)
	}

	for _, tc := range []struct {
		shared, pinned bool
	}{{false, true}, {true, false}} {
		t.Setenv(EnvCTLookup, "")
		k = relayKit(t, tc.shared, tc.pinned)
		if on, err := k.ServeCTLookup(); on || err != nil || slices.Contains(reported(k), ctlookup.Capability) {
			t.Fatalf("%+v: off without a word by default: %v %v", tc, on, err)
		}
		t.Setenv(EnvCTLookup, "1")
		k = relayKit(t, tc.shared, tc.pinned)
		if _, err := k.ServeCTLookup(); err == nil {
			t.Fatalf("%+v: 1 on a sensor that cannot is a usage error", tc)
		}
	}

	t.Setenv(EnvCTLookup, "yes")
	if _, err := relayKit(t, true, true).ServeCTLookup(); err == nil {
		t.Fatal("unknown value accepted")
	}
}

func TestCTLookupSourceSettings(t *testing.T) {
	t.Setenv(EnvCTLookup, "")
	for _, bad := range []struct{ env, v string }{
		{EnvCTCRTSHURL, "http://mirror.example"},
		{EnvCTCRTSHURL, "https://u:p@mirror.example"},
		{EnvCTCertSpotterURL, "https://mirror.example/?x=1"},
		{EnvCTCertSpotterKey, "a key with spaces"},
		{EnvCTCertSpotterKeyFile, "/nonexistent/key"},
	} {
		t.Run(bad.env+"="+bad.v, func(t *testing.T) {
			t.Setenv(bad.env, bad.v)
			if _, err := relayKit(t, true, true).ServeCTLookup(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Setenv(EnvCTCRTSHURL, "https://crt.mirror.example")
	t.Setenv(EnvCTCertSpotterURL, "off")
	t.Setenv(EnvCTCertSpotterKey, "k-123")
	if on, err := relayKit(t, true, true).ServeCTLookup(); !on || err != nil {
		t.Fatalf("mirror settings refused: %v", err)
	}
}
