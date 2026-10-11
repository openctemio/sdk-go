package client

import (
	"testing"
	"time"
)

func TestGRPCBackoffGrowsAndCaps(t *testing.T) {
	base := 30 * time.Minute
	for n, want := range map[int]time.Duration{1: 30 * time.Minute, 2: time.Hour, 3: 2 * time.Hour, 4: 4 * time.Hour, 9: 4 * time.Hour} {
		if got := grpcBackoff(base, n); got != want {
			t.Errorf("failures %d: %s, want %s", n, got, want)
		}
	}
}

func TestSelectionMemory(t *testing.T) {
	dir := t.TempDir()
	m := &v3Manager{opts: TransportOptions{CertDir: dir, ReprobeInterval: time.Hour}}
	now := time.Now()
	if _, skip := m.skipGRPC(now); skip {
		t.Fatal("nothing remembered yet")
	}
	m.remember(BindingHTTPS, ReasonHandshakeFailed, now)
	if r, skip := m.skipGRPC(now.Add(30 * time.Minute)); !skip || r != ReasonHandshakeFailed {
		t.Fatalf("within the backoff: %q %v", r, skip)
	}
	if _, skip := m.skipGRPC(now.Add(61 * time.Minute)); skip {
		t.Fatal("after the backoff gRPC is tried again")
	}
	// A second failure doubles the wait; it survives a restart.
	m.remember(BindingHTTPS, ReasonHandshakeFailed, now)
	restarted := &v3Manager{opts: TransportOptions{CertDir: dir, ReprobeInterval: time.Hour}}
	if _, skip := restarted.skipGRPC(now.Add(90 * time.Minute)); !skip {
		t.Fatal("two failures: 2h backoff, remembered across a restart")
	}
	// A platform reason is never a backoff; success clears it.
	restarted.remember(BindingHTTPS, ReasonPlatformWithoutGRPC, now)
	if _, skip := restarted.skipGRPC(now); skip {
		t.Fatal("a platform without gRPC is asked again at the next negotiation")
	}
	restarted.remember(BindingGRPC, "", now)
	if _, skip := restarted.skipGRPC(now); skip || restarted.sel.Failures != 0 {
		t.Fatal("success clears the failures")
	}
}

func TestNextNegotiationIsSoonerForPlatformReasons(t *testing.T) {
	m := &v3Manager{opts: TransportOptions{ReprobeInterval: time.Hour}}
	if d := m.nextNegotiation(&v3State{reason: ReasonPlatformWithoutGRPC}); d > platformRecheck {
		t.Fatalf("platform without gRPC: %s, want at most %s", d, platformRecheck)
	}
	if d := m.nextNegotiation(&v3State{reason: ReasonGRPCUnreachable}); d < 30*time.Minute {
		t.Fatalf("network failure: %s, want at least half the reprobe interval", d)
	}
}
