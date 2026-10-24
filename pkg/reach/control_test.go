package reach

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

var netipZero netip.Addr

func okDial(n *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		n.Add(1)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
}

func TestControlTellsSensorFaultFromTargetFact(t *testing.T) {
	var dials atomic.Int32
	okResolve := func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.1")}, nil }
	failDial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("network is unreachable")
	}
	failResolve := func(context.Context, string) ([]net.IP, error) { return nil, &net.DNSError{Err: "server misbehaving"} }

	cases := []struct {
		name       string
		c          *Control
		wantPath   ProbeState
		wantDNS    ProbeState
		faultNoRte bool
		faultDNS   bool
	}{
		{"all fine: the targets are the cause", &Control{Dial: okDial(&dials), Endpoint: "echo.example:443", Resolve: okResolve, Name: "echo.example"},
			ProbeOK, ProbeOK, false, false},
		{"path down: no route out is the sensor's", &Control{Dial: failDial, Endpoint: "echo.example:443", Resolve: okResolve, Name: "echo.example"},
			ProbeFailed, ProbeOK, true, false},
		{"resolver down: dns failures are the sensor's, timeouts are not", &Control{Dial: okDial(&dials), Endpoint: "echo.example:443", Resolve: failResolve, Name: "echo.example"},
			ProbeOK, ProbeFailed, false, true},
		{"nothing configured: nothing is charged", &Control{}, ProbeSkipped, ProbeSkipped, false, false},
		{"empty answer is a failed lookup", &Control{Resolve: func(context.Context, string) ([]net.IP, error) { return nil, nil }, Name: "echo.example"},
			ProbeSkipped, ProbeFailed, false, true},
	}
	for _, tc := range cases {
		res := tc.c.Check(context.Background())
		if res.Path != tc.wantPath || res.DNS != tc.wantDNS {
			t.Errorf("%s: path %s dns %s, want %s %s", tc.name, res.Path, res.DNS, tc.wantPath, tc.wantDNS)
		}
		if res.SensorFault(Timeout) != tc.faultNoRte || res.SensorFault(NoRoute) != tc.faultNoRte || res.SensorFault(DNSFailure) != tc.faultDNS {
			t.Errorf("%s: faults wrong: %+v", tc.name, res)
		}
		if res.SensorFault(Reached) || res.SensorFault(PortClosed) {
			t.Errorf("%s: a reached target is never a sensor fault", tc.name)
		}
	}
	var nilCtl *Control
	if r := nilCtl.Check(context.Background()); r.Checked() || r.SensorFault(Timeout) {
		t.Errorf("nil control charged something: %+v", r)
	}
}

func TestControlCachesAndBoundsEachProbe(t *testing.T) {
	var dials atomic.Int32
	now := time.Unix(1_000_000, 0)
	c := &Control{Dial: okDial(&dials), Endpoint: "echo.example:443", TTL: time.Minute, now: func() time.Time { return now }}
	c.Check(context.Background())
	c.Check(context.Background())
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want one probe for the task", dials.Load())
	}
	now = now.Add(2 * time.Minute)
	c.Check(context.Background())
	if dials.Load() != 2 {
		t.Fatalf("dials = %d after the TTL", dials.Load())
	}

	// A probe that hangs is cut at Timeout and counts as failed.
	hang := &Control{Timeout: 50 * time.Millisecond, Endpoint: "echo.example:443",
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	start := time.Now()
	if res := hang.Check(context.Background()); res.Path != ProbeFailed || time.Since(start) > 2*time.Second {
		t.Fatalf("hanging probe: %+v after %v", res, time.Since(start))
	}
}

func TestControlCanceledJobChargesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Control{Endpoint: "echo.example:443", Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		cancel()
		return nil, ctx.Err()
	}}
	if res := c.Check(ctx); res.Checked() || res.SensorFault(Timeout) {
		t.Fatalf("a canceled job charged the sensor: %+v", res)
	}
	if c.last.Checked() {
		t.Fatal("a canceled check was cached")
	}
}

func TestControlInContext(t *testing.T) {
	c := &Control{}
	if ControlFromContext(WithControl(context.Background(), c)) != c || ControlFromContext(context.Background()) != nil || ControlFromContext(nil) != nil { //nolint:staticcheck // nil context is the documented no-op
		t.Fatal("context round trip")
	}
}

func TestLookupFindsATargetUnderAnotherSpelling(t *testing.T) {
	r := NewRecorder()
	r.Record(Observation{Target: "shop.example.com", Class: Timeout})
	r.Record(Observation{Target: "198.51.100.7:8443", Class: Reached})
	for _, q := range []string{"shop.example.com", "https://shop.example.com/login?x=1", "https://user@Shop.Example.com:443/", "shop.example.com."} {
		if c, _, ok := r.Lookup(q); !ok || c != Timeout {
			t.Errorf("Lookup(%q) = %v %v", q, c, ok)
		}
	}
	if c, _, ok := r.Lookup("http://198.51.100.7/"); !ok || c != Reached {
		t.Errorf("address under a URL: %v %v", c, ok)
	}
	if _, _, ok := r.Lookup("other.example"); ok {
		t.Error("found a target that was never recorded")
	}
	var nilRec *Recorder
	if _, _, ok := nilRec.Lookup("x"); ok {
		t.Error("nil recorder found something")
	}
	for in, want := range map[string]string{"": "", "https://[2001:db8::1]:8443/x": "2001:db8::1", "[2001:db8::1]": "2001:db8::1", "2001:db8::1": "2001:db8::1", "Host:80": "host", "ssh://git@h.example:22/r": "h.example"} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
