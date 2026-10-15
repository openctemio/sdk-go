package core

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func resolvesTo(addr string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP(addr)}, nil }
}

func zoneCtx(ranges ...string) context.Context {
	return WithJobZone(context.Background(), ParseZoneRanges(ranges))
}

// SECURITY: on a shared sensor a name that resolves to an internal address
// is refused: a metadata, loopback, link-local or CGNAT address always; a
// private one unless the operator allows private targets and the job's
// zone contains it.
func TestSharedScanTargetPolicy(t *testing.T) {
	cases := []struct {
		name         string
		addr         string
		allowPrivate bool
		zone         []string
		ok           bool
	}{
		{"public", "203.0.113.10", false, nil, true},
		{"private, no zone", "10.1.2.3", true, nil, false},
		{"private, other zone", "10.1.2.3", true, []string{"192.168.0.0/16"}, false},
		{"private, in zone", "10.1.2.3", true, []string{"10.1.0.0/16"}, true},
		{"private, in zone, operator refuses", "10.1.2.3", false, []string{"10.1.0.0/16"}, false},
		{"metadata, zone cannot allow", "169.254.169.254", true, []string{"169.254.0.0/16", "10.0.0.0/8"}, false},
		{"loopback", "127.0.0.1", true, []string{"127.0.0.0/8"}, false},
		{"cgnat", "100.64.0.1", true, []string{"100.64.0.0/10"}, false},
		{"aws ipv6 metadata", "fd00:ec2::254", true, []string{"fd00::/8"}, false},
	}
	for _, c := range cases {
		p := &ScanTargetPolicy{Shared: true, AllowPrivate: c.allowPrivate, LookupIP: resolvesTo(c.addr)}
		_, err := p.Validate(zoneCtx(c.zone...), "https://app.example.com/")
		if (err == nil) != c.ok {
			t.Errorf("%s: name: err %v, want ok %v", c.name, err, c.ok)
		}
		_, err = p.Validate(zoneCtx(c.zone...), c.addr)
		if (err == nil) != c.ok {
			t.Errorf("%s: address: err %v, want ok %v", c.name, err, c.ok)
		}
	}
	// The same policy without Shared ignores zones (an organization sensor).
	p := &ScanTargetPolicy{AllowPrivate: true, LookupIP: resolvesTo("10.1.2.3")}
	if _, err := p.Validate(context.Background(), "app.example.com"); err != nil {
		t.Fatalf("organization sensor: %v", err)
	}
}

// A range target lies wholly inside the job's zone or outside every
// non-public range.
func TestSharedScanTargetPolicyRanges(t *testing.T) {
	p := &ScanTargetPolicy{Shared: true, AllowPrivate: true}
	for target, ok := range map[string]bool{
		"198.51.100.0/24": true,
		"10.1.2.0/24":     true,
		"10.0.0.0/8":      false, // wider than the zone
		"10.2.0.0/16":     false,
		"0.0.0.0/0":       false,
	} {
		_, err := p.Validate(zoneCtx("10.1.0.0/16"), target)
		if (err == nil) != ok {
			t.Errorf("%s: err %v, want ok %v", target, err, ok)
		}
	}
}

// A zone never names more than private space: public, metadata, loopback
// and malformed entries are dropped.
func TestParseZoneRanges(t *testing.T) {
	got := ParseZoneRanges([]string{"10.0.0.0/8", " 192.168.1.5 ", "203.0.113.0/24", "169.254.0.0/16", "127.0.0.0/8",
		"0.0.0.0/0", "8.0.0.0/7", "fc00::/7", "::ffff:10.1.0.0/112", "nonsense", ""})
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.5/32"),
		netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("10.1.0.0/16")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if JobZoneFromContext(context.Background()) != nil {
		t.Fatal("a context without a zone has one")
	}
}

type zoneExecutor struct{ zone chan []netip.Prefix }

func (e *zoneExecutor) Execute(ctx context.Context, _ *Command) (*CommandExecutionResult, error) {
	e.zone <- JobZoneFromContext(ctx)
	return &CommandExecutionResult{}, nil
}

// The poller puts a command's zone ranges (the private ones only) on the
// context its executor runs with.
func TestCommandPollerCarriesJobZone(t *testing.T) {
	cc := &countingCommandClient{cmds: make(chan *Command, 1)}
	ex := &zoneExecutor{zone: make(chan []netip.Prefix, 1)}
	p := NewCommandPoller(cc, ex, &CommandPollerConfig{PollInterval: 10 * time.Millisecond})
	cc.cmds <- &Command{ID: "z1", Type: "scan", ZoneRanges: []string{"10.20.0.0/16", "203.0.113.0/24"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case z := <-ex.zone:
		if len(z) != 1 || z[0] != netip.MustParsePrefix("10.20.0.0/16") {
			t.Fatalf("zone %v", z)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command did not run")
	}
}
