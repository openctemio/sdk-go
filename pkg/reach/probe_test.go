package reach

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestProbeNeedsGuard(t *testing.T) {
	if _, err := Probe(context.Background(), nil, []string{"192.0.2.1"}, ProbeOptions{}); !errors.Is(err, ErrNoGuard) {
		t.Fatalf("err = %v", err)
	}
}

func TestProbeOptionsCapped(t *testing.T) {
	o, err := ProbeOptions{Rate: 1000, MaxAddrs: 1 << 20, Timeout: time.Hour}.normalized()
	if err != nil {
		t.Fatal(err)
	}
	if o.Rate != MaxProbeRate || o.MaxAddrs != MaxProbeAddrs || o.Timeout != maxProbeTimeout || len(o.Ports) != len(DefaultProbePorts) || o.Dial == nil {
		t.Errorf("options %+v", o)
	}
	for _, bad := range [][]int{{0}, {70000}, {1, 2, 3, 4, 5, 6, 7, 8, 9}} {
		if _, err := (ProbeOptions{Ports: bad}).normalized(); err == nil {
			t.Errorf("ports %v accepted", bad)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"app.example.com":                     "app.example.com",
		"app.example.com:8443":                "app.example.com",
		"https://user@app.example.com:8443/x": "app.example.com",
		"http://[2001:db8::1]:80/":            "2001:db8::1",
		"[2001:db8::1]":                       "2001:db8::1",
		"2001:db8::1":                         "2001:db8::1",
		"192.0.2.1":                           "192.0.2.1",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRangeRemaining(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.0/24")
	if n := rangeRemaining(p, netip.MustParseAddr("192.0.2.200")); n != 56 {
		t.Errorf("v4 remaining = %d", n)
	}
	p6 := netip.MustParsePrefix("2001:db8::/120")
	if n := rangeRemaining(p6, netip.MustParseAddr("2001:db8::10")); n != 240 {
		t.Errorf("v6 remaining = %d", n)
	}
	if n := rangeRemaining(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParseAddr("10.0.1.0")); n != 1<<24-256 {
		t.Errorf("/8 remaining = %d", n)
	}
	if n := rangeRemaining(netip.MustParsePrefix("2001:db8::/64"), netip.MustParseAddr("2001:db8::1")); n != 1<<30 {
		t.Errorf("/64 remaining = %d", n)
	}
}
