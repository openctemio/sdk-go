package core

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/netctx"
)

type fakeNetworkReporter struct {
	mu sync.Mutex
	r  *netctx.Report
}

func (f *fakeNetworkReporter) Report() *netctx.Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.r
}

func (f *fakeNetworkReporter) set(r *netctx.Report) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.r = r
}

// The network report rides in the manifest: absent until the first
// detection, registered with it, and a changed report (the sensor moved)
// re-registers the manifest on the next heartbeat.
func TestBaseSensor_ManifestCarriesNetworkReport(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{}
	s := newManifestSensor(t, p)
	nr := &fakeNetworkReporter{}
	s.SetNetworkReporter(nr)

	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if puts, _ := p.counts(); puts != 1 || p.puts[0].Network != nil {
		t.Fatalf("before detection: %d puts, network %+v", puts, p.puts[0].Network)
	}

	nr.set(&netctx.Report{V: 1, Mode: netctx.ModeSummary, Fingerprint: "sha256:a", Internet: netctx.InternetNone})
	s.sendHeartbeat(ctx)
	if puts, _ := p.counts(); puts != 2 || p.puts[1].Network == nil || p.puts[1].Network.Fingerprint != "sha256:a" {
		t.Fatalf("after detection: %d puts", puts)
	}
	s.sendHeartbeat(ctx)
	if puts, _ := p.counts(); puts != 2 {
		t.Fatalf("unchanged report re-registered: %d puts", puts)
	}

	nr.set(&netctx.Report{V: 1, Mode: netctx.ModeSummary, Fingerprint: "sha256:b", Internet: netctx.InternetNone})
	s.sendHeartbeat(ctx)
	if puts, _ := p.counts(); puts != 3 || p.puts[2].Network.Fingerprint != "sha256:b" {
		t.Fatalf("moved: %d puts", puts)
	}

	s.SetNetworkReporter(nil)
	s.sendHeartbeat(ctx)
	if puts, _ := p.counts(); puts != 4 || p.puts[3].Network != nil {
		t.Fatalf("reporter removed: %d puts", puts)
	}
}

func TestLocalPolicy_NetworkScope(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	priv := env(map[string]string{EnvSensorAllowPrivateTargets: "1"})
	lp, err := ParseLocalPolicy([]byte("apiVersion: "+LocalPolicyAPIVersion+`
targets:
  allow_private: true
  allow: ["10.20.0.0/16", "198.51.100.0/24", "2001:db8::/32", "corp.example"]
  deny: ["10.20.9.0/24"]
`), LocalPolicyOptions{LookupEnv: priv})
	if err != nil {
		t.Fatal(err)
	}
	s := lp.NetworkScope()
	if !s.Set || s.NoPrivate || fmt.Sprint(s.Allow) != "[10.20.0.0/16 198.51.100.0/24 2001:db8::/32]" || fmt.Sprint(s.Deny) != "[10.20.9.0/24]" {
		t.Fatalf("scope = %+v", s)
	}

	// Private targets off: no private prefix may be named.
	lp, err = ParseLocalPolicy([]byte("apiVersion: "+LocalPolicyAPIVersion+"\ntargets:\n  allow: [\"198.51.100.0/24\"]\n"),
		LocalPolicyOptions{LookupEnv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if s = lp.NetworkScope(); !s.NoPrivate || !s.Set {
		t.Fatalf("scope = %+v", s)
	}

	// Required and absent: nothing at all.
	s = (*LocalPolicy)(nil).WithRequired(true).NetworkScope()
	if !s.Set || len(s.Allow) != 0 {
		t.Fatalf("fail-closed scope = %+v", s)
	}
	// Legacy install without a policy: no allow list.
	if s = (*LocalPolicy)(nil).NetworkScope(); s.Set {
		t.Fatalf("absent scope = %+v", s)
	}

	// The report built under the policy names nothing outside it.
	r := netctx.BuildReport(netctx.Declared{Mode: netctx.ModeFull, Reach: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}},
		netctx.Detected{OnLink: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24"), netip.MustParsePrefix("192.0.2.0/24")}},
		netctx.Egress{}, lp.NetworkScope())
	if r.Declared != nil || len(r.Detected.OnLink) != 0 || r.Trimmed != 3 {
		t.Fatalf("report = %+v %+v trimmed %d", r.Declared, r.Detected, r.Trimmed)
	}
}
