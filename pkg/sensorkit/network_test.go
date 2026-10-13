package sensorkit

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/netctx"
)

func lastManifestNetwork(t *testing.T, f *conformance.FakePlatform) map[string]any {
	t.Helper()
	ms := f.Manifests()
	if len(ms) == 0 {
		return nil
	}
	var m struct {
		Network map[string]any `json:"network"`
	}
	if err := json.Unmarshal(ms[len(ms)-1], &m); err != nil {
		t.Fatal(err)
	}
	return m.Network
}

// A platform that reads network reports gets one in the manifest: the
// declaration, the egress address its echo saw, nothing outside the local
// policy. A platform that does not list the feature gets none.
func TestKit_NetworkReportInManifest(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetManifest(true)
	f.SetNetwork(true)
	t.Cleanup(f.Close)

	dir := t.TempDir()
	policy := filepath.Join(dir, "sensor-policy.yaml")
	if err := os.WriteFile(policy, []byte("apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [203.0.113.0/24]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, _, _ := baseOptions(t, f)
	t.Setenv(core.EnvLocalPolicy, policy)
	t.Setenv(netctx.EnvSite, "hn-dc1")
	t.Setenv(netctx.EnvReach, "10.2.0.0/16,203.0.113.0/25")
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "trivy", installed: true})
	stop := runKit(t, k)
	waitFor(t, "a manifest with a network report", func() bool { return lastManifestNetwork(t, f) != nil })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	n := lastManifestNetwork(t, f)
	raw, _ := json.Marshal(n)
	if n["mode"] != "summary" || n["egress_address"] != "127.0.0.1" || !strings.HasPrefix(n["fingerprint"].(string), "sha256:") {
		t.Fatalf("network = %s", raw)
	}
	decl, _ := n["declared"].(map[string]any)
	if decl["site"] != "hn-dc1" {
		t.Fatalf("declared = %s", raw)
	}
	// The policy allows 203.0.113.0/24 only: the private reach is not
	// named, and neither is any private on-link prefix of the test host.
	if strings.Contains(string(raw), "10.2.0.0") || !strings.Contains(string(raw), "203.0.113.0/25") {
		t.Fatalf("network report goes beyond the local policy: %s", raw)
	}
	if det, ok := n["detected"].(map[string]any); ok {
		links, _ := det["on_link"].([]any)
		for _, p := range links {
			if !netip.MustParsePrefix("203.0.113.0/24").Overlaps(netip.MustParsePrefix(p.(string))) {
				t.Fatalf("on-link %v outside the local policy", p)
			}
		}
	}
	ids := map[string]bool{}
	for _, c := range k.ConfigReport().Checks {
		ids[c.ID] = true
	}
	for _, id := range []string{CheckNetworkEgress, CheckNetworkDNSView, CheckNetworkDeclared} {
		if !ids[id] {
			t.Errorf("check %s not reported", id)
		}
	}
}

func TestKit_NetworkReportNotSentWithoutFeature(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetManifest(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "trivy", installed: true})
	stop := runKit(t, k)
	waitFor(t, "a manifest", func() bool { return len(f.Manifests()) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if n := lastManifestNetwork(t, f); n != nil {
		t.Fatalf("network sent to a platform that does not read it: %v", n)
	}
}

func TestKit_BadNetworkDeclarationStops(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	t.Setenv(netctx.EnvReach, "10.0.0.0/33")
	if _, err := New(opts); err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), netctx.EnvReach) {
		t.Fatalf("bad declaration: %v", err)
	}
}

func TestNetworkChecks(t *testing.T) {
	routed := netctx.Detected{RoutesKnown: true, ResolvConfRead: true,
		Routes:          []netctx.Route{{Prefix: netip.MustParsePrefix("10.20.0.0/16")}},
		Resolvers:       []netip.Addr{netip.MustParseAddr("10.20.0.2")},
		SystemResolvers: []netip.Addr{netip.MustParseAddr("10.20.0.2")}}
	reach := []netip.Prefix{netip.MustParsePrefix("10.20.5.0/24"), netip.MustParsePrefix("10.9.0.0/16")}

	cases := []struct {
		name   string
		check  core.ConfigCheck
		status string
		code   string
	}{
		{"egress direct", networkEgressCheck(netctx.State{Egress: netctx.Egress{Internet: netctx.InternetDirect, Reason: netctx.ReasonEchoPublic}}), core.CheckPass, "direct"},
		{"egress none", networkEgressCheck(netctx.State{Egress: netctx.Egress{Internet: netctx.InternetNone, Reason: netctx.ReasonNoDefaultRoute}}), core.CheckPass, "none"},
		{"egress failed", networkEgressCheck(netctx.State{Egress: netctx.Egress{Internet: netctx.InternetUnknown, Reason: netctx.ReasonEchoFailed}}), core.CheckWarn, "unknown"},
		{"egress private platform", networkEgressCheck(netctx.State{Egress: netctx.Egress{Internet: netctx.InternetUnknown, Reason: netctx.ReasonEchoPrivate}}), core.CheckWarn, "unknown"},
		{"egress unsupported", networkEgressCheck(netctx.State{Egress: netctx.Egress{Internet: netctx.InternetUnknown, Reason: netctx.ReasonEchoUnsupported}}), core.CheckSkip, "unsupported"},
		{"dns consistent", networkDNSCheck(netctx.State{Detected: routed}, "linux"), core.CheckPass, "consistent"},
		{"dns split", networkDNSCheck(netctx.State{Detected: netctx.Detected{ResolvConfRead: true, ResolversFromEnv: true,
			Resolvers: []netip.Addr{netip.MustParseAddr("10.9.9.9")}, SystemResolvers: routed.Resolvers}}, "linux"), core.CheckWarn, "split_view"},
		{"dns unreadable", networkDNSCheck(netctx.State{}, "linux"), core.CheckWarn, "resolv_conf_unreadable"},
		{"dns none", networkDNSCheck(netctx.State{Detected: netctx.Detected{ResolvConfRead: true}}, "linux"), core.CheckWarn, "no_resolvers"},
		{"dns other os", networkDNSCheck(netctx.State{}, "windows"), core.CheckSkip, "unknown"},
		{"declared nothing", networkDeclaredCheck(netctx.State{Detected: routed}), core.CheckSkip, "nothing_declared"},
		{"declared unrouted", networkDeclaredCheck(netctx.State{Declared: netctx.Declared{Reach: reach}, Detected: routed}), core.CheckWarn, "unrouted"},
		{"declared routed", networkDeclaredCheck(netctx.State{Declared: netctx.Declared{Reach: reach[:1]}, Detected: routed}), core.CheckPass, "routed"},
		{"declared routes unknown", networkDeclaredCheck(netctx.State{Declared: netctx.Declared{Reach: reach}}), core.CheckSkip, "routes_unknown"},
	}
	for _, c := range cases {
		if c.check.Status != c.status || c.check.Code != c.code {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, c.check.Status, c.check.Code, c.status, c.code)
		}
		// Checks never carry a declared prefix or an address.
		raw, _ := json.Marshal(c.check)
		for _, leak := range []string{"10.9.", "10.20.", "10.9.9.9"} {
			if strings.Contains(string(raw), leak) {
				t.Errorf("%s: check discloses %s: %s", c.name, leak, raw)
			}
		}
	}
}

func TestControlViaProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	if controlViaProxy(httpsec.ProxySetting{Mode: httpsec.ProxyDirect}, "https://platform.example") {
		t.Fatal("direct reported as proxy")
	}
	if !controlViaProxy(httpsec.ProxySetting{Mode: httpsec.ProxyURL}, "https://platform.example") {
		t.Fatal("proxy URL not reported")
	}
}
