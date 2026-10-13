package netctx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestParseDeclared(t *testing.T) {
	d, err := ParseDeclared(env(map[string]string{
		EnvSite:        "hn-dc1",
		EnvReach:       "10.2.0.0/16, 10.2.3.4 ,192.168.7.9/24,2001:db8:1::/48,10.2.0.0/16",
		EnvDNSSuffixes: ".Corp.Example., svc.cluster.local,corp.example",
		EnvInternet:    "PROXY",
		EnvReport:      "full",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Site != "hn-dc1" || d.Internet != InternetProxy || d.Mode != ModeFull {
		t.Fatalf("declared = %+v", d)
	}
	want := []netip.Prefix{pfx("10.2.0.0/16"), pfx("10.2.3.4/32"), pfx("192.168.7.0/24"), pfx("2001:db8:1::/48")}
	if fmt.Sprint(d.Reach) != fmt.Sprint(want) {
		t.Fatalf("reach = %v, want %v", d.Reach, want)
	}
	if fmt.Sprint(d.DNSSuffixes) != "[corp.example svc.cluster.local]" {
		t.Fatalf("suffixes = %v", d.DNSSuffixes)
	}

	def, err := ParseDeclared(env(nil))
	if err != nil || def.Internet != InternetAuto || def.Mode != ModeSummary || def.Site != "" || def.Reach != nil {
		t.Fatalf("defaults = %+v, %v", def, err)
	}
}

func TestParseDeclaredRefusesBadValues(t *testing.T) {
	many := make([]string, MaxReach+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	cases := map[string]map[string]string{
		"bad cidr":       {EnvReach: "10.0.0.0/33"},
		"not an address": {EnvReach: "example.com"},
		"too wide v4":    {EnvReach: "10.0.0.0/7"},
		"too wide v6":    {EnvReach: "2001:db8::/31"},
		"default route":  {EnvReach: "0.0.0.0/0"},
		"loopback":       {EnvReach: "127.0.0.0/8"},
		"link-local v6":  {EnvReach: "fe80::/64"},
		"zone":           {EnvReach: "fe80::1%eth0"},
		"too many":       {EnvReach: strings.Join(many, ",")},
		"site chars":     {EnvSite: "hn dc/1"},
		"site long":      {EnvSite: strings.Repeat("a", MaxSiteLen+1)},
		"suffix":         {EnvDNSSuffixes: "corp..example"},
		"suffix label":   {EnvDNSSuffixes: "-corp.example"},
		"internet":       {EnvInternet: "maybe"},
		"report":         {EnvReport: "verbose"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDeclared(env(m))
			if !errors.Is(err, ErrInvalidDeclaration) {
				t.Fatalf("err = %v, want ErrInvalidDeclaration", err)
			}
			for k, v := range m {
				if !strings.Contains(err.Error(), k) {
					t.Fatalf("error %q does not name %s", err, k)
				}
				if len(v) > 3 && strings.Contains(err.Error(), v) {
					t.Fatalf("error %q echoes the value", err)
				}
			}
		})
	}
}

const routeV4 = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100140A	0003	0	0	100	00000000	0	0	0
eth0	0000140A	00000000	0001	0	0	100	0000FFFF	0	0	0
tun0	0000020A	00000000	0001	0	0	0	0000FFFF	0	0	0
eth0	0000000B	00000000	0201	0	0	0	000000FF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

// A host with IPv6 on eth0 (default via fe80::1) and the kernel's reject
// default on lo.
const routeV6 = `20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`

const noDefaultV6 = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`

const resolvConf = `# generated
nameserver 10.20.0.2
nameserver fe80::1%eth0
nameserver 10.20.0.2
search Corp.Example. lab.corp.example ; comment
options ndots:2
`

func ifaces() []Iface {
	up := net.FlagUp | net.FlagBroadcast
	return []Iface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addrs: []netip.Prefix{pfx("127.0.0.1/8"), pfx("::1/128")}},
		{Name: "eth0", Flags: up, Addrs: []netip.Prefix{pfx("10.20.1.5/16"), pfx("2001:db8:1::5/64"), pfx("fe80::5/64")}},
		{Name: "eth1", Flags: up, Addrs: []netip.Prefix{pfx("203.0.113.10/24")}},
		{Name: "tun0", Flags: up, Addrs: []netip.Prefix{pfx("10.2.0.7/16")}},
		{Name: "ens5", Flags: up, Addrs: []netip.Prefix{pfx("fd12:3456:789a::5/64"), pfx("100.64.1.2/10")}},
		{Name: "docker0", Flags: up, Addrs: []netip.Prefix{pfx("172.17.0.1/16")}},
		{Name: "br-1a2b", Flags: up, Addrs: []netip.Prefix{pfx("172.18.0.1/16")}},
		{Name: "veth9", Flags: up, Addrs: []netip.Prefix{pfx("172.19.0.1/16")}},
		{Name: "cni0", Flags: up, Addrs: []netip.Prefix{pfx("10.244.0.1/24")}},
		{Name: "eth2", Flags: net.FlagBroadcast, Addrs: []netip.Prefix{pfx("192.168.50.1/24")}}, // down
	}
}

func sources() Sources {
	return Sources{
		Interfaces: func() ([]Iface, error) { return ifaces(), nil },
		RouteV4:    func() ([]byte, error) { return []byte(routeV4), nil },
		RouteV6:    func() ([]byte, error) { return []byte(routeV6), nil },
		ResolvConf: func() ([]byte, error) { return []byte(resolvConf), nil },
		Lookup:     env(nil),
	}
}

func TestDetect(t *testing.T) {
	d := Detect(sources())
	wantOnLink := "[10.2.0.0/16 10.20.0.0/16 100.64.0.0/10 203.0.113.0/24 2001:db8:1::/64 fd12:3456:789a::/64]"
	if fmt.Sprint(d.OnLink) != wantOnLink {
		t.Fatalf("on-link = %v, want %v", d.OnLink, wantOnLink)
	}
	if !d.RoutesKnown || !d.DefaultV4 || !d.DefaultV6 {
		t.Fatalf("routes known %v v4 %v v6 %v", d.RoutesKnown, d.DefaultV4, d.DefaultV6)
	}
	if fmt.Sprint(d.Gateways) != "[10.20.0.1 fe80::1]" {
		t.Fatalf("gateways = %v", d.Gateways)
	}
	for _, r := range d.Routes {
		if r.Iface == "lo" || r.Prefix == pfx("11.0.0.0/24") {
			t.Fatalf("rejected or loopback route kept: %+v", r)
		}
	}
	if fmt.Sprint(d.SystemResolvers) != "[10.20.0.2 fe80::1]" || fmt.Sprint(d.Resolvers) != fmt.Sprint(d.SystemResolvers) || d.ResolversFromEnv {
		t.Fatalf("resolvers = %v / %v", d.SystemResolvers, d.Resolvers)
	}
	if fmt.Sprint(d.SearchDomains) != "[corp.example lab.corp.example]" {
		t.Fatalf("search = %v", d.SearchDomains)
	}
	if !d.Routed(pfx("10.2.5.0/24")) || !d.Routed(pfx("198.51.100.0/24")) || !d.Routed(pfx("2001:db8:9::/48")) {
		t.Fatal("covered prefixes reported unrouted")
	}
}

func TestDetectResolversFromEnv(t *testing.T) {
	src := sources()
	src.Lookup = env(map[string]string{EnvDNSResolvers: "10.9.9.9, [2001:db8::53]:53,10.9.9.10:5353,bogus"})
	d := Detect(src)
	if !d.ResolversFromEnv || fmt.Sprint(d.Resolvers) != "[10.9.9.9 2001:db8::53 10.9.9.10]" {
		t.Fatalf("resolvers = %v (env %v)", d.Resolvers, d.ResolversFromEnv)
	}
}

func TestDetectUnknownSources(t *testing.T) {
	d := Detect(Sources{
		Interfaces: func() ([]Iface, error) { return nil, errors.New("no") },
		RouteV4:    func() ([]byte, error) { return []byte("garbage"), nil },
		ResolvConf: func() ([]byte, error) { return nil, errors.New("no") },
	})
	if d.RoutesKnown || d.OnLink != nil || d.ResolvConfRead || len(d.Resolvers) != 0 {
		t.Fatalf("detected = %+v", d)
	}
	if !d.Routed(pfx("10.0.0.0/8")) {
		t.Fatal("unknown routes must not warn")
	}
}

func TestDetectNoDefaultRoute(t *testing.T) {
	src := sources()
	src.RouteV4 = func() ([]byte, error) {
		return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
			"eth0\t0000140A\t00000000\t0001\t0\t0\t0\t0000FFFF\n"), nil
	}
	src.RouteV6 = func() ([]byte, error) { return []byte(noDefaultV6), nil }
	d := Detect(src)
	if !d.RoutesKnown || d.DefaultV4 || d.DefaultV6 {
		t.Fatalf("known %v v4 %v v6 %v", d.RoutesKnown, d.DefaultV4, d.DefaultV6)
	}
	if d.Routed(pfx("10.9.0.0/16")) || !d.Routed(pfx("10.20.3.0/24")) {
		t.Fatal("route coverage wrong")
	}
}

func TestDetectBoundsResolvConf(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "nameserver 10.0.0.%d\n", i+1)
	}
	b.WriteString("search")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, " d%d.example", i)
	}
	servers, search := parseResolvConf([]byte(b.String()))
	if len(servers) != MaxResolvers || len(search) != MaxSearchDomains {
		t.Fatalf("servers %d search %d", len(servers), len(search))
	}
}

func TestFingerprint(t *testing.T) {
	d := Declared{Site: "hn"}
	det := Detect(sources())
	fp := Fingerprint(d, det)
	if !strings.HasPrefix(fp, "sha256:") || len(fp) != 71 {
		t.Fatalf("fingerprint %q", fp)
	}
	// Stable across order and public or egress changes.
	det2 := det
	det2.OnLink = append([]netip.Prefix{pfx("198.51.100.0/24")}, det.OnLink...)
	det2.Resolvers = []netip.Addr{det.Resolvers[1], det.Resolvers[0]}
	if Fingerprint(d, det2) != fp {
		t.Fatal("fingerprint depends on order or public prefixes")
	}
	moved := det
	moved.OnLink = []netip.Prefix{pfx("10.99.0.0/16")}
	for name, f := range map[string]string{
		"moved":    Fingerprint(d, moved),
		"site":     Fingerprint(Declared{Site: "hcm"}, det),
		"gateway":  Fingerprint(d, Detected{OnLink: det.OnLink, Gateways: []netip.Addr{netip.MustParseAddr("10.20.0.254")}, Resolvers: det.Resolvers, SearchDomains: det.SearchDomains}),
		"resolver": Fingerprint(d, Detected{OnLink: det.OnLink, Gateways: det.Gateways, SearchDomains: det.SearchDomains}),
		"search":   Fingerprint(d, Detected{OnLink: det.OnLink, Gateways: det.Gateways, Resolvers: det.Resolvers}),
	} {
		if f == fp {
			t.Fatalf("%s: fingerprint did not change", name)
		}
	}
}

func echoOK(addr string, proxy bool) Echo {
	return func(context.Context) (EchoResult, error) {
		return EchoResult{Address: netip.MustParseAddr(addr), ViaProxy: proxy}, nil
	}
}

func echoErr(err error) Echo {
	return func(context.Context) (EchoResult, error) { return EchoResult{}, err }
}

func TestResolveEgress(t *testing.T) {
	ctx := context.Background()
	det := Detect(sources())
	noRoute := det
	noRoute.DefaultV4, noRoute.DefaultV6 = false, false
	unknownRoutes := Detected{}
	cases := []struct {
		name   string
		decl   Internet
		det    Detected
		echo   Echo
		want   Internet
		reason string
	}{
		{"public direct", InternetAuto, det, echoOK("198.51.100.7", false), InternetDirect, ReasonEchoPublic},
		{"public v6", InternetAuto, det, echoOK("2001:db8:ffff::7", false), InternetDirect, ReasonEchoPublic},
		{"public via proxy", InternetAuto, det, echoOK("198.51.100.7", true), InternetProxy, ReasonEchoPublic},
		{"private platform", InternetAuto, det, echoOK("10.20.1.5", false), InternetUnknown, ReasonEchoPrivate},
		{"cgnat is private", InternetAuto, det, echoOK("100.64.3.3", false), InternetUnknown, ReasonEchoPrivate},
		{"echo blocked is unknown, never none", InternetAuto, det, echoErr(errors.New("timeout")), InternetUnknown, ReasonEchoFailed},
		{"echo unsupported", InternetAuto, det, echoErr(fmt.Errorf("x: %w", ErrEchoUnsupported)), InternetUnknown, ReasonEchoUnsupported},
		{"no echo", InternetAuto, det, nil, InternetUnknown, ReasonNoEcho},
		{"no default route", InternetAuto, noRoute, echoErr(errors.New("x")), InternetNone, ReasonNoDefaultRoute},
		{"no default route but a proxy carried the echo", InternetAuto, noRoute, echoOK("10.20.0.9", true), InternetUnknown, ReasonEchoPrivate},
		{"unknown routes are not none", InternetAuto, unknownRoutes, nil, InternetUnknown, ReasonNoEcho},
		{"declared none wins", InternetNone, det, echoOK("198.51.100.7", false), InternetNone, ReasonDeclared},
		{"declared direct wins", InternetDirect, noRoute, nil, InternetDirect, ReasonDeclared},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eg := ResolveEgress(ctx, Declared{Internet: c.decl}, c.det, c.echo, 0)
			if eg.Internet != c.want || eg.Reason != c.reason {
				t.Fatalf("egress = %+v, want %s/%s", eg, c.want, c.reason)
			}
		})
	}
	// An echo that ignores its deadline is still bounded by the context.
	slow := func(ctx context.Context) (EchoResult, error) { <-ctx.Done(); return EchoResult{}, ctx.Err() }
	if eg := ResolveEgress(ctx, Declared{}, det, slow, 1); eg.Internet != InternetUnknown {
		t.Fatalf("slow echo = %+v", eg)
	}
}

func TestBuildReportSummary(t *testing.T) {
	d := Declared{Site: "hn", Reach: []netip.Prefix{pfx("10.2.0.0/16")}, DNSSuffixes: []string{"corp.example"}, Mode: ModeSummary}
	det := Detect(sources())
	eg := ResolveEgress(context.Background(), d, det, echoOK("198.51.100.7", false), 0)
	r := BuildReport(d, det, eg, Scope{})
	if r.V != ReportVersion || r.Mode != ModeSummary || r.Internet != InternetDirect || r.EgressAddress != "198.51.100.7" {
		t.Fatalf("report = %+v", r)
	}
	if got := fmt.Sprint(r.Detected.OnLink); got != "[10.2.0.0/16 10.20.0.0/16 100.64.0.0/10 fd12:3456:789a::/64]" {
		t.Fatalf("summary lists %v", got)
	}
	if r.Detected.PublicOnLink != 2 || r.Detected.Routes != "known" || !r.Detected.DefaultV6 {
		t.Fatalf("detected = %+v", r.Detected)
	}
	if r.Declared.Site != "hn" || fmt.Sprint(r.Declared.Reach) != "[10.2.0.0/16]" {
		t.Fatalf("declared = %+v", r.Declared)
	}
	raw, _ := json.Marshal(r)
	for _, leak := range []string{"203.0.113", "2001:db8:1::", "172.17", "10.244", "fe80::5", "10.20.0.1"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("summary report discloses %s: %s", leak, raw)
		}
	}
	// Deterministic.
	raw2, _ := json.Marshal(BuildReport(d, Detect(sources()), eg, Scope{}))
	if string(raw) != string(raw2) {
		t.Fatal("report is not deterministic")
	}
}

func TestBuildReportFullListsPublic(t *testing.T) {
	r := BuildReport(Declared{Mode: ModeFull}, Detect(sources()), Egress{Internet: InternetDirect}, Scope{})
	if r.Detected.PublicOnLink != 0 || !strings.Contains(fmt.Sprint(r.Detected.OnLink), "203.0.113.0/24") ||
		!strings.Contains(fmt.Sprint(r.Detected.OnLink), "2001:db8:1::/64") {
		t.Fatalf("full = %+v", r.Detected)
	}
}

func TestBuildReportOff(t *testing.T) {
	d := Declared{Site: "hn", Reach: []netip.Prefix{pfx("10.2.0.0/16")}, Mode: ModeOff}
	det := Detect(sources())
	eg := Egress{Internet: InternetDirect, Address: netip.MustParseAddr("198.51.100.7")}
	r := BuildReport(d, det, eg, Scope{})
	raw, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if len(m) != 4 || m["mode"] != "off" || m["internet"] != "direct" || m["fingerprint"] != Fingerprint(d, det) {
		t.Fatalf("off report = %s", raw)
	}
}

func TestBuildReportTrimsToLocalPolicy(t *testing.T) {
	d := Declared{Reach: []netip.Prefix{pfx("10.2.0.0/16"), pfx("10.3.0.0/16"), pfx("192.168.0.0/16")}}
	det := Detect(sources())
	scope := Scope{Set: true, Allow: []netip.Prefix{pfx("10.2.0.0/16"), pfx("10.20.5.0/24"), pfx("192.168.10.0/24"), pfx("fd12:3456:789a::/48")}}
	r := BuildReport(d, det, Egress{Internet: InternetUnknown}, scope)
	if got := fmt.Sprint(r.Declared.Reach); got != "[10.2.0.0/16 192.168.10.0/24]" {
		t.Fatalf("reach = %v", got)
	}
	// On-link: 10.2/16 kept, 10.20/16 narrowed to the allowed /24, CGNAT
	// dropped, the ULA /64 kept (inside the allowed /48).
	if got := fmt.Sprint(r.Detected.OnLink); got != "[10.2.0.0/16 10.20.5.0/24 fd12:3456:789a::/64]" {
		t.Fatalf("on-link = %v", got)
	}
	// Reach: 10.3 dropped, 192.168/16 narrowed. On-link: 10.20 narrowed,
	// CGNAT dropped. Resolvers: both outside the policy.
	if r.Detected.Resolvers != nil {
		t.Fatalf("resolvers outside the policy named: %v", r.Detected.Resolvers)
	}
	if r.Trimmed != 6 {
		t.Fatalf("trimmed = %d", r.Trimmed)
	}
	// Every listed prefix is inside the policy.
	for _, s := range append(append([]string{}, r.Declared.Reach...), r.Detected.OnLink...) {
		p := pfx(s)
		inside := false
		for _, a := range scope.Allow {
			if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
				inside = true
			}
		}
		if !inside {
			t.Fatalf("%s is outside the local policy", s)
		}
	}
	// An empty allow list reports no prefix at all.
	r = BuildReport(d, det, Egress{}, Scope{Set: true})
	if r.Declared != nil && len(r.Declared.Reach) != 0 || len(r.Detected.OnLink) != 0 {
		t.Fatalf("empty scope reported %+v %+v", r.Declared, r.Detected)
	}
	if r.Internet != InternetUnknown {
		t.Fatalf("zero egress reported %q", r.Internet)
	}
}

func TestBuildReportDropsDeniedAndPrivate(t *testing.T) {
	d := Declared{Reach: []netip.Prefix{pfx("10.2.0.0/16"), pfx("198.51.100.0/24")}, Mode: ModeFull}
	det := Detect(sources())
	r := BuildReport(d, det, Egress{}, Scope{NoPrivate: true, Deny: []netip.Prefix{pfx("203.0.113.0/24")}})
	raw, _ := json.Marshal(r)
	for _, leak := range []string{"10.2.", "10.20.", "100.64.", "fd12:", "203.0.113."} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("report names %s although the policy refuses it: %s", leak, raw)
		}
	}
	if fmt.Sprint(r.Declared.Reach) != "[198.51.100.0/24]" || fmt.Sprint(r.Detected.OnLink) != "[2001:db8:1::/64]" {
		t.Fatalf("kept reach %v on-link %v", r.Declared.Reach, r.Detected.OnLink)
	}
	// A narrower allowed range inside a wide private on-link prefix is not
	// named when private targets are refused.
	r = BuildReport(Declared{}, det, Egress{}, Scope{Set: true, NoPrivate: true, Allow: []netip.Prefix{pfx("10.20.5.0/24")}})
	if len(r.Detected.OnLink) != 0 {
		t.Fatalf("on-link %v", r.Detected.OnLink)
	}
}

func TestBuildReportBounds(t *testing.T) {
	var many []Iface
	for i := 0; i < 50; i++ {
		many = append(many, Iface{Name: fmt.Sprintf("eth%d", i), Flags: net.FlagUp,
			Addrs: []netip.Prefix{pfx(fmt.Sprintf("10.%d.0.1/16", i))}})
	}
	src := sources()
	src.Interfaces = func() ([]Iface, error) { return many, nil }
	r := BuildReport(Declared{}, Detect(src), Egress{}, Scope{})
	if len(r.Detected.OnLink) != MaxOnLink || r.Trimmed != 50-MaxOnLink {
		t.Fatalf("on-link %d trimmed %d", len(r.Detected.OnLink), r.Trimmed)
	}
}

// Detection makes no network call besides the echo: every source here is
// local, and the echo is called exactly once per refresh.
func TestWatcherDetectsWithoutDialing(t *testing.T) {
	calls := 0
	src := sources()
	w := NewWatcher(Options{Declared: Declared{Mode: ModeSummary}, Sources: &src,
		Echo: func(context.Context) (EchoResult, error) {
			calls++
			return EchoResult{Address: netip.MustParseAddr("198.51.100.7")}, nil
		}})
	if w.Report() != nil {
		t.Fatal("report before refresh")
	}
	st, changed := w.Refresh(context.Background())
	if !changed || calls != 1 || st.Report.Internet != InternetDirect {
		t.Fatalf("first refresh changed %v calls %d %+v", changed, calls, st.Report)
	}
	if _, changed = w.Refresh(context.Background()); changed || calls != 2 {
		t.Fatalf("same facts reported changed (%v) or echo calls %d", changed, calls)
	}
	ifs := ifaces()
	ifs[1].Addrs = []netip.Prefix{pfx("10.30.1.5/16")}
	src.Interfaces = func() ([]Iface, error) { return ifs, nil }
	st2, changed := w.Refresh(context.Background())
	if !changed || st2.Report.Fingerprint == st.Report.Fingerprint {
		t.Fatal("a move was not noticed")
	}
	if got, ok := w.State(); !ok || got.Report != w.Report() {
		t.Fatal("state and report disagree")
	}
}

func TestWatcherScopeAppliesOnRefresh(t *testing.T) {
	src := sources()
	scope := Scope{}
	w := NewWatcher(Options{Sources: &src, Scope: func() Scope { return scope }})
	st, _ := w.Refresh(context.Background())
	if len(st.Report.Detected.OnLink) == 0 {
		t.Fatal("nothing listed")
	}
	scope = Scope{Set: true, Allow: []netip.Prefix{pfx("10.2.0.0/16")}}
	st, changed := w.Refresh(context.Background())
	if !changed || fmt.Sprint(st.Report.Detected.OnLink) != "[10.2.0.0/16]" {
		t.Fatalf("reloaded policy not applied: %v", st.Report.Detected.OnLink)
	}
}

func TestWatcherRescopeWithoutEcho(t *testing.T) {
	src := sources()
	calls := 0
	scope := Scope{}
	w := NewWatcher(Options{Sources: &src, Scope: func() Scope { return scope },
		Echo: func(context.Context) (EchoResult, error) { calls++; return EchoResult{}, errors.New("x") }})
	if _, changed := w.Rescope(); changed {
		t.Fatal("rescope before refresh")
	}
	w.Refresh(context.Background())
	scope = Scope{Set: true}
	st, changed := w.Rescope()
	if !changed || calls != 1 || len(st.Report.Detected.OnLink) != 0 {
		t.Fatalf("rescope changed %v calls %d on-link %v", changed, calls, st.Report.Detected.OnLink)
	}
	if _, changed = w.Rescope(); changed {
		t.Fatal("same scope reported changed")
	}
}

func TestWatcherRunStops(t *testing.T) {
	src := sources()
	w := NewWatcher(Options{Sources: &src})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	n := 0
	go func() { w.Run(ctx, 1, func(State) { n++ }); close(done) }()
	for w.Report() == nil { // Run refreshes on its first tick
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if n != 1 {
		t.Fatalf("onChange called %d times for unchanged facts", n)
	}
}

func TestParseRouteV4Masks(t *testing.T) {
	if _, err := parseRouteV4([]byte("not a table")); err == nil {
		t.Fatal("garbage accepted")
	}
	rs, err := parseRouteV4([]byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t0000140A\t00000000\t0001\t0\t0\t0\t00FF00FF\n" + // non-contiguous mask
		"eth0\tZZ\t00000000\t0001\t0\t0\t0\t0000FFFF\n" +
		"eth0\t0000140A\t00000000\t0000\t0\t0\t0\t0000FFFF\n")) // down
	if err != nil || len(rs) != 0 {
		t.Fatalf("routes %v err %v", rs, err)
	}
}
