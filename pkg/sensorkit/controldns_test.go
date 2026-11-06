package sensorkit

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/netctx"
)

// finalized runs a check through the report's schema filter, as the
// platform receives it.
func finalized(t *testing.T, c core.ConfigCheck) core.ConfigCheck {
	t.Helper()
	r := &core.ConfigReport{Checks: []core.ConfigCheck{c}}
	r.Finalize(nil, 0)
	if len(r.Checks) != 1 {
		t.Fatalf("check %+v dropped by the report schema", c)
	}
	return r.Checks[0]
}

func TestControlDNSCheck(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	const api = "https://platform.example.com"
	st := func(s httpsec.LastGoodStatus) []httpsec.LastGoodStatus {
		s.Host = "platform.example.com:443"
		return []httpsec.LastGoodStatus{s}
	}
	for _, tc := range []struct {
		name     string
		url      string
		proxy    bool
		sts      []httpsec.LastGoodStatus
		ok       bool
		status   string
		code     string
		severity string
		params   []string
	}{
		{name: "before the first lookup", url: api, sts: st(httpsec.LastGoodStatus{}), ok: false},
		{name: "resolving", url: api, sts: st(httpsec.LastGoodStatus{State: httpsec.LastGoodResolving}), ok: true,
			status: core.CheckPass, code: "resolving", params: []string{"host"}},
		{name: "cached", url: api, sts: st(httpsec.LastGoodStatus{State: httpsec.LastGoodCached, Since: t0, ResolvedAt: t0.Add(-time.Hour),
			Cause: "server_misbehaving"}), ok: true, status: core.CheckWarn, code: "cached_address", severity: core.SeverityWarning,
			params: []string{"cause", "host", "resolved_at", "since"}},
		{name: "failed", url: api, sts: st(httpsec.LastGoodStatus{State: httpsec.LastGoodFailed, Since: t0, Cause: "timeout"}), ok: true,
			status: core.CheckWarn, code: "lookup_failed", severity: core.SeverityWarning, params: []string{"cause", "host", "since"}},
		{name: "recovered is information only", url: api, sts: st(httpsec.LastGoodStatus{State: httpsec.LastGoodResolving, FailedAt: t0,
			RecoveredAt: t0.Add(time.Hour)}), ok: true, status: core.CheckWarn, code: "recovered", severity: core.SeverityInfo,
			params: []string{"failed_at", "host", "recovered_at"}},
		{name: "proxy resolves", url: api, proxy: true, ok: true, status: core.CheckSkip, code: "via_proxy"},
		{name: "plain http", url: "http://platform.example.com", ok: true, status: core.CheckSkip, code: "plain_http"},
		{name: "address literal", url: "https://192.0.2.10", ok: true, status: core.CheckPass, code: "address_literal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := controlDNSCheck(tc.url, tc.proxy, tc.sts)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			c = finalized(t, c)
			if c.Status != tc.status || c.Code != tc.code {
				t.Fatalf("got %s/%s, want %s/%s", c.Status, c.Code, tc.status, tc.code)
			}
			if tc.severity != "" && c.Severity != tc.severity {
				t.Fatalf("severity %s, want %s", c.Severity, tc.severity)
			}
			if len(c.Params) != len(tc.params) {
				t.Fatalf("params %v, want %v", c.Params, tc.params)
			}
			for _, p := range tc.params {
				if _, ok := c.Params[p]; !ok {
					t.Fatalf("param %s missing (kept by the schema: %v)", p, c.Params)
				}
			}
		})
	}
	// The rollup: a recovered outage does not lower the health; a cached
	// address does (attention).
	rec, _ := controlDNSCheck(api, false, st(httpsec.LastGoodStatus{State: httpsec.LastGoodResolving, FailedAt: t0, RecoveredAt: t0}))
	if h := core.ConfigHealthOf([]core.ConfigCheck{finalized(t, rec)}); h != core.ConfigHealthOK {
		t.Fatalf("recovered: health %s", h)
	}
	cached, _ := controlDNSCheck(api, false, st(httpsec.LastGoodStatus{State: httpsec.LastGoodCached, Since: t0, ResolvedAt: t0, Cause: "timeout"}))
	if h := core.ConfigHealthOf([]core.ConfigCheck{finalized(t, cached)}); h != core.ConfigHealthAttention {
		t.Fatalf("cached: health %s", h)
	}
}

func TestCoreAddressesCheck(t *testing.T) {
	a := netip.MustParseAddr
	st := &netctx.State{
		Detected: netctx.Detected{
			SystemResolvers:   []netip.Addr{a("127.0.0.11")},
			UpstreamResolvers: []netip.Addr{a("10.0.0.53")},
			Resolvers:         []netip.Addr{a("10.0.1.53")},
			ResolversFromEnv:  true,
			Gateways:          []netip.Addr{a("10.0.0.1")},
		},
		Egress: netctx.Egress{Address: a("10.0.5.20")},
	}
	platform := []httpsec.LastGoodStatus{{Host: "platform.example.com:443", Addrs: []netip.Addr{a("10.0.0.10")}}}
	c := finalized(t, coreAddressesCheck(netctx.ModeSummary, st, netctx.Scope{}, platform))
	want := map[string]string{"resolvers": "10.0.0.53", "tool_resolvers": "10.0.1.53", "gateways": "10.0.0.1",
		"host_addrs": "10.0.5.20", "platform_addrs": "10.0.0.10"}
	if c.Status != core.CheckPass || c.Code != "listed" || len(c.Params) != len(want) {
		t.Fatalf("check %+v", c)
	}
	for k, v := range want {
		if p := c.Params[k]; len(p.Names) != 1 || p.Names[0] != v {
			t.Fatalf("%s = %v, want [%s]", k, p.Names, v)
		}
	}

	// Without the Docker comment the system resolvers are named; loopback
	// never is.
	st2 := *st
	st2.Detected.UpstreamResolvers = nil
	c = finalized(t, coreAddressesCheck(netctx.ModeSummary, &st2, netctx.Scope{}, nil))
	if _, ok := c.Params["resolvers"]; ok {
		t.Fatalf("loopback resolver named: %v", c.Params)
	}

	// The local policy's scope bounds what is named.
	scoped := netctx.Scope{Set: true, Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	c = finalized(t, coreAddressesCheck(netctx.ModeSummary, st, scoped, platform))
	if _, ok := c.Params["host_addrs"]; ok {
		t.Fatalf("an address outside the local policy was named: %v", c.Params)
	}
	if _, ok := c.Params["tool_resolvers"]; ok {
		t.Fatalf("an address outside the local policy was named: %v", c.Params)
	}

	// The host owner turned the network report off: nothing is named.
	c = finalized(t, coreAddressesCheck(netctx.ModeOff, st, netctx.Scope{}, platform))
	if c.Status != core.CheckSkip || len(c.Params) != 0 {
		t.Fatalf("report off: %+v", c)
	}
	c = finalized(t, coreAddressesCheck(netctx.ModeSummary, nil, netctx.Scope{}, nil))
	if c.Status != core.CheckSkip || c.Code != "none_known" {
		t.Fatalf("nothing known: %+v", c)
	}
}

func TestApplyControlDNS_RefusesBadDuration(t *testing.T) {
	t.Setenv(EnvControlDNSMaxStale, "a day")
	k := &Kit{errw: io.Discard}
	if err := k.applyControlDNS(); err == nil {
		t.Fatal("an invalid duration must stop the sensor")
	}
}
