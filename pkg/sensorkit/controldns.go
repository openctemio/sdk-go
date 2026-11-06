package sensorkit

// The control channel's DNS fallback (httpsec.LastGood) as the sensor sees
// it: the maximum age of a last-known-good platform address
// (SENSOR_CONTROL_DNS_MAX_STALE), the state file that keeps it across a
// restart, one log line per change, and two config checks:
//
//   - runtime.control_dns: whether the platform host resolves, or the
//     sensor dials a cached address since when, or it cannot reach the
//     platform for a lookup failure (and, once back, when that outage was);
//   - network.core_addresses: the addresses a scan of this sensor should
//     leave alone (its resolvers, gateways, its own address as the platform
//     sees it, the platform's addresses), for the platform's scan warning.
//
// Security: the fallback never changes what TLS verifies (see
// httpsec.LastGood). The address check names only addresses the local
// policy lets this sensor scan (the network report's rule), and nothing
// when the host owner turned the network report off.

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/netctx"
)

// EnvControlDNSMaxStale bounds how old a last-known-good platform address
// may be and still be dialed when the platform host does not resolve; 0
// turns the fallback off.
const EnvControlDNSMaxStale = "SENSOR_CONTROL_DNS_MAX_STALE"

// Check ids.
const (
	CheckControlDNS    = "runtime.control_dns"
	CheckCoreAddresses = "network.core_addresses"
)

// controlDNSStateFile keeps the platform's last-known-good addresses in the
// state directory.
const controlDNSStateFile = "platform-addrs.json"

// applyControlDNS configures the API clients' last-known-good addresses.
func (k *Kit) applyControlDNS() error {
	maxAge := httpsec.DefaultLastGoodMaxAge
	if v := strings.TrimSpace(os.Getenv(EnvControlDNSMaxStale)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return usageError(fmt.Errorf("%s must be a duration such as 24h (0 turns the fallback off)", EnvControlDNSMaxStale))
		}
		maxAge = d
	}
	lg := httpsec.APILastGood()
	lg.SetMaxAge(maxAge)
	errw := k.errw
	lg.SetLogger(func(format string, args ...any) { _, _ = fmt.Fprintf(errw, "Warning: "+format+"\n", args...) })
	if k.s.stateDir != "" {
		lg.SetStateFile(filepath.Join(k.s.stateDir, controlDNSStateFile))
	}
	lg.OnEvent(k.onControlDNS)
	return nil
}

// onControlDNS logs a change once and refreshes the checks.
func (k *Kit) onControlDNS(ev httpsec.LastGoodEvent) {
	host := hostOnly(ev.Host)
	switch {
	case ev.To == httpsec.LastGoodCached:
		_, _ = fmt.Fprintf(k.errw, "Warning: the platform host %s does not resolve (%v); dialing its last-known-good address %s (looked up %s). TLS still verifies %s.\n",
			host, ev.Err, joinAddrs(ev.Addrs), ev.ResolvedAt.UTC().Format(time.RFC3339), host)
	case ev.To == httpsec.LastGoodFailed:
		_, _ = fmt.Fprintf(k.errw, "Warning: the platform host %s does not resolve (%v) and no address younger than %s is known: the sensor cannot reach the platform until DNS answers. Pin the host (extra_hosts) or fix the resolver.\n",
			host, ev.Err, EnvControlDNSMaxStale)
	case ev.To == httpsec.LastGoodResolving && !ev.FailedAt.IsZero():
		_, _ = fmt.Fprintf(k.errw, "The platform host %s resolves again (lookups failed since %s).\n",
			host, ev.FailedAt.UTC().Format(time.RFC3339))
	}
	k.reportControlDNS()
	k.reportCoreAddresses()
}

// reportControlDNS records runtime.control_dns for the platform host.
func (k *Kit) reportControlDNS() {
	if c, ok := controlDNSCheck(k.s.apiURL, k.controlViaProxy, httpsec.APILastGood().Status()); ok {
		k.ReportCheck(c)
	}
}

// controlDNSCheck builds runtime.control_dns; false before the first lookup.
func controlDNSCheck(apiURL string, viaProxy bool, sts []httpsec.LastGoodStatus) (core.ConfigCheck, bool) {
	c := core.ConfigCheck{ID: CheckControlDNS, Keys: []string{EnvControlDNSMaxStale}}
	if viaProxy {
		c.Status, c.Code, c.Keys = core.CheckSkip, "via_proxy", nil
		c.Summary = "platform requests go through a proxy, which resolves the platform host"
		return c, true
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Hostname() == "" {
		return c, false
	}
	if !strings.EqualFold(u.Scheme, "https") {
		c.Status, c.Code, c.Keys = core.CheckSkip, "plain_http", nil
		return c, true
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		c.Status, c.Code, c.Keys = core.CheckPass, "address_literal", nil
		return c, true
	}
	var st *httpsec.LastGoodStatus
	for i := range sts {
		if strings.EqualFold(hostOnly(sts[i].Host), u.Hostname()) {
			st = &sts[i]
			break
		}
	}
	if st == nil || st.State == httpsec.LastGoodUnknown {
		return c, false
	}
	c.Params = map[string]core.ConfigParam{"host": core.ParamHost(u.Hostname())}
	unix := func(t time.Time) core.ConfigParam { return core.ParamInt(t.Unix()) }
	when := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	switch st.State {
	case httpsec.LastGoodCached:
		c.Status, c.Code = core.CheckWarn, "cached_address"
		c.Params["since"], c.Params["resolved_at"], c.Params["cause"] = unix(st.Since), unix(st.ResolvedAt), core.ParamEnum(st.Cause)
		c.Summary = "the platform host does not resolve (" + st.Cause + ") since " + when(st.Since) +
			"; the sensor dials the address it last resolved, verified by TLS"
	case httpsec.LastGoodFailed:
		c.Status, c.Code = core.CheckWarn, "lookup_failed"
		c.Params["since"], c.Params["cause"] = unix(st.Since), core.ParamEnum(st.Cause)
		c.Summary = "the platform host does not resolve (" + st.Cause + ") since " + when(st.Since) +
			" and no recent address is known: the sensor cannot reach the platform"
	default:
		if st.FailedAt.IsZero() {
			c.Status, c.Code = core.CheckPass, "resolving"
			return c, true
		}
		// Back after an outage: information only (it does not lower the
		// health rollup), so the platform can name the cause of the gap.
		c.Status, c.Severity, c.Code = core.CheckWarn, core.SeverityInfo, "recovered"
		c.Params["failed_at"], c.Params["recovered_at"] = unix(st.FailedAt), unix(st.RecoveredAt)
		c.Summary = "the platform host did not resolve from " + when(st.FailedAt) + " to " + when(st.RecoveredAt)
	}
	return c, true
}

// reportCoreAddresses records network.core_addresses from the latest
// network detection and the platform's addresses.
func (k *Kit) reportCoreAddresses() {
	var st *netctx.State
	if w := k.netWatch.Load(); w != nil {
		if s, ok := w.State(); ok {
			st = &s
		}
	}
	k.reportCoreAddressesFrom(st)
}

// reportCoreAddressesFrom is reportCoreAddresses for a detection (nil:
// none yet).
func (k *Kit) reportCoreAddressesFrom(st *netctx.State) {
	scope := k.LocalPolicy().NetworkScope()
	k.ReportCheck(coreAddressesCheck(k.network.Mode, st, scope, httpsec.APILastGood().Status()))
}

// coreAddressesCheck lists the core infrastructure addresses a scan from
// this sensor should exclude.
func coreAddressesCheck(mode netctx.Mode, st *netctx.State, scope netctx.Scope, sts []httpsec.LastGoodStatus) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckCoreAddresses, Status: core.CheckPass, Severity: core.SeverityInfo, Code: "listed"}
	if mode == netctx.ModeOff {
		c.Status, c.Code, c.Keys = core.CheckSkip, "not_reported", []string{netctx.EnvReport}
		return c
	}
	params := map[string]core.ConfigParam{}
	add := func(key string, addrs []netip.Addr) {
		var names []string
		for _, a := range addrs {
			if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || !scope.Names(a) {
				continue
			}
			if s := a.String(); !containsStr(names, s) {
				names = append(names, s)
			}
			if len(names) == core.MaxConfigNames {
				break
			}
		}
		if len(names) > 0 {
			params[key] = core.ParamNames(names...)
		}
	}
	if st != nil {
		d := st.Detected
		// The control channel's resolvers: the ones behind a local stub
		// (Docker's embedded DNS) when known.
		res := d.UpstreamResolvers
		if len(res) == 0 {
			res = d.SystemResolvers
		}
		add("resolvers", res)
		if d.ResolversFromEnv {
			add("tool_resolvers", d.Resolvers)
		}
		add("gateways", d.Gateways)
		add("host_addrs", []netip.Addr{st.Egress.Address})
	}
	var platform []netip.Addr
	for _, s := range sts {
		platform = append(platform, s.Addrs...)
	}
	add("platform_addrs", platform)
	if len(params) == 0 {
		c.Status, c.Code = core.CheckSkip, "none_known"
		return c
	}
	c.Params = params
	return c
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, 0, len(as))
	for _, a := range as {
		s = append(s, a.String())
	}
	return strings.Join(s, ", ")
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
