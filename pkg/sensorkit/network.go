package sensorkit

// The sensor's network self-description (sdk-go pkg/netctx, api RFC-089,
// docs/rfcs/RFC-089-reachability-aware-routing.md in openctemio/openctem):
// what the host owner declares, what the kit detects, sent in the manifest
// to a platform that reads it, never wider than the local policy.

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/netctx"
)

// Network check ids.
const (
	CheckNetworkEgress   = "network.egress"
	CheckNetworkDNSView  = "network.dns_view"
	CheckNetworkDeclared = "network.declared_vs_detected"
)

// networkFirstRefresh bounds the detection before the first heartbeat.
const networkFirstRefresh = 15 * time.Second

// controlViaProxy reports whether platform requests go through a proxy.
func controlViaProxy(p httpsec.ProxySetting, apiURL string) bool {
	switch p.Mode {
	case httpsec.ProxyURL:
		return true
	case httpsec.ProxyDirect:
		return false
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Host == "" {
		return false
	}
	pu, err := http.ProxyFromEnvironment(&http.Request{URL: u})
	return err == nil && pu != nil
}

// applyNetwork applies and reports the proxies, then reads the host owner's
// network declaration (a value it cannot use stops the sensor, as every
// other setting does) and whether platform requests go through a proxy.
func (k *Kit) applyNetwork(proxies Proxies, proxyOpts ProxyOptions) error {
	proxies.Apply()
	proxies.report(k.out, k.errw, proxyOpts)
	d, err := netctx.ParseDeclared(os.LookupEnv)
	if err != nil {
		return usageError(err)
	}
	k.network, k.controlViaProxy = d, controlViaProxy(proxies.Control, k.s.apiURL)
	return nil
}

// startNetwork detects the network once (bounded), reports it in every
// manifest from now on and re-detects every netctx.DefaultInterval until
// ctx ends.
func (k *Kit) startNetwork(ctx context.Context) {
	if k.client == nil || k.sensor == nil {
		return
	}
	via := k.controlViaProxy
	w := netctx.NewWatcher(netctx.Options{
		Declared: k.network,
		Echo: func(ctx context.Context) (netctx.EchoResult, error) {
			a, err := k.client.EgressEcho(ctx)
			return netctx.EchoResult{Address: a, ViaProxy: via}, err
		},
		Scope: func() netctx.Scope { return k.LocalPolicy().NetworkScope() },
	})
	rctx, cancel := context.WithTimeout(ctx, networkFirstRefresh)
	st, _ := w.Refresh(rctx)
	cancel()
	k.reportNetworkChecks(st)
	k.netWatch.Store(w)
	k.sensor.SetNetworkReporter(w)
	go w.Run(ctx, netctx.DefaultInterval, k.reportNetworkChecks)
}

// rescopeNetwork narrows the network report to a new local policy at once.
func (k *Kit) rescopeNetwork() {
	if w := k.netWatch.Load(); w != nil {
		w.Rescope()
	}
}

// reportNetworkChecks records the three network checks of a detection.
func (k *Kit) reportNetworkChecks(st netctx.State) {
	k.ReportCheck(networkEgressCheck(st))
	k.ReportCheck(networkDNSCheck(st, runtime.GOOS))
	k.ReportCheck(networkDeclaredCheck(st))
}

func networkEgressCheck(st netctx.State) core.ConfigCheck {
	eg := st.Egress
	c := core.ConfigCheck{ID: CheckNetworkEgress, Code: string(eg.Internet),
		Params: map[string]core.ConfigParam{"reason": core.ParamEnum(eg.Reason)}}
	switch {
	case eg.Internet != netctx.InternetUnknown:
		c.Status = core.CheckPass
		switch eg.Internet {
		case netctx.InternetNone:
			c.Summary = "this sensor reports no internet egress: internet targets go to other sensors"
		case netctx.InternetProxy:
			c.Summary = "this sensor reaches the internet only through a proxy: raw-socket scans of internet targets go to other sensors"
		}
		if eg.Declared {
			c.Keys = []string{netctx.EnvInternet}
		}
	case eg.Reason == netctx.ReasonEchoUnsupported, eg.Reason == netctx.ReasonNoEcho:
		c.Status, c.Code = core.CheckSkip, "unsupported"
	case eg.Reason == netctx.ReasonEchoPrivate:
		c.Status, c.Keys = core.CheckWarn, []string{netctx.EnvInternet}
		c.Summary = "the platform is on a private network, so the egress check cannot tell whether this host reaches the internet; set " +
			netctx.EnvInternet + " to direct, proxy or none"
	default:
		c.Status, c.Keys = core.CheckWarn, []string{netctx.EnvInternet}
		c.Summary = "the egress check against the platform failed; internet egress is unknown (set " + netctx.EnvInternet + " to declare it)"
	}
	return c
}

func networkDNSCheck(st netctx.State, goos string) core.ConfigCheck {
	d := st.Detected
	c := core.ConfigCheck{ID: CheckNetworkDNSView}
	switch {
	case !d.ResolvConfRead && goos == "linux":
		c.Status, c.Code = core.CheckWarn, "resolv_conf_unreadable"
		c.Summary = "/etc/resolv.conf cannot be read: names resolve with the platform's defaults only"
	case d.ResolversFromEnv && !sameAddrs(d.Resolvers, d.SystemResolvers):
		c.Status, c.Code, c.Keys = core.CheckWarn, "split_view", []string{netctx.EnvDNSResolvers}
		c.Summary = "tools resolve names with " + netctx.EnvDNSResolvers + " while the local policy and the egress forwarder use the system resolvers: " +
			"the two views can disagree on what a name points to"
	case len(d.Resolvers) == 0 && d.ResolvConfRead:
		c.Status, c.Code = core.CheckWarn, "no_resolvers"
		c.Summary = "no DNS resolver is configured"
	case len(d.Resolvers) == 0:
		c.Status, c.Code = core.CheckSkip, "unknown"
	default:
		c.Status, c.Code = core.CheckPass, "consistent"
	}
	return c
}

func networkDeclaredCheck(st netctx.State) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckNetworkDeclared}
	switch {
	case len(st.Declared.Reach) == 0:
		c.Status, c.Code = core.CheckSkip, "nothing_declared"
		return c
	case !st.Detected.RoutesKnown:
		c.Status, c.Code = core.CheckSkip, "routes_unknown"
		return c
	}
	unrouted := 0
	for _, p := range st.Declared.Reach {
		if !st.Detected.Routed(p) {
			unrouted++
		}
	}
	if unrouted == 0 {
		c.Status, c.Code = core.CheckPass, "routed"
		return c
	}
	c.Status, c.Code, c.Keys = core.CheckWarn, "unrouted", []string{netctx.EnvReach}
	c.Params = map[string]core.ConfigParam{"count": core.ParamInt(int64(unrouted))}
	c.Summary = fmt.Sprintf("%d declared reach prefix(es) have no route from this host (no default route and no route covering them)", unrouted)
	return c
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[netip.Addr]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}
