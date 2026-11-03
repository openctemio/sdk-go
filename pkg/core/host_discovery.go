package core

// Host discovery (discover.hosts@1, api RFC-088): the mechanism a tool
// wrapper uses to turn what its probe saw into the capability's report. The
// platform decides what is probed (the targets, the probe ports in the job's
// ports param, the rate); a sensor never picks its own probe set.

import (
	"fmt"
	"net/netip"

	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// CapabilityHostDiscovery is the host discovery capability id.
const CapabilityHostDiscovery = "discover.hosts"

// ErrNoProbePorts: a host discovery job that names no probe ports. The
// platform sends them with every such job; a tool never guesses them.
var ErrNoProbePorts = fmt.Errorf("the host discovery job names no probe ports (param ports)")

// LiveHostsReport turns a port probe's report into a host discovery report
// in place: every ip_address that exposes an open service (a service asset
// linked from it by an exposes relationship, CTIS 2.0) is kept as a live
// address, with last_seen_at set to when it answered (the report's
// generated_at unless the asset states it); everything else (a host name, an address without an answering port, the
// service assets and their relationships) is dropped, because host
// discovery reports addresses only. targets, when not empty, also drops an
// address that is none of the job's targets nor inside one of its ranges: a
// tool never reports a host it was not given.
func LiveHostsReport(report *ctis.Report, targets []string) {
	if report == nil {
		return
	}
	cover := newTargetCover(targets)
	firstPort := openPortsByHost(report)
	seen := report.Metadata.GeneratedAt
	if seen.IsZero() {
		seen = time.Now().UTC()
	}
	kept := report.Assets[:0]
	for _, a := range report.Assets {
		if a.Type != ctis.AssetTypeIPAddress {
			continue
		}
		if _, ok := firstPort[a.ID]; !ok || !cover.covers(a.Value) {
			continue
		}
		if a.LastSeenAt == nil {
			t := seen
			a.LastSeenAt = &t
		}
		kept = append(kept, a)
	}
	report.Assets = kept
	report.Relationships = nil
}

// servicePort is one open port of a service asset.
type servicePort struct {
	Port      int
	Transport string
}

// openPortsByHost returns, per asset id, the lowest open port of the
// services it exposes (exposes relationships to service assets whose state
// is open or not stated).
func openPortsByHost(report *ctis.Report) map[string]servicePort {
	services := make(map[string]servicePort)
	for _, a := range report.Assets {
		if a.Type != ctis.AssetTypeService || a.Technical == nil || a.Technical.Service == nil {
			continue
		}
		st := a.Technical.Service
		if st.Port <= 0 || (st.State != "" && st.State != ctis.PortOpen) {
			continue
		}
		tr := string(st.Transport)
		if tr == "" {
			tr = string(ctis.TransportTCP)
		}
		services[a.ID] = servicePort{Port: st.Port, Transport: tr}
	}
	out := make(map[string]servicePort)
	for _, rel := range report.Relationships {
		if rel.Type != ctis.RelExposes {
			continue
		}
		sp, ok := services[rel.ToRef]
		if !ok {
			continue
		}
		if cur, ok := out[rel.FromRef]; !ok || sp.Port < cur.Port {
			out[rel.FromRef] = sp
		}
	}
	return out
}

// targetCover answers whether an address is one of a job's targets or
// inside one of its ranges (empty: everything).
type targetCover struct {
	all    bool
	addrs  map[netip.Addr]bool
	ranges []netip.Prefix
}

func newTargetCover(targets []string) targetCover {
	c := targetCover{all: len(targets) == 0, addrs: map[netip.Addr]bool{}}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if p, err := netip.ParsePrefix(t); err == nil {
			if a := p.Addr(); a.Is4In6() {
				p = netip.PrefixFrom(a.Unmap(), max(p.Bits()-96, 0))
			}
			c.ranges = append(c.ranges, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(t); err == nil {
			c.addrs[a.Unmap().WithZone("")] = true
		}
	}
	return c
}

func (c targetCover) covers(value string) bool {
	if c.all {
		return true
	}
	a, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	if c.addrs[a] {
		return true
	}
	for _, p := range c.ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
