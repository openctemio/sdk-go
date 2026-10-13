package core

// Host discovery (discover.hosts@1, api RFC-088): the mechanism a tool
// wrapper uses to turn what its probe saw into the capability's report. The
// platform decides what is probed (the targets, the probe ports in the job's
// ports param, the rate); a sensor never picks its own probe set.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// CapabilityHostDiscovery is the host discovery capability id.
const CapabilityHostDiscovery = "discover.hosts"

// PropLiveBy is the property of a live address that names the probe that
// answered ("tcp:443", "icmp").
const PropLiveBy = "live_by"

// ErrNoProbePorts: a host discovery job that names no probe ports. The
// platform sends them with every such job; a tool never guesses them.
var ErrNoProbePorts = fmt.Errorf("the host discovery job names no probe ports (param ports)")

// LiveHostsReport turns a port probe's report into a host discovery report
// in place: every ip_address with an answering port is kept as a live
// address, with the first answering port in properties.live_by
// ("tcp:<port>"); everything else (a host name, an address without an
// answering port) is dropped, because host discovery reports addresses
// only. targets, when not empty, also drops an address that is none of
// the job's targets nor inside one of its ranges: a tool never reports a
// host it was not given.
func LiveHostsReport(report *ctis.Report, targets []string) {
	if report == nil {
		return
	}
	cover := newTargetCover(targets)
	kept := report.Assets[:0]
	for _, a := range report.Assets {
		if a.Type != ctis.AssetTypeIPAddress || a.Technical == nil || a.Technical.IPAddress == nil || len(a.Technical.IPAddress.Ports) == 0 {
			continue
		}
		if !cover.covers(a.Value) {
			continue
		}
		if a.Properties == nil {
			a.Properties = ctis.Properties{}
		}
		a.Properties[PropLiveBy] = "tcp:" + strconv.Itoa(a.Technical.IPAddress.Ports[0].Port)
		kept = append(kept, a)
	}
	report.Assets = kept
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
