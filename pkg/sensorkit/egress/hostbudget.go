package egress

import (
	"context"
	"errors"
	"net/netip"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// The per-host budget in the forwarder: which key a destination is counted
// under, and the address it is dialed at as a second key.
//
// A destination is counted under its canonical host (adapt.CanonicalHost,
// the function adapt.HostKey applies to a target): the name a tool sends in
// another spelling (case, a trailing dot, Unicode or its ASCII form, an
// IPv6 address written differently, an IPv4-mapped IPv6 address, an IPv4
// address in hexadecimal or decimal) is the same host and gets the same
// rate, connection slots and breaker. The scope check is separate and
// unchanged: it admits what the task's targets name, by its own rules.
//
// Every connection is also counted under the address it is dialed at: the
// names of a task that resolve to one address share that address's rate,
// slots and breaker besides their own, so N names of one server get one
// server's budget, not N. What the forwarder reads on a connection is
// reported to both, and the stricter of the two holds.

// hostKey is the key host is counted under.
func hostKey(host string) string { return adapt.CanonicalHost(host) }

// addrKey is the key of an address a connection is dialed at.
func addrKey(a netip.Addr) string { return a.Unmap().WithZone("").String() }

// peer names one upstream connection for the rate controller: the key of
// the host the tool asked for and the key of the address it was dialed at
// ("" when none was, or when the two are one).
type peer struct {
	host, addr string
}

func peerOf(host, addr string) peer {
	p := peer{host: hostKey(host)}
	if a, err := netip.ParseAddr(addr); err == nil {
		if k := addrKey(a); k != p.host {
			p.addr = k
		}
	}
	return p
}

// peerOfRecord is the peer of the connection rec describes.
func peerOfRecord(rec *Record) peer { return peerOf(rec.Host, rec.Addr) }

// report feeds one signal of the connection to the host's state and to its
// address's.
func (f *Forwarder) report(p peer, e adapt.Event) {
	f.hostRate.Report(p.host, e)
	if p.addr != "" {
		f.hostRate.ReportAddr(p.addr, e)
	}
}

// acquire waits for the rate of the connection's host and of its address:
// one more request on a connection that is open (a request the forwarder
// reads, or one it counts on a tunnel).
func (f *Forwarder) acquire(ctx context.Context, p peer) error {
	if err := f.hostRate.Acquire(ctx, p.host); err != nil {
		return err
	}
	if p.addr == "" {
		return nil
	}
	err := f.hostRate.AcquireAddr(ctx, p.addr)
	if errors.Is(err, adapt.ErrHostUnavailable) {
		f.addrGap(p)
	}
	return err
}

// addrGap records on the host that the address it is reached at is backed
// off: the host's own state may be healthy, and its coverage is incomplete
// all the same.
func (f *Forwarder) addrGap(p peer) {
	f.hostRate.MarkGap(p.host, adapt.GapBreakerOpen, "the address "+p.addr+" it is reached at is backed off (shared with the task's other names of that address)")
}

// PinnedAddrs are the keys of the addresses the admitted name host is
// pinned to (the address itself for an address target): the address states
// a canary's answer about host is reported to (adapt.CanaryTarget.Addrs).
func (f *Forwarder) PinnedAddrs(host string) []string {
	h := Key(host)
	if a, err := netip.ParseAddr(h); err == nil {
		return []string{addrKey(a)}
	}
	var out []string
	for _, a := range f.names[h] {
		if !alwaysRefused(a) {
			out = append(out, addrKey(a))
		}
	}
	return out
}
