package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

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
// names of a task that resolve to one address share that address's rate
// and connection slots besides their own, so N names of one server get one
// server's budget, not N. The address has a rate and slots and nothing
// else: one address often serves many unrelated sites (a CDN edge, shared
// hosting), so what the forwarder reads on a connection lowers the
// address's rate and never refuses, holds or cools down the other names
// reached there (adapt.HostRate.ReportAddr). Breakers, cooldowns and
// Retry-After holds are per host name.
//
// A slot counts a request in flight. A connection the tool keeps open
// between requests gives its slots back while it is quiet (connSlots) and
// takes them again for its next request, so the idle connections of one
// name do not keep the other names of its address waiting. A connection
// that finds no slot within Limits.DialTimeout is refused, and its host is
// reported as a coverage gap: the request never left, and the result must
// not read as "nothing found" for that host.

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
// reads, or one it counts on a tunnel). Only the host's own state can
// refuse it (its breaker, a Retry-After, a cooldown); the address only
// paces.
func (f *Forwarder) acquire(ctx context.Context, p peer) error {
	if err := f.hostRate.Acquire(ctx, p.host); err != nil {
		return err
	}
	if p.addr == "" {
		return nil
	}
	return f.hostRate.AcquireAddr(ctx, p.addr)
}

// nextRequest lets one more request start on a kept-alive connection the
// forwarder reads: the connection takes its slots again (it gave them
// back when the answer before was passed on) and waits for the rate of
// its host and of its address. A request that finds no slot is a coverage
// gap of the host.
func (f *Forwarder) nextRequest(ctx context.Context, sl *connSlots, p peer) error {
	if err := sl.resume(ctx); err != nil {
		if errors.Is(err, ErrHostBusy) {
			f.busyGap(p.host)
		}
		return err
	}
	return f.acquire(ctx, p)
}

// answered gives the slots of a kept-alive connection the forwarder reads
// back once an answer was passed on: no request is in flight on it.
func (f *Forwarder) answered(sl *connSlots) {
	if f.limits.SlotIdle > 0 {
		sl.park(nil)
	}
}

// busyGap records on host that one of its connections was refused for lack
// of a connection slot (ErrHostBusy): part of the host was not scanned.
func (f *Forwarder) busyGap(host string) {
	f.hostRate.MarkGap(host, adapt.GapRateFloor, adapt.GapDetailHostBusy)
}

// DefaultSlotIdle is how long a kept-alive connection may be quiet after
// the host's answer before it stops counting toward the host's connection
// slots, when Limits.SlotIdle is 0. It is well under Limits.DialTimeout,
// the time a new connection waits for a slot, and long enough that an
// answer still arriving (its bytes keep coming) keeps its slot.
const DefaultSlotIdle = time.Second

// slotIdleUnsure is how many times Limits.SlotIdle a tunnel is given
// before its slots are given back while the forwarder cannot be sure that
// what the host sent last was the answer: on the tunnel's first request
// (a TLS 1.3 server sends its session tickets after the handshake, which
// can arrive after the request left) and on a tunnel whose client offered
// HTTP/2 (the host sends settings, window updates and pings between
// answers). Still under Limits.DialTimeout with the defaults (5s of 15s),
// so an idle tunnel frees its slots before a waiting connection is
// refused. An answer to such a request that takes longer than this, after
// other bytes from the host, is counted out of the slots while it is still
// in flight: there the slots bound less than the requests in flight, and
// the rate still holds.
const slotIdleUnsure = 5

// slotIdleFor is how long the tunnel behind m may be quiet before its
// slots are given back.
func (f *Forwarder) slotIdleFor(m *tunnelMeter) time.Duration {
	if m.turned.Load() {
		return f.limits.SlotIdle
	}
	return slotIdleUnsure * f.limits.SlotIdle
}

// connSlots are the connection slots one upstream connection holds: one of
// its host's and, when the address is counted apart, one of its address's.
// They are held from the dial, given back while the connection is idle
// between requests (park) and taken again for its next request (resume),
// and given back for good when the connection ends (drop). A nil value
// holds nothing.
type connSlots struct {
	f          *Forwarder
	host, addr string

	mu               sync.Mutex
	held, done       bool
	relHost, relAddr func()
}

// park gives the slots back when idle (evaluated with the lock held, nil:
// always) says the connection is quiet.
func (s *connSlots) park(idle func() bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.held || s.done || (idle != nil && !idle()) {
		s.mu.Unlock()
		return
	}
	s.held = false
	rh, ra := s.relHost, s.relAddr
	s.mu.Unlock()
	ra()
	rh()
}

// resume takes the slots again for a connection that was parked, waiting
// as a new connection does (ErrHostBusy after Limits.DialTimeout).
func (s *connSlots) resume(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.held || s.done {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	rh, err := s.f.hostSlot(ctx, s.host)
	if err != nil {
		return err
	}
	ra := func() {}
	if s.addr != "" {
		if ra, err = s.f.hostSlot(ctx, s.addr); err != nil {
			rh()
			return err
		}
	}
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		ra()
		rh()
		return nil
	}
	s.held, s.relHost, s.relAddr = true, rh, ra
	s.mu.Unlock()
	return nil
}

// drop gives the slots back for good.
func (s *connSlots) drop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	held := s.held
	s.held, s.done = false, true
	rh, ra := s.relHost, s.relAddr
	s.mu.Unlock()
	if held {
		ra()
		rh()
	}
}

// slotsOf are the slots the upstream connection c holds (nil: none).
func slotsOf(c net.Conn) *connSlots {
	if b, ok := c.(*boundedConn); ok {
		return b.slots
	}
	return nil
}

// tunnelActivity is when a tunnel last carried bytes, and from which side.
type tunnelActivity struct {
	last     atomic.Int64 // unix nanoseconds
	fromHost atomic.Bool
}

func (a *tunnelActivity) touch(fromHost bool) {
	a.fromHost.Store(fromHost)
	a.last.Store(time.Now().UnixNano())
}

// quiet reports whether the host sent the tunnel's last bytes at least d
// ago: it answered, and nothing is in flight that the forwarder can see.
func (a *tunnelActivity) quiet(d time.Duration) bool {
	return a.fromHost.Load() && time.Since(time.Unix(0, a.last.Load())) >= d
}

// watchIdle parks the tunnel's slots whenever the tunnel has been quiet
// for idle(), checked every tick, until stop is closed.
func (s *connSlots) watchIdle(a *tunnelActivity, tick time.Duration, idle func() time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(max(tick, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.park(func() bool { return a.quiet(idle()) })
		}
	}
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
