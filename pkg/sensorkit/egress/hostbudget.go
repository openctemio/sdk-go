package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
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
// A slot counts an open connection: the connections open to a host, and
// to an address, never exceed its slots. A connection the tool keeps open
// between requests is idle while it is quiet after the host's answer
// (connSlots); a new connection that finds every slot taken closes the
// oldest idle connection whose slot it needs and takes it, so the idle
// connections of one name do not keep the other names of its address (or
// the name's own next connection) waiting. A connection that finds no slot
// within Limits.DialTimeout, every slot being held by a connection that is
// not idle, is refused, and its host is reported as a coverage gap
// (adapt.GapSlotsFull): the request never left, and the result must not
// read as "nothing found" for that host. The forwarder's own bound caused
// it, not the host: it is never reported as the host pushing back.

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
// forwarder reads: the connection stops being idle (it keeps its slots)
// and waits for the rate of its host and of its address. A connection that
// was closed for another one while it was idle carries no further request
// (errSlotEvicted).
func (f *Forwarder) nextRequest(ctx context.Context, sl *connSlots, p peer) error {
	if err := sl.resume(); err != nil {
		return err
	}
	return f.acquire(ctx, p)
}

// answered marks a kept-alive connection the forwarder reads idle once an
// answer was passed on: no request is in flight on it.
func (f *Forwarder) answered(sl *connSlots) {
	if f.limits.SlotIdle > 0 {
		sl.park(nil)
	}
}

// busyGap records on host that one of its connections was refused for lack
// of a connection slot (ErrHostBusy), or that a tunnel whose request may
// still have been outstanding was closed for a connection that waited for
// its slot: part of the host was not scanned.
// The forwarder's own bound refused it, so the gap is GapSlotsFull, never a
// reason that says the host pushed back.
func (f *Forwarder) busyGap(host string) {
	f.hostRate.MarkGap(host, adapt.GapSlotsFull, adapt.GapDetailSlotsFull)
}

// DefaultSlotIdle is how long a kept-alive connection may be quiet after
// the host's answer before it counts as idle, and may be closed for a
// connection that waits for its slot, when Limits.SlotIdle is 0. It is
// well under Limits.DialTimeout, the time a new connection waits for a
// slot, and long enough that an answer still arriving (its bytes keep
// coming) keeps the connection.
const DefaultSlotIdle = time.Second

// UnsureSlotIdle is how long a tunnel must be quiet before it counts as
// idle while the forwarder cannot be sure that what the host sent last was
// the end of the answer, nor that the answer started: on the tunnel's
// first request (a TLS 1.3 server sends its session tickets after the
// handshake, which can arrive after the request left). Such a tunnel is
// unsure. Once a further request followed the host's bytes, the host has
// answered on it: a tunnel whose client and host took turns (HTTP/1.1) is
// sure and counts as idle after Limits.SlotIdle; one whose client offered
// HTTP/2 (the host sends settings, window updates and pings of its own,
// also while an answer has not started) stays unsure and counts as idle
// after the unsure time, as before the host answered. Having answered
// only decides the gap: closing such a tunnel records none.
//
// An unsure tunnel is never closed for another connection before it has
// been quiet this long: a connection that waits for its slot keeps waiting,
// past Limits.DialTimeout if need be (Forwarder.hostSlot), rather than cut
// an answer that may still be arriving, and the connections open to the
// host still never exceed its slots. An unsure tunnel that is closed for
// another connection after that time leaves a coverage gap of its host
// (busyGap) when its request may still have been outstanding: on TLS, what
// the host sent after it may have been only the end of its handshake
// (tunnelMeter.answerSeen). A tunnel whose last traffic was the host's
// answer leaves none, whatever its client offered (ordinary keep-alive
// reuse).
// Thirty seconds is far longer than an answer ordinarily pauses once it
// has started.
const UnsureSlotIdle = 30 * time.Second

// slotIdleFor is how long the tunnel behind m may be quiet before it
// counts as idle.
func (f *Forwarder) slotIdleFor(m *tunnelMeter) time.Duration {
	switch {
	case m.turned.Load():
		return f.limits.SlotIdle
	}
	return f.unsureIdle
}

// errSlotEvicted ends a connection the forwarder closed while it was idle,
// to give its slots to a connection that waited for them.
var errSlotEvicted = errors.New("egress: the idle connection was closed for another connection to the host")

// slotPool is the connection slots of one key (a host or an address): ch
// holds one token per open connection. Under Forwarder.hostMu, waiters
// counts the connections waiting for a slot and idle lists the open
// connections that hold one and are idle, oldest first. pending counts
// the unsure tunnels that hold one and are quiet but do not count as idle
// yet (UnsureSlotIdle): a connection that waits for a slot keeps waiting
// past Limits.DialTimeout while one is pending. closing counts the
// connections closed for a waiter whose slots are not free yet: a waiter
// whose wait ends meanwhile waits for them rather than be refused.
type slotPool struct {
	ch      chan struct{}
	waiters int
	idle    []*connSlots
	pending int
	closing int
}

// release returns a func that frees one slot of the pool, once.
func (p *slotPool) release() func() {
	var once sync.Once
	return func() { once.Do(func() { <-p.ch }) }
}

// remove takes s out of the pool's idle list.
func (p *slotPool) remove(s *connSlots) {
	if p == nil {
		return
	}
	if i := slices.Index(p.idle, s); i >= 0 {
		p.idle = slices.Delete(p.idle, i, i+1)
	}
}

// evictLocked picks the oldest idle connection of pool to close for a
// connection that waits for one of its slots (nil: none is idle). The
// caller holds f.hostMu and closes it after unlocking (connSlots.close).
func (f *Forwarder) evictLocked(pool *slotPool) *connSlots {
	if pool == nil || len(pool.idle) == 0 {
		return nil
	}
	v := pool.idle[0]
	v.unparkLocked()
	v.evictLocked()
	return v
}

// connSlots are the connection slots one upstream connection holds: one of
// its host's and, when the address is counted apart, one of its address's.
// They are held from the dial until the connection ends (drop). While the
// connection is idle between requests (park) it is listed in its pools'
// idle lists, and a connection that waits for one of its slots closes it
// (evictLocked, close); its next request takes it off the lists again
// (resume). The state is guarded by Forwarder.hostMu. A nil value holds
// nothing.
type connSlots struct {
	f                  *Forwarder
	hostPool, addrPool *slotPool
	relHost, relAddr   func()
	// up is the upstream connection; client, when set, the tool's side of
	// it (attach): closing for another connection closes both.
	up, client net.Conn

	parked, evicted, done bool
	// pending: an unsure tunnel quiet for Limits.SlotIdle that does not
	// count as idle yet (slotPool.pending).
	pending bool
}

// attach records the tool's side of the connection, closed with it when it
// is closed for another connection.
func (s *connSlots) attach(client net.Conn) {
	if s == nil {
		return
	}
	s.f.hostMu.Lock()
	s.client = client
	s.f.hostMu.Unlock()
}

// unparkLocked takes the connection off its pools' idle lists.
func (s *connSlots) unparkLocked() {
	if !s.parked {
		return
	}
	s.parked = false
	s.hostPool.remove(s)
	s.addrPool.remove(s)
}

// evictLocked marks the connection closed for a connection that waits for
// one of its slots; its pools count it as closing until drop frees them.
func (s *connSlots) evictLocked() {
	s.evicted = true
	if s.hostPool != nil {
		s.hostPool.closing++
	}
	if s.addrPool != nil {
		s.addrPool.closing++
	}
}

// setPendingLocked sets whether the connection is a pending unsure tunnel
// and keeps its pools' counts.
func (s *connSlots) setPendingLocked(p bool) {
	if s.pending == p {
		return
	}
	s.pending = p
	d := 1
	if !p {
		d = -1
	}
	if s.hostPool != nil {
		s.hostPool.pending += d
	}
	if s.addrPool != nil {
		s.addrPool.pending += d
	}
}

// pend marks the connection a pending unsure tunnel while quiet (evaluated
// with the lock held) says so and it is neither idle nor closed.
func (s *connSlots) pend(quiet func() bool) {
	if s == nil || (s.hostPool == nil && s.addrPool == nil) {
		return
	}
	s.f.hostMu.Lock()
	s.setPendingLocked(!s.parked && !s.evicted && !s.done && quiet())
	s.f.hostMu.Unlock()
}

// park marks the connection idle when idle (evaluated with the lock held,
// nil: always) says it is quiet. When a connection already waits for one
// of its slots, it is closed at once and its slots go to that connection.
func (s *connSlots) park(idle func() bool) {
	if s == nil || (s.hostPool == nil && s.addrPool == nil) {
		return
	}
	f := s.f
	f.hostMu.Lock()
	if s.parked || s.evicted || s.done || (idle != nil && !idle()) {
		f.hostMu.Unlock()
		return
	}
	s.setPendingLocked(false)
	if (s.hostPool != nil && s.hostPool.waiters > 0) || (s.addrPool != nil && s.addrPool.waiters > 0) {
		s.evictLocked()
		f.hostMu.Unlock()
		s.close()
		return
	}
	s.parked = true
	if s.hostPool != nil {
		s.hostPool.idle = append(s.hostPool.idle, s)
	}
	if s.addrPool != nil {
		s.addrPool.idle = append(s.addrPool.idle, s)
	}
	f.hostMu.Unlock()
}

// resume ends the connection's idle time for its next request: it keeps
// the slots it holds. A connection that was closed for another one
// returns errSlotEvicted; one that ended, nil (its own error ends it).
// Calls at once (from two goroutines) are safe: the connection holds its
// slots once whatever the order.
func (s *connSlots) resume() error {
	if s == nil {
		return nil
	}
	s.f.hostMu.Lock()
	defer s.f.hostMu.Unlock()
	if s.evicted {
		return errSlotEvicted
	}
	s.setPendingLocked(false)
	s.unparkLocked()
	return nil
}

// wasEvicted reports whether the forwarder closed the connection for
// another one: how it ended says nothing about the host.
func (s *connSlots) wasEvicted() bool {
	if s == nil {
		return false
	}
	s.f.hostMu.Lock()
	defer s.f.hostMu.Unlock()
	return s.evicted
}

// close closes a connection picked for another one (evicted is set): both
// sides of it, then its slots are freed.
func (s *connSlots) close() {
	if s == nil {
		return
	}
	s.f.hostMu.Lock()
	up, client := s.up, s.client
	s.f.hostMu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	if up != nil {
		_ = up.Close()
	}
	s.drop()
}

// drop gives the slots back for good (once).
func (s *connSlots) drop() {
	if s == nil {
		return
	}
	s.f.hostMu.Lock()
	if s.done {
		s.f.hostMu.Unlock()
		return
	}
	s.done = true
	s.setPendingLocked(false)
	s.unparkLocked()
	evicted := s.evicted
	s.f.hostMu.Unlock()
	s.relAddr()
	s.relHost()
	if evicted {
		// The slots are free: the pools no longer count them as closing.
		s.f.hostMu.Lock()
		if s.hostPool != nil {
			s.hostPool.closing--
		}
		if s.addrPool != nil {
			s.addrPool.closing--
		}
		s.f.hostMu.Unlock()
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

// watchIdle marks the tunnel idle whenever it has been quiet for idle()
// (Limits.SlotIdle for a sure tunnel, UnsureSlotIdle for an unsure one),
// and an unsure tunnel that has been quiet for Limits.SlotIdle pending
// until then, checked every tick, until stop is closed.
func (s *connSlots) watchIdle(a *tunnelActivity, tick time.Duration, idle func() time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(max(tick, 10*time.Millisecond))
	defer t.Stop()
	short := s.f.limits.SlotIdle
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			d := idle()
			s.park(func() bool { return a.quiet(d) })
			s.pend(func() bool { return d > short && a.quiet(short) })
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
