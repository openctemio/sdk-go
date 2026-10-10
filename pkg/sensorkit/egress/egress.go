// Package egress is a task's way out to the network: a forwarder that every
// connection of a confined tool goes through (RFC-060 in openctemio/openctem
// api/docs/rfcs; the forwarder RFC-034 designs for proxied zones is the same
// one).
//
// A Forwarder serves HTTP CONNECT, absolute-form HTTP and SOCKS5 on a
// listener the caller gives it (a unix socket the task's relay reaches, or a
// loopback port), and answers DNS queries for the names it admits. For every
// connection it:
//
//   - checks the destination against the task's Scope: a name must be an
//     admitted target (dialed at the addresses pinned at admission, never
//     resolved again) or a vendor host (resolved now, public addresses only);
//     an address must be in an admitted prefix; metadata, link-local,
//     multicast and unspecified addresses are refused whatever the scope
//     says;
//   - applies the rate limit (connections per second for the task, and per
//     destination host);
//   - records the destination, the verdict and the bytes (Record).
//
// The forwarder enforces nothing by itself: a tool reaches the network only
// through it when the sandbox leaves it no other route (a network namespace
// with no interface but loopback; RFC-060 §4.2). Without that, it is a
// proxy a well-behaved tool uses, and the record still shows what it did.
//
// Stability: Experimental (docs/STABILITY.md).
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Scope is what a task may reach.
type Scope struct {
	// Names are the admitted target names, each with the addresses the
	// admission resolved and checked. A connection to a name goes to these
	// addresses only: the name is never resolved again (no rebinding).
	Names map[string][]netip.Addr
	// Prefixes are the admitted address ranges (IP and CIDR targets, and
	// the pinned addresses of Names are added by the forwarder).
	Prefixes []netip.Prefix
	// Vendor are hosts the tool's manifest may reach besides its targets
	// (permissions.vendor_hosts): resolved at connect time, public
	// addresses only.
	Vendor []string
	// Ports, when not empty, are the only destination ports allowed.
	Ports []int
	// AnyPublic admits any name or address that resolves to public
	// addresses only (a tool whose network class reaches the internet
	// through the sensor's egress): loopback, private, link-local and
	// metadata addresses stay refused, and every destination is still
	// recorded.
	AnyPublic bool
	// DNSOnly answers DNS for the admitted names and refuses every
	// connection, to the admitted names too (a tool whose network is DNS
	// resolution learns records; it never reaches a host).
	DNSOnly bool
}

// Verdicts of a Record.
const (
	Allowed = "allowed"
	Refused = "refused"
)

// Record is one destination a task asked for.
type Record struct {
	Time     time.Time `json:"time"`
	Protocol string    `json:"protocol"` // connect, http, socks5, dns
	Host     string    `json:"host"`
	Port     int       `json:"port,omitempty"`
	Addr     string    `json:"addr,omitempty"`
	Verdict  string    `json:"verdict"`
	Reason   string    `json:"reason,omitempty"`
	BytesOut int64     `json:"bytes_out,omitempty"`
	BytesIn  int64     `json:"bytes_in,omitempty"`
}

// ErrRefused is the error of a destination outside the scope.
var ErrRefused = errors.New("egress: destination refused")

// Limits bound a forwarder. Zero fields take the defaults.
type Limits struct {
	// Rate is connections per second for the task (0: 100).
	Rate float64
	// PerHostRate is connections per second to one host (0: Rate).
	PerHostRate float64
	// MaxConns is how many connections may be open at once (0: 256).
	MaxConns int
	// DialTimeout bounds one upstream dial (0: 15s).
	DialTimeout time.Duration
	// HandshakeTimeout bounds reading a request (0: 10s).
	HandshakeTimeout time.Duration
	// MaxRecords bounds the record kept in memory (0: 10000); further
	// records are counted, not kept.
	MaxRecords int
}

func (l Limits) withDefaults() Limits {
	if l.Rate <= 0 {
		l.Rate = 100
	}
	if l.PerHostRate <= 0 {
		l.PerHostRate = l.Rate
	}
	if l.MaxConns <= 0 {
		l.MaxConns = 256
	}
	if l.DialTimeout <= 0 {
		l.DialTimeout = 15 * time.Second
	}
	if l.HandshakeTimeout <= 0 {
		l.HandshakeTimeout = 10 * time.Second
	}
	if l.MaxRecords <= 0 {
		l.MaxRecords = 10000
	}
	return l
}

// Forwarder is one task's forwarder. Create it with New.
type Forwarder struct {
	scope    Scope
	names    map[string][]netip.Addr
	prefixes []netip.Prefix
	limits   Limits

	// Dial opens an upstream connection (default: a net.Dialer). The
	// address is always an IP and a port the scope allowed.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// LookupVendor resolves a vendor host (default: net.DefaultResolver).
	LookupVendor func(ctx context.Context, host string) ([]netip.Addr, error)
	// OnRecord, when set, receives every record as it happens.
	OnRecord func(Record)
	// Upstream answers a DNS query of another type than A or AAAA for an
	// admitted name (UpstreamDNS; nil: such queries get an empty answer).
	Upstream func(ctx context.Context, query []byte) ([]byte, error)

	rate    *rate.Limiter
	mu      sync.Mutex
	perHost map[string]*rate.Limiter
	records []Record
	dropped int
	conns   chan struct{}
}

// New returns the forwarder of one task. Names are normalized (lower case,
// no trailing dot); their pinned addresses join the admitted prefixes.
func New(scope Scope, limits Limits) *Forwarder {
	limits = limits.withDefaults()
	f := &Forwarder{scope: scope, limits: limits, names: map[string][]netip.Addr{},
		rate: rate.NewLimiter(rate.Limit(limits.Rate), max(1, int(limits.Rate))), perHost: map[string]*rate.Limiter{},
		conns: make(chan struct{}, limits.MaxConns)}
	for n, addrs := range scope.Names {
		key := normName(n)
		f.names[key] = append(f.names[key], addrs...)
	}
	f.prefixes = slices.Clone(scope.Prefixes)
	return f
}

func normName(n string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".") }

// alwaysRefused are addresses no scope can admit: cloud metadata and other
// link-local, multicast and unspecified addresses.
func alwaysRefused(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || slices.Contains(metadataAddrs, a)
}

// metadataAddrs are cloud metadata and host-agent addresses outside the
// link-local range.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud metadata
	netip.MustParseAddr("168.63.129.16"),   // Azure host agent (wireserver)
}

// publicOnly refuses what a vendor host must never resolve to: besides
// alwaysRefused, loopback and private ranges.
func publicOnly(a netip.Addr) bool {
	a = a.Unmap()
	return alwaysRefused(a) || a.IsLoopback() || a.IsPrivate() || !a.IsGlobalUnicast()
}

func (f *Forwarder) portAllowed(port int) bool {
	return port > 0 && port <= 65535 && (len(f.scope.Ports) == 0 || slices.Contains(f.scope.Ports, port))
}

func (f *Forwarder) inPrefixes(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range f.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Resolve checks host:port and returns the addresses to dial, in order.
func (f *Forwarder) Resolve(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	if f.scope.DNSOnly {
		return nil, fmt.Errorf("%w: the task may resolve names, not connect", ErrRefused)
	}
	if !f.portAllowed(port) {
		return nil, fmt.Errorf("%w: port %d not allowed", ErrRefused, port)
	}
	return f.resolveHost(ctx, host)
}

// resolveHost checks a host (any port) and returns its addresses.
func (f *Forwarder) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	h := normName(strings.Trim(host, "[]"))
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		switch {
		case alwaysRefused(a):
			return nil, fmt.Errorf("%w: %s is a link-local, metadata or reserved address", ErrRefused, a)
		case f.inPrefixes(a):
		case f.scope.AnyPublic && !publicOnly(a):
		default:
			return nil, fmt.Errorf("%w: %s is not a target", ErrRefused, a)
		}
		return []netip.Addr{a}, nil
	}
	if addrs, ok := f.names[h]; ok {
		var out []netip.Addr
		for _, a := range addrs {
			if !alwaysRefused(a) {
				out = append(out, a.Unmap())
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: %s has no admitted address", ErrRefused, h)
		}
		return out, nil
	}
	if f.isVendor(h) || f.scope.AnyPublic {
		lookup := f.LookupVendor
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		addrs, err := lookup(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("egress: resolve %s: %w", h, err)
		}
		var out []netip.Addr
		for _, a := range addrs {
			if !publicOnly(a) {
				out = append(out, a.Unmap())
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%w: %s resolves to no public address", ErrRefused, h)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: %s is not a target", ErrRefused, h)
}

func (f *Forwarder) isVendor(h string) bool {
	for _, v := range f.scope.Vendor {
		if normName(v) == h {
			return true
		}
	}
	return false
}

// allowRate waits for the task's and the host's rate (bounded by ctx).
func (f *Forwarder) allowRate(ctx context.Context, host string) error {
	f.mu.Lock()
	l, ok := f.perHost[host]
	if !ok {
		l = rate.NewLimiter(rate.Limit(f.limits.PerHostRate), max(1, int(f.limits.PerHostRate)))
		if len(f.perHost) < 65536 {
			f.perHost[host] = l
		}
	}
	f.mu.Unlock()
	if err := f.rate.Wait(ctx); err != nil {
		return err
	}
	return l.Wait(ctx)
}

// dial checks, rate-limits and dials host:port; it records the attempt.
func (f *Forwarder) dial(ctx context.Context, protocol, host string, port int) (net.Conn, *Record, error) {
	rec := &Record{Time: time.Now().UTC(), Protocol: protocol, Host: host, Port: port}
	addrs, err := f.Resolve(ctx, host, port)
	if err != nil {
		rec.Verdict, rec.Reason = Refused, err.Error()
		f.record(*rec)
		return nil, nil, err
	}
	if err := f.allowRate(ctx, normName(host)); err != nil {
		rec.Verdict, rec.Reason = Refused, "rate: "+err.Error()
		f.record(*rec)
		return nil, nil, err
	}
	dial := f.Dial
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	var lastErr error
	for _, a := range addrs {
		dctx, cancel := context.WithTimeout(ctx, f.limits.DialTimeout)
		c, err := dial(dctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		cancel()
		if err == nil {
			rec.Verdict, rec.Addr = Allowed, a.String()
			return c, rec, nil
		}
		lastErr = err
	}
	rec.Verdict, rec.Reason = Allowed, "dial failed: "+lastErr.Error()
	f.record(*rec)
	return nil, nil, lastErr
}

func (f *Forwarder) record(r Record) {
	f.mu.Lock()
	if len(f.records) < f.limits.MaxRecords {
		f.records = append(f.records, r)
	} else {
		f.dropped++
	}
	cb := f.OnRecord
	f.mu.Unlock()
	if cb != nil {
		cb(r)
	}
}

// Records returns what the task asked for so far, and how many records
// were dropped over the limit.
func (f *Forwarder) Records() ([]Record, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.records), f.dropped
}

// Refusals returns the refused records.
func (f *Forwarder) Refusals() []Record {
	recs, _ := f.Records()
	var out []Record
	for _, r := range recs {
		if r.Verdict == Refused {
			out = append(out, r)
		}
	}
	return out
}
