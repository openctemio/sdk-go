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
//     an address must be in an admitted prefix or be one an admitted name is
//     pinned to (a tool that resolves a target through the forwarder's DNS
//     and dials the address it got, as a port scanner does); metadata,
//     link-local, multicast and unspecified addresses are refused whatever
//     the scope says;
//   - applies the rate limit: connections per second for the task, and an
//     adaptive rate per destination host (adapt.HostRate) that backs off
//     on 429/503 (honoring Retry-After), resets, timeouts, failed TLS
//     handshakes and blocks, and never goes above the task's ceiling;
//     a host it cannot cover is a coverage gap (Forwarder.TargetRate);
//   - records the destination, the verdict and the bytes (Record).
//
// Forwarder.Dial may send the connections through an organization's proxy
// pool (package egress/upstream): the checks above run first, the pool
// only chooses the path to the address they allowed (TargetHost, Record's
// Endpoint, UpstreamError).
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

	"github.com/openctemio/ctis/addrscope"
	"golang.org/x/time/rate"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/internal/absname"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// Scope is what a task may reach.
type Scope struct {
	// Names are the admitted target names, each with the addresses the
	// admission resolved and checked. A connection to a name goes to these
	// addresses only: the name is never resolved again (no rebinding).
	Names map[string][]netip.Addr
	// Prefixes are the admitted address ranges (IP and CIDR targets). The
	// pinned addresses of Names are admitted too, each one alone and with
	// the limits of the names pinned to it.
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
	// Limits are the port, protocol and path limits of the task's targets
	// (from the job's signed statement). A limited host, and every address
	// a limited name is pinned to, is reached only on an allowed port; on a
	// port whose limits name path prefixes every HTTP request is checked
	// (TLS is terminated with the forwarder's own authority) and one
	// outside the prefixes is refused and recorded.
	Limits []scopelimit.Limit
	// Web is the job's web scope: when set, every connection is guarded
	// (TLS terminated as for a path limit), each HTTP request outside the
	// scope is refused and recorded, and anything that is not HTTP/1.x is
	// refused. WebTargets are the job's target hosts, the hosts of a web
	// scope that names none.
	Web        *webscope.Scope
	WebTargets []string
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
	// Endpoint is the id of the upstream proxy endpoint that carried the
	// connection (a connection Dial returned as an EndpointConn), empty
	// for a direct one.
	Endpoint string `json:"endpoint,omitempty"`
}

// ErrRefused is the error of a destination outside the scope.
var ErrRefused = errors.New("egress: destination refused")

// Limits bound a forwarder. Zero fields take the defaults.
type Limits struct {
	// Rate is connections per second for the task (0: 100).
	Rate float64
	// PerHostRate is the ceiling of the adaptive rate to one host:
	// connections, and requests on a connection the forwarder reads, per
	// second (0: Rate). The rate starts below it and never exceeds it.
	PerHostRate float64
	// MaxConns is how many connections may be open at once (0: 256).
	MaxConns int
	// DialTimeout bounds one upstream dial (0: 15s).
	DialTimeout time.Duration
	// HandshakeTimeout bounds reading a request (0: 10s).
	HandshakeTimeout time.Duration
	// UpstreamIdle is how long an upstream connection may stay silent
	// before it is closed (0: DefaultUpstreamIdle; negative: no bound,
	// only the forwarder's context closes it).
	UpstreamIdle time.Duration
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
	switch {
	case l.UpstreamIdle == 0:
		l.UpstreamIdle = DefaultUpstreamIdle
	case l.UpstreamIdle < 0:
		l.UpstreamIdle = 0
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
	// pinned maps every address an admitted name is pinned to back to those
	// names: the address alone is admitted (never its range), so a tool
	// that dials what the forwarder's DNS answered reaches exactly what the
	// name reaches.
	pinned map[netip.Addr][]string
	limits Limits

	// Dial opens an upstream connection (default: a net.Dialer). The
	// address is always an IP and a port the scope allowed.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// LookupVendor resolves a vendor host (default: net.DefaultResolver).
	LookupVendor func(ctx context.Context, host string) ([]netip.Addr, error)
	// OnRecord, when set, receives every record as it happens.
	OnRecord func(Record)
	// SearchDomains are the host resolver's search domains (SearchDomains):
	// a query for a name that is not a target and ends in one of them is a
	// tool's resolver appending it to a target that did not resolve. It is
	// answered NXDOMAIN, never resolved, and not recorded as a refusal.
	SearchDomains []string
	// Upstream answers a DNS query of another type than A or AAAA for an
	// admitted name (UpstreamDNS; nil: such queries get an empty answer).
	Upstream func(ctx context.Context, query []byte) ([]byte, error)
	// Reach, when set, receives the outcome of every connection toward a
	// target (not toward a vendor host): reached, refused, no route,
	// timeout, a name that does not resolve.
	Reach *reach.Recorder

	scopeLimits scopelimit.Set
	addrLimits  map[netip.Addr][]string
	authority   tlsAuthority

	rate     *rate.Limiter
	hostRate *adapt.HostRate
	mu       sync.Mutex
	records  []Record
	dropped  int
	tally    Tally
	conns    chan struct{}
}

// New returns the forwarder of one task. Names are normalized (lower case,
// no trailing dot); their pinned addresses join the admitted prefixes.
func New(scope Scope, limits Limits) *Forwarder {
	limits = limits.withDefaults()
	f := &Forwarder{scope: scope, limits: limits, names: map[string][]netip.Addr{}, pinned: map[netip.Addr][]string{},
		tally:    Tally{Targets: map[string]TargetTally{}},
		rate:     rate.NewLimiter(rate.Limit(limits.Rate), max(1, int(limits.Rate))),
		hostRate: adapt.NewHostRate(limits.PerHostRate),
		conns:    make(chan struct{}, limits.MaxConns)}
	for n, addrs := range scope.Names {
		key := normName(n)
		f.names[key] = append(f.names[key], addrs...)
	}
	for n, addrs := range f.names {
		for _, a := range addrs {
			if a = a.Unmap(); !alwaysRefused(a) && !slices.Contains(f.pinned[a], n) {
				f.pinned[a] = append(f.pinned[a], n)
			}
		}
	}
	f.prefixes = slices.Clone(scope.Prefixes)
	f.scopeLimits = scopelimit.NewSet(scope.Limits)
	f.indexLimits()
	return f
}

func normName(n string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".") }

// Key is the key Tally.Targets counts a target name under: lower case, no
// trailing dot, no brackets. An address or range target is counted under
// its prefix (netip.Prefix.String of the prefix in Scope.Prefixes).
func Key(host string) string { return normName(strings.Trim(host, "[]")) }

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

// publicOnly refuses what a vendor host or an egress-proxy destination
// must never resolve to: besides alwaysRefused, every internal address of
// ctis addrscope (the deny list the platform uses too): loopback, private,
// CGNAT, reserved ranges, and IPv6 addresses that carry an internal IPv4
// address (NAT64, 6to4, Teredo).
func publicOnly(a netip.Addr) bool {
	a = a.Unmap()
	return alwaysRefused(a) || addrscope.IsInternal(a) || !a.IsGlobalUnicast()
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
	if !f.limitPortAllowed(host, port) {
		return nil, fmt.Errorf("%w: port %d of %s is outside the job's scope limits", ErrRefused, port, normName(host))
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
		case len(f.pinned[a]) > 0:
			// An address an admitted name is pinned to: the same address
			// and the same ports (Ports, and the limits indexLimits gave it)
			// as the name, nothing of its range.
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
				return net.DefaultResolver.LookupNetIP(ctx, "ip", absname.Of(host))
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

// TargetRate is the task's per-host rate controller: its Summary has the
// rates reached and the hosts whose coverage is incomplete (gaps). Set its
// OnChange before Serve to log the rate changes.
func (f *Forwarder) TargetRate() *adapt.HostRate { return f.hostRate }

// allowRate waits for the task's rate and the host's adaptive rate (bounded
// by ctx); a host whose breaker is open is refused (adapt.ErrHostUnavailable).
func (f *Forwarder) allowRate(ctx context.Context, host string) error {
	if err := f.rate.Wait(ctx); err != nil {
		return err
	}
	return f.hostRate.Acquire(ctx, host)
}

// dial checks, rate-limits and dials host:port; it records the attempt.
func (f *Forwarder) dial(ctx context.Context, protocol, host string, port int) (net.Conn, *Record, error) {
	rec := &Record{Time: time.Now().UTC(), Protocol: protocol, Host: host, Port: port}
	target := f.Reach
	if f.isVendor(normName(host)) {
		target = nil
	}
	addrs, err := f.Resolve(ctx, host, port)
	if err != nil {
		if reach.Classify(err) == reach.DNSFailure {
			target.RecordErr(host, netip.Addr{}, port, err)
		}
		if errors.Is(err, ErrRefused) {
			f.count(host, false)
		}
		rec.Verdict, rec.Reason = Refused, err.Error()
		f.record(*rec)
		return nil, nil, err
	}
	f.count(host, true)
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
	targetErr := false // lastErr is about the target, not about an upstream proxy
	dctxBase := WithTargetHost(ctx, host)
	if _, ok := f.names[normName(host)]; ok {
		dctxBase = WithScopedName(dctxBase)
	}
	var pathErr *UpstreamError // the last failure was the path's (UpstreamError.PathFault)
	for _, a := range addrs {
		dctx, cancel := context.WithTimeout(dctxBase, f.limits.DialTimeout)
		c, err := dial(dctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		cancel()
		var ue *UpstreamError
		if !errors.As(err, &ue) {
			ue = nil
		}
		pathFault := ue != nil && ue.PathFault()
		switch {
		case ctx.Err() != nil || pathFault:
			// Nothing learned about the target.
		case ue != nil && ue.TargetClass.Valid():
			// What the proxy said about the target, never the proxy's
			// own address (the reach summary is shown with the run).
			target.Record(reach.Observation{Target: host, Addr: a, Port: port, Class: ue.TargetClass,
				Detail: "through the proxy pool: " + string(ue.TargetClass)})
		default:
			target.RecordErr(host, a, port, err)
		}
		if err == nil {
			f.hostRate.ReportDial(normName(host), port, nil)
			rec.Verdict, rec.Addr = Allowed, a.String()
			if ec, ok := c.(EndpointConn); ok {
				rec.Endpoint = ec.UpstreamEndpoint()
			}
			// The connection never outlives the forwarder's context, and a
			// silent host cannot hold it open (conn_bound.go).
			return bound(ctx, c, f.limits.UpstreamIdle), rec, nil
		}
		lastErr, targetErr, pathErr = err, !pathFault, nil
		if pathFault {
			pathErr = ue
		}
		if ue != nil && ue.Final {
			break
		}
	}
	// A path that failed says nothing about the target: the target's rate
	// is paced on what the target did only.
	if ctx.Err() == nil && targetErr {
		f.hostRate.ReportDial(normName(host), port, lastErr)
	}
	if ctx.Err() == nil && pathErr != nil {
		// The connection never left through the pool: that part of the
		// host is not scanned, and the result must not read as "nothing
		// found" (the scan ends partial with the host as a gap).
		f.hostRate.MarkGap(normName(host), adapt.GapProxyUnavailable,
			"the proxy pool could not carry a connection to port "+strconv.Itoa(port)+" ("+pathErr.Class+")")
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

// Tally counts a task's connections the scope checked (connect, http and
// socks5; not DNS questions, not requests the guard read): allowed (the
// dial was attempted, whether it then succeeded or not) and refused by the
// scope. A connection refused by the rate (a host backed off) is in
// neither: that host is a coverage gap (TargetRate), not out of scope.
type Tally struct {
	Allowed int `json:"allowed"`
	Refused int `json:"refused"`
	// Targets counts the connections toward each target: under its name
	// (Key) for a name, also when it was dialed at one of its pinned
	// addresses, and under its prefix for an address or range target. A
	// destination that is no target is counted in Allowed/Refused only.
	Targets map[string]TargetTally `json:"targets,omitempty"`
}

// TargetTally is one target's connections.
type TargetTally struct {
	Allowed int `json:"allowed"`
	Refused int `json:"refused"`
}

// Unreached reports whether the scope refused every connection the tool
// made toward the target (at least one).
func (t TargetTally) Unreached() bool { return t.Refused > 0 && t.Allowed == 0 }

// count adds one connection toward host to the tally. The keys are bounded
// by the scope (its names and prefixes), whatever the tool asks for.
func (f *Forwarder) count(host string, allowed bool) {
	keys := f.targetKeys(host)
	f.mu.Lock()
	defer f.mu.Unlock()
	if allowed {
		f.tally.Allowed++
	} else {
		f.tally.Refused++
	}
	for _, k := range keys {
		t := f.tally.Targets[k]
		if allowed {
			t.Allowed++
		} else {
			t.Refused++
		}
		f.tally.Targets[k] = t
	}
}

// targetKeys are the targets a connection to host counts toward: the
// admitted name; for an address, the names pinned to it and the admitted
// prefixes that contain it.
func (f *Forwarder) targetKeys(host string) []string {
	h := Key(host)
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		keys := slices.Clone(f.pinned[a])
		for _, p := range f.prefixes {
			if p.Contains(a) {
				keys = append(keys, p.String())
			}
		}
		return keys
	}
	if _, ok := f.names[h]; ok {
		return []string{h}
	}
	return nil
}

// Tally returns the task's connection counts so far.
func (f *Forwarder) Tally() Tally {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := Tally{Allowed: f.tally.Allowed, Refused: f.tally.Refused, Targets: make(map[string]TargetTally, len(f.tally.Targets))}
	for k, v := range f.tally.Targets {
		t.Targets[k] = v
	}
	return t
}
