package conformance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// ReachProber is a sensor's reach probe as the suite drives it: it must
// dial only through guard and dial, and only for targets. SDKReachProber
// is the SDK's own (reach.Probe).
type ReachProber func(ctx context.Context, guard reach.Guard, dial reach.DialFunc, targets []string) (reach.ProbeResult, error)

// SDKReachProber runs reach.Probe with the suite's guard and dialer.
func SDKReachProber(ctx context.Context, guard reach.Guard, dial reach.DialFunc, targets []string) (reach.ProbeResult, error) {
	return reach.Probe(ctx, guard, targets, reach.ProbeOptions{Dial: dial, Timeout: 500 * time.Millisecond})
}

// RunReachSuite checks a sensor's reach probe (RFC-089 §4.3 in
// openctemio/openctem):
//
//   - OnlyAdmitted: with a recording dialer, the probe never dials an
//     address its guard did not admit: a literal outside the scope, the
//     out-of-scope half of a range, a denied address inside a range, a
//     name resolving to a denied address, IPv6, link-local, a name, never
//     a name (only address literals reach the dialer).
//   - Bounds: at most reach.MaxProbeAddrs addresses, at most
//     reach.MaxProbeRate connects in any second, one connect per address
//     at a time.
//   - Classes: a refused port is reached (port_closed), no route and
//     timeouts are unreached, and the summary is bounded and stable.
//   - Unroutable: a target behind no route is reported unreached, never as
//     reached or as nothing.
//   - Canceled: a canceled probe stops dialing.
func RunReachSuite(t T, probe ReachProber) {
	t.Helper()
	// Each check reports its failures with its name; a failing check does
	// not stop the others.
	run := func(name string, check func(fail func(format string, args ...any))) {
		check(func(format string, args ...any) { t.Errorf(name+": "+format, args...) })
	}

	run("OnlyAdmitted", func(fail func(string, ...any)) {
		g := newSuiteGuard()
		g.allow("192.0.2.0/28", "2001:db8:1::/126")
		g.deny("192.0.2.5")
		g.names["app.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.3")}
		g.names["rebind.example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.7")}
		g.names["mixed.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("203.0.113.9")}
		d := newRecordingDialer(nil)
		targets := []string{
			"198.51.100.1", "203.0.113.0/30", "192.0.2.0/27", "app.example.com", "https://app.example.com:8443/x",
			"rebind.example.com", "mixed.example.com", "2001:db8:1::/124", "[2001:db8:2::1]", "fe80::1", "169.254.169.254",
			"192.0.2.5",
		}
		if _, err := probe(context.Background(), g, d.dial, targets); err != nil {
			fail("probe: %v", err)
			return
		}
		dialed := d.addrs()
		if len(dialed) == 0 {
			fail("the probe dialed nothing")
			return
		}
		for _, a := range dialed {
			if !g.admits(a) {
				fail("SECURITY: dialed %s, which the guard did not admit", a)
			}
		}
		if d.names() > 0 {
			fail("SECURITY: %d dials named a host: a probe dials checked address literals only", d.names())
		}
		// The admitted addresses were probed (the in-scope part of the range
		// and the v6 addresses included).
		for _, want := range []string{"192.0.2.0", "192.0.2.3", "192.0.2.4", "192.0.2.15", "2001:db8:1::3"} {
			if !slices.Contains(dialed, netip.MustParseAddr(want)) {
				fail("admitted %s was not probed", want)
			}
		}
	})

	run("NoGuard", func(fail func(string, ...any)) {
		d := newRecordingDialer(nil)
		if _, err := probe(context.Background(), nil, d.dial, []string{"192.0.2.1"}); err == nil {
			fail("a probe without a guard ran")
		}
		if len(d.addrs()) > 0 {
			fail("SECURITY: a probe without a guard dialed")
		}
	})

	run("Bounds", func(fail func(string, ...any)) {
		g := newSuiteGuard()
		g.allow("10.20.0.0/22")
		d := newRecordingDialer(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()
		res, _ := probe(ctx, g, d.dial, []string{"10.20.0.0/22"})
		// Within 2.5 s at 10/s, at most ~26 connects; never more than
		// MaxProbeAddrs addresses in any case.
		if n := len(d.addrs()); n > reach.MaxProbeAddrs {
			fail("dialed %d addresses, more than %d", n, reach.MaxProbeAddrs)
		}
		if res.NotProbed == 0 {
			fail("1024 admitted addresses, none counted as not probed (probed %d)", res.Probed)
		}
		times := d.times()
		limit := int(reach.MaxProbeRate)
		for i := limit; i < len(times); i++ {
			if w := times[i].Sub(times[i-limit]); w < 950*time.Millisecond {
				fail("%d connects within %s: more than %d per second", limit+1, w, limit)
				break
			}
		}
		if d.maxPerHost() > 1 {
			fail("%d connects to one address at once; want one at a time", d.maxPerHost())
		}
		if len(times) < 5 {
			fail("only %d connects in 2.5 s", len(times))
		}
	})

	run("LargeRange", func(fail func(string, ...any)) {
		// The guard refuses every address: admission must give up early,
		// not walk 16M (or 2^32) addresses.
		g := newSuiteGuard()
		d := newRecordingDialer(nil)
		start := time.Now()
		_, _ = probe(context.Background(), g, d.dial, []string{"10.0.0.0/8", "0.0.0.0/0"})
		if len(d.addrs()) > 0 {
			fail("SECURITY: dialed an address the guard refused")
		}
		if el := time.Since(start); el > 2*time.Second {
			fail("admitting a /8 took %s", el)
		}
		if n := g.checks(); n > 4*reach.MaxProbeAddrs+16 {
			fail("%d guard checks for two large ranges", n)
		}
	})

	run("Classes", func(fail func(string, ...any)) {
		g := newSuiteGuard()
		g.allow("192.0.2.0/29", "2001:db8::/125")
		errs := map[string]error{
			"192.0.2.1":   syscall.ECONNREFUSED,
			"192.0.2.2":   syscall.ENETUNREACH,
			"192.0.2.3":   os.ErrDeadlineExceeded,
			"2001:db8::1": syscall.EHOSTUNREACH,
			"2001:db8::2": syscall.EACCES,
		}
		d := newRecordingDialer(errs)
		res, err := probe(context.Background(), g, d.dial, []string{"192.0.2.0/30", "2001:db8::1", "2001:db8::2", "2001:db8::4"})
		if err != nil {
			fail("probe: %v", err)
			return
		}
		want := map[reach.Class]int{reach.Reached: 2, reach.PortClosed: 1, reach.NoRoute: 2, reach.Timeout: 1, reach.FirewallRefused: 1}
		for c, n := range want {
			if res.Classes[c] != n {
				fail("class %s = %d, want %d (all: %v)", c, res.Classes[c], n, res.Classes)
			}
		}
		if res.Targets != 7 || res.Reached != 3 || res.Unreached != 4 {
			fail("summary %+v", res.Summary)
		}
		if len(res.Blocks) > reach.MaxBlockRows || len(res.UnreachedList) > reach.MaxUnreachedListed {
			fail("summary not bounded")
		}
		again, _ := probe(context.Background(), g, newRecordingDialer(errs).dial, []string{"192.0.2.0/30", "2001:db8::1", "2001:db8::2", "2001:db8::4"})
		if fmt.Sprint(again.Summary) != fmt.Sprint(res.Summary) {
			fail("summary not stable:\n%+v\n%+v", res.Summary, again.Summary)
		}
	})

	run("Unroutable", func(fail func(string, ...any)) {
		g := newSuiteGuard()
		g.allow("198.51.100.0/24")
		d := newRecordingDialer(map[string]error{"198.51.100.20": syscall.ENETUNREACH})
		res, err := probe(context.Background(), g, d.dial, []string{"198.51.100.20"})
		if err != nil {
			fail("probe: %v", err)
			return
		}
		if res.Targets != 1 || res.Unreached != 1 || res.Reached != 0 || len(res.UnreachedList) != 1 || res.UnreachedList[0].Class != reach.NoRoute {
			fail("an unroutable target must be reported unreached (no_route): %+v %+v", res.Summary, res.UnreachedList)
		}
	})

	run("Canceled", func(fail func(string, ...any)) {
		g := newSuiteGuard()
		g.allow("192.0.2.0/24")
		d := newRecordingDialer(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, _ = probe(ctx, g, d.dial, []string{"192.0.2.0/24"})
		n := len(d.addrs())
		time.Sleep(300 * time.Millisecond)
		if m := len(d.addrs()); m != n {
			fail("dials went on after the probe returned (%d then %d)", n, m)
		}
		if n > 5 {
			fail("%d dials in 300 ms", n)
		}
	})
}

// suiteGuard admits addresses in allowed prefixes minus denied ones, and
// names by a fixed table (each of the name's addresses checked).
type suiteGuard struct {
	mu      sync.Mutex
	allowed []netip.Prefix
	denied  map[netip.Addr]bool
	names   map[string][]netip.Addr
	n       int
}

func newSuiteGuard() *suiteGuard {
	return &suiteGuard{denied: map[netip.Addr]bool{}, names: map[string][]netip.Addr{}}
}

func (g *suiteGuard) allow(prefixes ...string) {
	for _, p := range prefixes {
		g.allowed = append(g.allowed, netip.MustParsePrefix(p))
	}
}

func (g *suiteGuard) deny(addrs ...string) {
	for _, a := range addrs {
		g.denied[netip.MustParseAddr(a)] = true
	}
}

func (g *suiteGuard) admits(a netip.Addr) bool {
	a = a.Unmap()
	if g.denied[a] || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return false
	}
	for _, p := range g.allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (g *suiteGuard) checks() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

func (g *suiteGuard) AdmittedAddrs(_ context.Context, host string) ([]netip.Addr, error) {
	g.mu.Lock()
	g.n++
	g.mu.Unlock()
	addrs := g.names[host]
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs == nil {
		return nil, fmt.Errorf("cannot resolve %s", host)
	}
	for _, a := range addrs {
		if !g.admits(a) {
			return nil, fmt.Errorf("%s (%s) is not admitted", host, a)
		}
	}
	return addrs, nil
}

func (g *suiteGuard) CheckDial(ctx context.Context, _, address string) ([]net.IP, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := g.AdmittedAddrs(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IP(a.AsSlice()))
	}
	return out, nil
}

// recordingDialer records every dial and answers from errs (keyed by
// address; absent: the connection opens).
type recordingDialer struct {
	mu       sync.Mutex
	errs     map[string]error
	dialed   []netip.Addr
	at       []time.Time
	byName   int
	inFlight map[netip.Addr]int
	maxHost  int
}

func newRecordingDialer(errs map[string]error) *recordingDialer {
	return &recordingDialer{errs: errs, inFlight: map[netip.Addr]int{}}
}

func (d *recordingDialer) dial(ctx context.Context, _, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return nil, err
	}
	a, err := netip.ParseAddr(host)
	d.mu.Lock()
	if err != nil {
		d.byName++
		d.mu.Unlock()
		return nil, errors.New("dial by name")
	}
	a = a.Unmap()
	d.dialed = append(d.dialed, a)
	d.at = append(d.at, time.Now())
	d.inFlight[a]++
	d.maxHost = max(d.maxHost, d.inFlight[a])
	e := d.errs[a.String()]
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.inFlight[a]--
		d.mu.Unlock()
	}()
	select {
	case <-time.After(5 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e != nil {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: wrapSyscall(e)}
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func wrapSyscall(e error) error {
	var errno syscall.Errno
	if errors.As(e, &errno) {
		return os.NewSyscallError("connect", errno)
	}
	return e
}

func (d *recordingDialer) addrs() []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := slices.Clone(d.dialed)
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

func (d *recordingDialer) times() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.at)
}

func (d *recordingDialer) names() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.byName
}

func (d *recordingDialer) maxPerHost() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.maxHost
}
