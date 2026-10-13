package reach

import (
	"context"
	"encoding/binary"
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

// Probe bounds. A probe is active work (it opens connections to targets),
// so it is small and polite whatever the caller asks for.
const (
	// MaxProbeRate is the most connects per second one probe opens.
	MaxProbeRate = 10
	// MaxProbeAddrs is the most addresses one probe touches.
	MaxProbeAddrs = 256
	// MaxProbePorts is the most ports tried per address.
	MaxProbePorts = 8
	// DefaultProbeTimeout is one connect's timeout.
	DefaultProbeTimeout = 2 * time.Second
	// maxProbeTimeout caps ProbeOptions.Timeout.
	maxProbeTimeout = 10 * time.Second
	// probeWorkers is how many addresses are probed at once (each one
	// connect at a time).
	probeWorkers = 4
)

// DefaultProbePorts are tried when ProbeOptions.Ports is empty.
var DefaultProbePorts = []int{443, 80, 22}

// ErrNoGuard is returned by Probe without a guard: a probe never dials
// what no policy checked.
var ErrNoGuard = errors.New("reach: a probe needs the sensor's guarded dialer")

// Guard is the sensor's target guard (core.LocalPolicy satisfies it): the
// local policy, the built-in deny list and pinned addresses.
type Guard interface {
	// AdmittedAddrs checks a host name or address and returns the
	// addresses it may be reached at (a name is resolved once, here).
	AdmittedAddrs(ctx context.Context, host string) ([]netip.Addr, error)
	// CheckDial checks a connection to "host:port" and returns the
	// addresses it may use.
	CheckDial(ctx context.Context, network, address string) ([]net.IP, error)
}

// DialFunc opens a connection (net.Dialer.DialContext's shape).
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ProbeOptions tune a probe; every value is capped by the bounds above.
type ProbeOptions struct {
	// Ports to try per address (default DefaultProbePorts; at most
	// MaxProbePorts, each 1-65535). An address is reached once one port
	// answers; the others are not tried.
	Ports []int
	// Timeout of one connect (default and cap: DefaultProbeTimeout,
	// maxProbeTimeout).
	Timeout time.Duration
	// Rate is connects per second (default and cap MaxProbeRate).
	Rate float64
	// MaxAddrs is the most addresses probed (default and cap MaxProbeAddrs).
	MaxAddrs int
	// Dial opens a connection to an address literal (default net.Dialer).
	Dial DialFunc
	// Recorder also receives every outcome (the job's recorder; nil: only
	// the result has them).
	Recorder *Recorder
}

// ProbeResult is what a probe saw.
type ProbeResult struct {
	Report
	// Probed counts the addresses probed.
	Probed int `json:"probed"`
	// NotProbed counts admitted addresses left out by MaxAddrs.
	NotProbed int `json:"not_probed,omitempty"`
	// Refused lists targets the guard refused (never dialed), at most
	// MaxUnreachedListed; RefusedTotal counts all.
	Refused      []string `json:"refused,omitempty"`
	RefusedTotal int      `json:"refused_total,omitempty"`
}

// probeAddr is one address to probe and the target it came from.
type probeAddr struct {
	target string
	addr   netip.Addr
}

// Probe tests whether this sensor reaches targets: one TCP connect per
// (address, port) until one answers, no payload, no ICMP. Every target is
// a job target the platform admitted; each is checked again by guard, and
// only the addresses guard returns are dialed, by address, never by name.
// A range is expanded address by address, each checked. At most
// MaxProbeAddrs addresses, MaxProbeRate connects per second and one
// connect per address at a time.
func Probe(ctx context.Context, guard Guard, targets []string, opts ProbeOptions) (ProbeResult, error) {
	if guard == nil {
		return ProbeResult{}, ErrNoGuard
	}
	opts, err := opts.normalized()
	if err != nil {
		return ProbeResult{}, err
	}
	rec := NewRecorder()
	res := ProbeResult{}
	addrs, err := admitted(ctx, guard, targets, opts.MaxAddrs, &res)
	if err != nil {
		return res, err
	}
	limiter := rate.NewLimiter(rate.Limit(opts.Rate), 1)
	work := make(chan probeAddr)
	var wg sync.WaitGroup
	for range min(probeWorkers, len(addrs)) {
		wg.Go(func() {
			for pa := range work {
				probeOne(ctx, guard, limiter, opts, pa, rec)
			}
		})
	}
	for _, pa := range addrs {
		if ctx.Err() != nil {
			break
		}
		select {
		case work <- pa:
			res.Probed++
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	res.Report = rec.Report()
	return res, ctx.Err()
}

func (o ProbeOptions) normalized() (ProbeOptions, error) {
	if len(o.Ports) == 0 {
		o.Ports = DefaultProbePorts
	}
	if len(o.Ports) > MaxProbePorts {
		return o, fmt.Errorf("reach: at most %d probe ports, got %d", MaxProbePorts, len(o.Ports))
	}
	for _, p := range o.Ports {
		if p < 1 || p > 65535 {
			return o, fmt.Errorf("reach: probe port %d is not valid", p)
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultProbeTimeout
	}
	o.Timeout = min(o.Timeout, maxProbeTimeout)
	if o.Rate <= 0 || o.Rate > MaxProbeRate {
		o.Rate = MaxProbeRate
	}
	if o.MaxAddrs <= 0 || o.MaxAddrs > MaxProbeAddrs {
		o.MaxAddrs = MaxProbeAddrs
	}
	if o.Dial == nil {
		d := &net.Dialer{}
		o.Dial = d.DialContext
	}
	return o, nil
}

// maxRangeChecks bounds the guard checks a probe makes while expanding
// ranges, so a large range the guard refuses is not walked to its end.
const maxRangeChecks = 4 * MaxProbeAddrs

// admitted turns targets into the addresses guard admits, at most limit;
// refused targets and addresses left out are counted in res.
func admitted(ctx context.Context, guard Guard, targets []string, limit int, res *ProbeResult) ([]probeAddr, error) {
	var out []probeAddr
	seen := map[netip.Addr]bool{}
	refuse := func(t string) {
		res.RefusedTotal++
		if len(res.Refused) < MaxUnreachedListed {
			res.Refused = append(res.Refused, cleanText(t, maxTargetLen))
		}
	}
	add := func(target string, addrs []netip.Addr) {
		for _, a := range addrs {
			a = a.Unmap()
			if !a.IsValid() || seen[a] {
				continue
			}
			seen[a] = true
			if len(out) >= limit {
				res.NotProbed++
				continue
			}
			out = append(out, probeAddr{target: target, addr: a})
		}
	}
	checks := 0
	for _, raw := range targets {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		t := strings.TrimSpace(raw)
		if p, err := netip.ParsePrefix(t); err == nil {
			// A range: every address is checked on its own (an exclusion
			// or deny entry inside the range is never dialed).
			p = p.Masked()
			refused := 0
			for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
				if len(out) >= limit || checks >= maxRangeChecks {
					res.NotProbed += rangeRemaining(p, a)
					break
				}
				checks++
				ok, err := guard.AdmittedAddrs(ctx, a.String())
				if err != nil || !slices.Contains(unmapAll(ok), a) {
					refused++
					continue
				}
				// Each address of a range is a target of its own.
				add(a.String(), []netip.Addr{a})
			}
			if refused > 0 {
				refuse(fmt.Sprintf("%s (%d addresses)", t, refused))
			}
			continue
		}
		host := hostOf(t)
		if host == "" {
			refuse(t)
			continue
		}
		addrs, err := guard.AdmittedAddrs(ctx, host)
		if err != nil || len(addrs) == 0 {
			refuse(t)
			continue
		}
		add(t, addrs)
	}
	return out, nil
}

// rangeRemaining counts the addresses of p from a on (capped at 2^30).
func rangeRemaining(p netip.Prefix, a netip.Addr) int {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 30 {
		return 1 << 30
	}
	size := 1 << hostBits
	off := int((low32(a) - low32(p.Addr())) & uint32(size-1)) //nolint:gosec // size <= 2^29
	return size - off
}

// low32 is the low 32 bits of a.
func low32(a netip.Addr) uint32 {
	b := a.As16()
	return binary.BigEndian.Uint32(b[12:])
}

func unmapAll(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap()
	}
	return out
}

// hostOf returns the host of a target: a URL's host, "host:port"'s host,
// a bracketed IPv6 address, or the target itself.
func hostOf(t string) string {
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
		if k := strings.LastIndex(t, "@"); k >= 0 {
			t = t[k+1:]
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return strings.Trim(t, "[]")
}

// probeOne tries the ports of one address in order until one answers.
func probeOne(ctx context.Context, guard Guard, limiter *rate.Limiter, opts ProbeOptions, pa probeAddr, rec *Recorder) {
	for _, port := range opts.Ports {
		address := net.JoinHostPort(pa.addr.String(), strconv.Itoa(port))
		// The guard checks the connection itself too (ports.allow, a
		// policy reloaded since admission); only the exact address it
		// returns is dialed.
		ips, err := guard.CheckDial(ctx, "tcp", address)
		if err != nil || !containsIP(ips, pa.addr) {
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			return
		}
		dctx, cancel := context.WithTimeout(ctx, opts.Timeout)
		conn, err := opts.Dial(dctx, "tcp", address)
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return
		}
		c := rec.RecordErr(pa.target, pa.addr, port, err)
		opts.Recorder.RecordErr(pa.target, pa.addr, port, err)
		if c.PathWorks() || c == NoRoute {
			// Reached, or certain that this sensor has no route: other
			// ports add nothing.
			return
		}
	}
}

func containsIP(ips []net.IP, a netip.Addr) bool {
	for _, ip := range ips {
		if b, ok := netip.AddrFromSlice(ip); ok && b.Unmap() == a.Unmap() {
			return true
		}
	}
	return false
}
