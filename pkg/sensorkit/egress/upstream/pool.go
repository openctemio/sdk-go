package upstream

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis/addrscope"

	"github.com/openctemio/sdk-go/pkg/internal/absname"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// Breaker settings (job-local, per endpoint).
const (
	breakerThreshold = 3
	breakerBase      = 30 * time.Second
	breakerMax       = 10 * time.Minute
	breakerJitter    = 0.2
)

// replyTimeoutLimit is the number of CONNECT replies that never came,
// through an endpoint that has carried no tunnel in the job, after which
// the endpoint is taken as hung (proxy_down) rather than every target as
// unreachable.
const replyTimeoutLimit = breakerThreshold

// maxSamples bounds the handshake times kept per endpoint.
const maxSamples = 256

// maxLastError bounds Report's last_error.
const maxLastError = 200

// Options configure a Pool. Zero fields take the defaults.
type Options struct {
	// Key identifies the job (or the task) for sticky ranking: the same
	// key and target host rank the endpoints the same way.
	Key string
	// Allow is the sensor's allow list (ParseAllow); nil allows any
	// endpoint that passes validation.
	Allow Allow
	// AttemptTimeout bounds one attempt through one endpoint, within the
	// caller's context (0: 10s).
	AttemptTimeout time.Duration
	// RootCAs verify an https endpoint's certificate (nil: the system
	// roots). Verification is never off.
	RootCAs *x509.CertPool

	// Test hooks.
	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	now    func() time.Time
	jitter func() float64 // in [0, 1)
}

// Pool is one job's view of a proxy pool: the Dial hook of the job's task
// forwarders. It is safe for concurrent use. Create it with New.
type Pool struct {
	cfg  Config
	opts Options

	mu    sync.Mutex
	state []endpointState
}

type endpointState struct {
	// breaker
	consecutive int
	openUntil   time.Time
	backoff     time.Duration
	probing     bool
	authFailed  bool
	// replyTimeouts counts CONNECT replies that never came while no tunnel
	// through the endpoint has succeeded in the job.
	replyTimeouts int

	// stats
	ok, down, auth, unreach, refused int64
	samples                          []time.Duration
	next                             int
	lastErr                          string
}

// New validates cfg (Config.Validate with opts.Allow) and returns its
// pool. Credentials are taken from cfg's endpoints (SetCredentials sets
// them later).
func New(cfg Config, opts Options) (*Pool, error) {
	cfg.Endpoints = slices.Clone(cfg.Endpoints)
	if err := cfg.Validate(opts.Allow); err != nil {
		return nil, err
	}
	if opts.AttemptTimeout <= 0 {
		opts.AttemptTimeout = 10 * time.Second
	}
	if opts.dialer == nil {
		d := &net.Dialer{}
		opts.dialer = d.DialContext
	}
	if opts.lookup == nil {
		opts.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", absname.Of(host))
		}
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.jitter == nil {
		opts.jitter = rand.Float64
	}
	return &Pool{cfg: cfg, opts: opts, state: make([]endpointState, len(cfg.Endpoints))}, nil
}

// Credential is one endpoint's credentials.
type Credential struct {
	EndpointID string
	Username   string
	Password   string
}

// SetCredentials gives endpoints their credentials (by endpoint id; ids
// the pool does not have are ignored). Call it before the first Dial.
func (p *Pool) SetCredentials(creds []Credential) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range creds {
		if len(c.Username) > maxCredential || len(c.Password) > maxCredential || hasControl(c.Username) || hasControl(c.Password) {
			return errors.New("upstream: credentials too long or with control characters")
		}
		for i := range p.cfg.Endpoints {
			if p.cfg.Endpoints[i].ID == c.EndpointID {
				p.cfg.Endpoints[i].Username, p.cfg.Endpoints[i].Password = c.Username, c.Password
			}
		}
	}
	return nil
}

// PoolID is the pool's id.
func (p *Pool) PoolID() string { return p.cfg.PoolID }

// Dial is egress.Forwarder.Dial: addr is the IP and port the forwarder's
// scope check allowed. The target host for sticky ranking comes from
// egress.TargetHost(ctx). Errors are *egress.UpstreamError.
func (p *Pool) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	target, err := netip.ParseAddrPort(addr)
	if err != nil || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, &egress.UpstreamError{Class: egress.ClassTargetRefused, Final: true,
			Err: fmt.Errorf("upstream: %s %q is not a TCP address and port", network, addr)}
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if p.cfg.AppliesTo == AppliesPublic && !isPublic(target.Addr()) {
		// The organization's default pool is for public targets; the
		// forwarder already admitted this internal one.
		return p.opts.dialer(ctx, "tcp", target.String())
	}
	host := egress.TargetHost(ctx)
	if host == "" {
		host = target.Addr().String()
	}
	var last *egress.UpstreamError
	for _, i := range p.rank(host) {
		ok, probe := p.acquire(i)
		if !ok {
			continue
		}
		e := p.endpoint(i)
		actx, cancel := context.WithTimeout(ctx, p.opts.AttemptTimeout)
		start := p.opts.now()
		c, err := p.tunnel(actx, &e, target)
		cancel()
		if err == nil {
			p.observe(i, probe, "", false, p.opts.now().Sub(start), "")
			return c, nil
		}
		class, cause, replyTimeout := egress.ClassProxyDown, err, false
		var targetClass reach.Class
		var ae *attemptError
		if errors.As(err, &ae) {
			class, cause, replyTimeout, targetClass = ae.class, ae.err, ae.replyTimeout, ae.target
		}
		if callerDone(ctx) {
			// The caller gave up (the task ended or its dial timed out):
			// nothing is learned about the endpoint.
			if probe {
				p.release(i)
			}
			return nil, &egress.UpstreamError{Class: class, Endpoint: e.ID, Final: true, Err: cause}
		}
		class = p.observe(i, probe, class, replyTimeout, 0, err.Error())
		last = &egress.UpstreamError{Class: class, Endpoint: e.ID, Final: class != egress.ClassTargetUnreachable, Err: cause}
		if class == egress.ClassTargetUnreachable {
			last.TargetClass = targetClass
		}
		if class != egress.ClassProxyDown {
			return nil, last
		}
	}
	if last == nil {
		return nil, &egress.UpstreamError{Class: egress.ClassProxyDown, Final: true, Err: ErrNoEndpoint}
	}
	// Every usable endpoint is down: the connection fails, never direct.
	last.Final = true
	return nil, last
}

// callerDone reports whether the caller's context has ended, its deadline
// included: the connection's I/O deadline is the context's, so a read can
// time out a moment before the context's own timer marks it done.
func callerDone(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	d, ok := ctx.Deadline()
	return ok && !time.Now().Before(d)
}

// ErrNoEndpoint is the error of a connection when no endpoint is usable
// (each one's breaker is open or it refused our credentials).
var ErrNoEndpoint = errors.New("upstream: no usable proxy endpoint (all down or refusing our credentials)")

// isPublic reports whether a target address is public: not private, ULA,
// CGNAT, loopback or any other internal range (ctis addrscope).
func isPublic(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !addrscope.IsInternal(a)
}

func (p *Pool) endpoint(i int) Endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Endpoints[i]
}

// rank orders the endpoints for a target host: by weighted rendezvous
// hash for sticky (lowest -ln(u)/w first), in the given order for
// priority. Endpoints that refused our credentials are left out.
func (p *Pool) rank(host string) []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := make([]int, 0, len(p.cfg.Endpoints))
	for i := range p.cfg.Endpoints {
		if !p.state[i].authFailed {
			idx = append(idx, i)
		}
	}
	if p.cfg.Strategy == StrategyPriority {
		return idx
	}
	scores := make(map[int]float64, len(idx))
	for _, i := range idx {
		e := p.cfg.Endpoints[i]
		scores[i] = -math.Log(unitHash(p.opts.Key, host, e.ID)) / e.Weight
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		switch {
		case scores[a] < scores[b]:
			return -1
		case scores[a] > scores[b]:
			return 1
		}
		return strings.Compare(p.cfg.Endpoints[a].ID, p.cfg.Endpoints[b].ID)
	})
	return idx
}

// unitHash maps (key, host, endpoint id) to (0, 1).
func unitHash(key, host, id string) float64 {
	h := sha256.New()
	for _, s := range []string{key, host, id} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint64(sum[:8]) >> 11 // 53 bits
	return (float64(v) + 0.5) / (1 << 53)
}

// acquire reports whether endpoint i may be tried now: its breaker is
// closed, or it is due for its one half-open probe (probe: this call
// took it).
func (p *Pool) acquire(i int) (ok, probe bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &p.state[i]
	if s.authFailed {
		return false, false
	}
	if s.openUntil.IsZero() {
		return true, false
	}
	if s.probing || p.opts.now().Before(s.openUntil) {
		return false, false
	}
	s.probing = true
	return true, true
}

// release gives back a probe that learned nothing.
func (p *Pool) release(i int) {
	p.mu.Lock()
	p.state[i].probing = false
	p.mu.Unlock()
}

// observe counts one attempt through endpoint i, moves its breaker and
// returns the attempt's class. A CONNECT reply that never came
// (replyTimeout) is about the target while the endpoint has carried a
// tunnel in the job. Before that it counts towards the breaker without
// closing it, and from the replyTimeoutLimit-th one (or on a half-open
// probe) it is proxy_down: a proxy that accepts connections and never
// answers is quarantined like one that refuses them.
func (p *Pool) observe(i int, wasProbe bool, class string, replyTimeout bool, handshake time.Duration, errMsg string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &p.state[i]
	if wasProbe {
		s.probing = false
	}
	hung := false
	if replyTimeout && s.ok == 0 {
		s.replyTimeouts++
		hung = true
		if wasProbe || s.replyTimeouts >= replyTimeoutLimit {
			class = egress.ClassProxyDown
		}
	}
	switch class {
	case "":
		s.ok++
		if len(s.samples) < maxSamples {
			s.samples = append(s.samples, handshake)
		} else {
			s.samples[s.next] = handshake
			s.next = (s.next + 1) % maxSamples
		}
	case egress.ClassProxyDown:
		s.down++
	case egress.ClassProxyAuth:
		s.auth++
		s.authFailed = true
	case egress.ClassTargetUnreachable:
		s.unreach++
	case egress.ClassTargetRefused:
		s.refused++
	}
	if errMsg != "" {
		s.lastErr = sanitize(class, errMsg, p.cfg.Endpoints[i])
	}
	if hung && class != egress.ClassProxyDown {
		// Not yet taken as hung: counted towards the breaker, which only
		// a proxy_down opens.
		s.consecutive++
		return class
	}
	if class != egress.ClassProxyDown {
		// The proxy answered: it is up.
		s.consecutive, s.openUntil, s.backoff = 0, time.Time{}, 0
		return class
	}
	s.consecutive++
	if wasProbe || s.consecutive >= breakerThreshold {
		switch {
		case s.backoff == 0:
			s.backoff = breakerBase
		case wasProbe:
			s.backoff = min(2*s.backoff, breakerMax)
		}
		j := 1 + breakerJitter*(2*p.opts.jitter()-1)
		s.openUntil = p.opts.now().Add(time.Duration(float64(s.backoff) * j))
	}
	return class
}

// Report is the body of the job's egress report (POST
// /commands/{id}/egress-report).
type Report struct {
	PoolID    string           `json:"pool_id"`
	Endpoints []EndpointReport `json:"endpoints"`
}

// EndpointReport is one endpoint's signals over the job.
type EndpointReport struct {
	EndpointID        string `json:"endpoint_id"`
	OK                int64  `json:"ok"`
	ProxyDown         int64  `json:"proxy_down"`
	ProxyAuth         int64  `json:"proxy_auth"`
	TargetUnreachable int64  `json:"target_unreachable"`
	TargetRefused     int64  `json:"target_refused"`
	HandshakeMsP50    int64  `json:"handshake_ms_p50"`
	HandshakeMsP95    int64  `json:"handshake_ms_p95"`
	LastError         string `json:"last_error"`
}

// Used reports whether any connection attempt went through an endpoint.
func (r Report) Used() bool {
	for _, e := range r.Endpoints {
		if e.OK+e.ProxyDown+e.ProxyAuth+e.TargetUnreachable+e.TargetRefused > 0 {
			return true
		}
	}
	return false
}

// Report returns the signals so far: every endpoint that saw an attempt
// (at most MaxEndpoints).
func (p *Pool) Report() Report {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := Report{PoolID: p.cfg.PoolID, Endpoints: []EndpointReport{}}
	for i, s := range p.state {
		if s.ok+s.down+s.auth+s.unreach+s.refused == 0 {
			continue
		}
		p50, p95 := percentiles(s.samples)
		r.Endpoints = append(r.Endpoints, EndpointReport{EndpointID: p.cfg.Endpoints[i].ID, OK: s.ok, ProxyDown: s.down,
			ProxyAuth: s.auth, TargetUnreachable: s.unreach, TargetRefused: s.refused,
			HandshakeMsP50: p50, HandshakeMsP95: p95, LastError: s.lastErr})
	}
	return r
}

func percentiles(samples []time.Duration) (p50, p95 int64) {
	if len(samples) == 0 {
		return 0, 0
	}
	s := slices.Clone(samples)
	slices.Sort(s)
	at := func(q float64) int64 {
		i := int(math.Ceil(q*float64(len(s)))) - 1
		return s[max(0, min(i, len(s)-1))].Milliseconds()
	}
	return at(0.50), at(0.95)
}

var userinfoURL = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]*@`)

// sanitize bounds an error message for a report or a log: no userinfo in a
// URL, no credential of the endpoint, no control characters, at most
// maxLastError bytes. The messages are built from endpoint names
// (scheme://host:port) and network errors only; this is a second guard.
func sanitize(class, msg string, e Endpoint) string {
	msg = userinfoURL.ReplaceAllString(msg, "${1}")
	for _, secret := range []string{e.Password, e.Username} {
		if len(secret) >= 3 {
			msg = strings.ReplaceAll(msg, secret, "[redacted]")
		}
	}
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if class != "" && !strings.HasPrefix(msg, class) {
		msg = class + ": " + msg
	}
	if len(msg) > maxLastError {
		msg = strings.ToValidUTF8(msg[:maxLastError], "")
	}
	return msg
}
