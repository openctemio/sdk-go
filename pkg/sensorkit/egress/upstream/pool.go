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

// replyTimeoutLimit is the number of distinct target addresses whose
// CONNECT reply never came, through an endpoint that has carried no tunnel
// in the job, after which the endpoint is taken as hung (proxy_down) rather
// than every target as unreachable. Distinct addresses: a port scan of one
// filtered host times out on every port through a healthy proxy.
const replyTimeoutLimit = breakerThreshold

// maxSamples bounds the handshake times kept per endpoint.
const maxSamples = 256

// maxLastError bounds Report's last_error.
const maxLastError = 200

// Local score of an endpoint (job-local EWMA of what the sensor saw): the
// first pick of a host's sticky slot is weighted by the platform's weight
// times firstPickFloor + score², so a degraded endpoint still gets a little
// traffic (and so evidence) while a healthy one gets most new hosts.
const (
	// ewmaAlpha is the weight of the newest attempt.
	ewmaAlpha = 0.2
	// latencyRef is the handshake time that halves an endpoint's score.
	latencyRef = time.Second
	// firstPickFloor keeps every usable endpoint pickable.
	firstPickFloor = 0.05
	// maxSlots bounds the sticky slots one job keeps; hosts past it are
	// ranked by the rendezvous hash alone.
	maxSlots = 65536
)

// ErrEndpointBusy is the error of a connection that waited for a free
// connection of its endpoint (Endpoint.MaxConns) until its caller gave up.
var ErrEndpointBusy = errors.New("upstream: the proxy endpoint is at its connection limit")

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
	// rand draws the first pick of a sticky slot, in [0, 1).
	rand func() float64
}

// Pool is one job's view of a proxy pool: the Dial hook of the job's task
// forwarders. It is safe for concurrent use. Create it with New.
type Pool struct {
	cfg  Config
	opts Options

	mu    sync.Mutex
	state []endpointState
	// slots are the sticky slots: the endpoint each target host of the job
	// goes through. A slot is set by the first connection that succeeds
	// and moves only when its endpoint fails as a proxy (down, refusing
	// our credentials, breaker open), never on a target's answer.
	slots map[string]int
	// sem bounds each endpoint's open connections (Endpoint.MaxConns; nil:
	// no bound).
	sem []chan struct{}
}

type endpointState struct {
	// breaker
	consecutive int
	openUntil   time.Time
	backoff     time.Duration
	probing     bool
	authFailed  bool
	// replyTimeouts counts CONNECT replies that never came while no tunnel
	// through the endpoint has succeeded in the job; timeoutAddrs are their
	// distinct target addresses (at most replyTimeoutLimit).
	replyTimeouts int
	timeoutAddrs  []netip.Addr

	// local score: EWMA of the proxy's own outcomes (1 a tunnel, 0 down or
	// refusing our credentials; a target's answer says nothing about the
	// proxy) and of the handshake time.
	okRate  float64
	latency float64 // seconds, 0: none seen

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
	if opts.rand == nil {
		opts.rand = rand.Float64
	}
	p := &Pool{cfg: cfg, opts: opts, state: make([]endpointState, len(cfg.Endpoints)),
		slots: map[string]int{}, sem: make([]chan struct{}, len(cfg.Endpoints))}
	for i, e := range cfg.Endpoints {
		p.state[i].okRate = 1
		if e.MaxConns > 0 {
			p.sem[i] = make(chan struct{}, e.MaxConns)
		}
	}
	return p, nil
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
	// A target the job scoped by name goes to a socks5h endpoint by name:
	// the proxy resolves it (remote DNS). The forwarder has already checked
	// the name's addresses (none is denied, and an internal one is dialed
	// directly above when the pool applies to public targets only).
	name := ""
	if egress.TargetScopedByName(ctx) && validName(host) && len(host) <= maxSOCKSName {
		name = host
	}
	var last *egress.UpstreamError
	order, slot := p.order(host)
	for _, i := range order {
		ok, probe := p.acquire(i)
		if !ok {
			continue
		}
		e := p.endpoint(i)
		release, err := p.take(ctx, i)
		if err != nil {
			if probe {
				p.release(i)
			}
			return nil, &egress.UpstreamError{Class: egress.ClassProxyDown, Endpoint: e.ID, Final: true, Err: err}
		}
		byName := ""
		if e.Scheme == SchemeSOCKS5H {
			byName = name
		}
		actx, cancel := context.WithTimeout(ctx, p.opts.AttemptTimeout)
		start := p.opts.now()
		c, err := p.tunnel(actx, &e, target, byName)
		cancel()
		if err == nil {
			p.observe(i, probe, "", false, target.Addr(), p.opts.now().Sub(start), "")
			p.keepSlot(host, slot, i)
			return withRelease(c, release), nil
		}
		release()
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
		class = p.observe(i, probe, class, replyTimeout, target.Addr(), 0, err.Error())
		// A connection by name is decided for every address of the target:
		// the forwarder does not ask again for the next one.
		last = &egress.UpstreamError{Class: class, Endpoint: e.ID, Final: class != egress.ClassTargetUnreachable || byName != "", Err: cause}
		if class == egress.ClassTargetUnreachable {
			last.TargetClass = targetClass
		}
		// Only the proxy's own failures move on to the next endpoint: down,
		// or refusing our credentials (the endpoint is out for the rest of
		// the job and reported). A target's answer is the same through any
		// proxy and is never retried through another one.
		if class != egress.ClassProxyDown && class != egress.ClassProxyAuth {
			return nil, last
		}
	}
	if last == nil {
		return nil, &egress.UpstreamError{Class: egress.ClassProxyDown, Final: true, Err: ErrNoEndpoint}
	}
	// Every usable endpoint is down or refused our credentials: the
	// connection fails, never direct.
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
var ErrNoEndpoint error = noEndpointError{}

// noEndpointError is ErrNoEndpoint's type. It names its failure class for
// the sensor's failure report (core.FailureClassifier; core imports this
// package, so the method is structural).
type noEndpointError struct{}

func (noEndpointError) Error() string {
	return "upstream: no usable proxy endpoint (all down or refusing our credentials)"
}

// FailureClass is the class "infra.egress.pool_exhausted".
func (noEndpointError) FailureClass() (class, reason string) {
	return "infra.egress.pool_exhausted", "pool_all_down"
}

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

// order is the endpoints to try for a target host, and the host's sticky
// slot before this connection (-1: none). With the priority strategy it is
// rank. With sticky: the slot's endpoint first; a host without a slot gets
// a first pick drawn with weight Weight × (firstPickFloor + score²) among
// the usable endpoints (those with a free connection when any has one);
// the rest follow in rendezvous order for failover.
func (p *Pool) order(host string) ([]int, int) {
	idx := p.rank(host)
	if p.cfg.Strategy == StrategyPriority || len(idx) == 0 {
		return idx, -1
	}
	p.mu.Lock()
	slot, ok := p.slots[host]
	if !ok || p.state[slot].authFailed {
		slot = -1
	}
	first := slot
	if first < 0 {
		first = p.firstPick(idx)
	}
	p.mu.Unlock()
	if first < 0 {
		return idx, slot
	}
	out := make([]int, 0, len(idx))
	out = append(out, first)
	for _, i := range idx {
		if i != first {
			out = append(out, i)
		}
	}
	return out, slot
}

// firstPick draws an endpoint among idx with weight pickWeight; the
// endpoints whose breaker is open, and those at their connection limit
// while another has room, are left out. -1 when none is usable. Called
// with p.mu held.
func (p *Pool) firstPick(idx []int) int {
	now := p.opts.now()
	var cand []int
	var weights []float64
	total := 0.0
	for pass := 0; pass < 2 && total == 0; pass++ {
		cand, weights = cand[:0], weights[:0]
		for _, i := range idx {
			s := &p.state[i]
			if !s.openUntil.IsZero() && now.Before(s.openUntil) {
				continue
			}
			if pass == 0 && p.sem[i] != nil && len(p.sem[i]) >= cap(p.sem[i]) {
				continue
			}
			w := p.pickWeight(i)
			cand, weights = append(cand, i), append(weights, w)
			total += w
		}
	}
	if total <= 0 {
		return -1
	}
	r := p.opts.rand() * total
	for k, w := range weights {
		if r < w {
			return cand[k]
		}
		r -= w
	}
	return cand[len(cand)-1]
}

// pickWeight is endpoint i's first-pick weight: the platform's weight
// times firstPickFloor + score². Called with p.mu held.
func (p *Pool) pickWeight(i int) float64 {
	sc := p.score(i)
	return p.cfg.Endpoints[i].Weight * (firstPickFloor + sc*sc)
}

// score is endpoint i's local score in [0, 1]: the EWMA of its tunnels
// that came up, scaled down by its handshake time (latencyRef halves it).
// Called with p.mu held.
func (p *Pool) score(i int) float64 {
	s := &p.state[i]
	return s.okRate / (1 + s.latency/latencyRef.Seconds())
}

// keepSlot records that host's connection went through endpoint i. A host
// without a slot gets i; a host whose slot is another endpoint gets i only
// because that endpoint failed as a proxy or was unusable in this dial
// (the order tried the slot first and only a proxy failure moves on).
func (p *Pool) keepSlot(host string, slot, i int) {
	if p.cfg.Strategy == StrategyPriority {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cur, ok := p.slots[host]
	switch {
	case !ok && len(p.slots) < maxSlots:
		p.slots[host] = i
	case ok && cur == slot && cur != i:
		p.slots[host] = i
	}
}

// take waits for a free connection of endpoint i (Endpoint.MaxConns),
// bounded by ctx, and returns its release (idempotent).
func (p *Pool) take(ctx context.Context, i int) (func(), error) {
	sem := p.sem[i]
	if sem == nil {
		return func() {}, nil
	}
	select {
	case sem <- struct{}{}:
	default:
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (%d)", ErrEndpointBusy, cap(sem))
		}
	}
	var once sync.Once
	return func() { once.Do(func() { <-sem }) }, nil
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
// closing it, and once replyTimeoutLimit distinct target addresses timed
// out (or on a half-open probe) it is proxy_down: a proxy that accepts
// connections and never answers is quarantined like one that refuses them,
// and one filtered host scanned port by port is not.
func (p *Pool) observe(i int, wasProbe bool, class string, replyTimeout bool, target netip.Addr, handshake time.Duration, errMsg string) string {
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
		if !slices.Contains(s.timeoutAddrs, target) && len(s.timeoutAddrs) < replyTimeoutLimit {
			s.timeoutAddrs = append(s.timeoutAddrs, target)
		}
		if wasProbe || len(s.timeoutAddrs) >= replyTimeoutLimit {
			class = egress.ClassProxyDown
		}
	}
	switch class {
	case "":
		s.okRate += ewmaAlpha * (1 - s.okRate)
		if sec := handshake.Seconds(); s.latency == 0 {
			s.latency = sec
		} else {
			s.latency += ewmaAlpha * (sec - s.latency)
		}
	case egress.ClassProxyDown, egress.ClassProxyAuth:
		s.okRate -= ewmaAlpha * s.okRate
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
