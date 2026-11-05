// Package webdiff is the calibrated differ of path and parameter discovery:
// it tells a response that shows something exists apart from the many ways
// a web server answers "nothing here" (a 404, a soft-404 page that answers
// 200, a single-page app that serves its index for every path, a wildcard
// API subtree, a login wall, a firewall rule that blocks a keyword).
//
// A Prober works on one origin (scheme://host[:port]) for one task. For each
// class of candidate (its directory and its shape: bare, slash, a file
// extension, a dot file) it first requests three random names, keeps their
// signatures (Sig: status, redirect pattern, content-type family, length,
// words, lines, title, header names, simhash of the normalised body) and
// derives a noise band. A candidate is a hit only when its answer differs
// from that baseline beyond the band, the difference repeats, and, for a
// directory or a 403, a random child of it answers like a missing path.
//
// Safety:
//   - every request is a GET of a path of the origin; redirects are never
//     followed (the Location is only read as a pattern), so a redirect to
//     an internal address or another host is never requested;
//   - a body is read up to MaxBody bytes; a gzip body is decoded by the
//     prober with the expansion ratio bounded; headers are bounded; the
//     whole exchange has a deadline and the body a minimum transfer rate.
//     An answer that breaks a bound stops the origin (hostile_response);
//   - an edge challenge or block (contract edgeprotect) is never a signal
//     and stops the origin (edge_protected); 429 and 503 back off and are
//     retried at most Retries times, never a hit;
//   - baselines live in the Prober, which lives for one task: nothing is
//     cached across tasks, so one task's probes never shape another's;
//   - nothing of a body leaves the package but its size and a 64-bit hash
//     of its normalised text.
//
// The client is used as given apart from its redirect policy: on a sensor
// it is the task's tool.Context.HTTP client, so the job's web scope, its
// request cap, the address pinning and the pacing of the task forwarder
// apply to every request.
//
// Stability: Experimental (docs/STABILITY.md).
package webdiff

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/contract/edgeprotect"
	"golang.org/x/time/rate"
)

// Gap reasons: why an origin, or some of its candidates, was not covered.
const (
	// GapCatchAll: the origin answers every path with its index page; bare
	// and directory candidates were skipped (file shapes still ran).
	GapCatchAll = "catch_all"
	// GapAuthWall: the origin redirects every path to a login page or
	// answers 401; an authenticated run would see more.
	GapAuthWall = "auth_wall"
	// GapEdgeProtected: an edge protection (WAF, CDN) challenged or
	// blocked the requests; the origin was stopped.
	GapEdgeProtected = "edge_protected"
	// GapThrottled: the origin kept answering 429 or 503; the origin was
	// stopped.
	GapThrottled = "throttled"
	// GapBlocked: the origin stopped answering (resets, timeouts); the
	// origin was stopped.
	GapBlocked = "blocked"
	// GapUnstableBaseline: a class's random names did not answer alike;
	// its candidates were skipped.
	GapUnstableBaseline = "unstable_baseline"
	// GapBudget: the request budget ran out before the candidates did.
	GapBudget = "budget"
	// GapHostileResponse: an answer broke a bound (decompression bomb,
	// huge headers, a body slower than the minimum rate or the deadline);
	// the origin was stopped.
	GapHostileResponse = "hostile_response"
	// GapProtocol: the origin does not speak HTTP/1.1; the origin was
	// stopped.
	GapProtocol = "protocol"
	// GapScopeFiltered: candidates the job's web scope refused (or that
	// name a state-changing action) and that were never requested.
	GapScopeFiltered = "scope_filtered"
)

// Verdict is the reading of a candidate's answer against its class's
// baseline.
type Verdict string

// Verdicts.
const (
	Same      Verdict = "same"
	Different Verdict = "different"
	// NoSignal: the answer says nothing about the path (an edge page, a
	// rate limit, a network error, a refusal by the sensor).
	NoSignal Verdict = "no_signal"
)

// Auth states of a hit.
const (
	AuthNone          = "none"
	AuthRequired      = "required"
	AuthRedirectLogin = "redirect_login"
)

// Labels of a hit.
const (
	LabelDirectory        = "directory"
	LabelForbidden        = "status:forbidden"
	LabelError            = "status:error"
	LabelRedirect         = "status:redirect"
	LabelMethodNotAllowed = "status:method_not_allowed"
)

// Defaults of Options.
const (
	DefaultMaxBody        = 256 << 10
	DefaultMaxHeaderBytes = 64 << 10
	DefaultDeadline       = 10 * time.Second
	DefaultMinRate        = 512
	DefaultMinRateAfter   = 2 * time.Second
	DefaultMaxRatio       = 100
	DefaultRetries        = 2
	DefaultRate           = 5
	// MaxRate bounds Options.Rate: a config value above it is lowered to it.
	MaxRate = 50
	// FrontedRate is the rate of an origin an edge network fronts (the first
	// answer that carries an edge marker lowers the limiter to it).
	FrontedRate             = 2
	DefaultRecalibrate      = 200
	DefaultMinBackoff       = time.Second
	DefaultMaxBackoff       = 30 * time.Second
	baselineSamples         = 3
	nameLen                 = 12
	maxConsecutiveFailures  = 5
	maxConsecutiveThrottled = 3
)

// Options bound a Prober. Zero values take the defaults.
type Options struct {
	// MaxRequests is the most requests the prober sends to the origin,
	// calibration and confirmation included (0: no cap of its own; the
	// job's web scope still caps the task).
	MaxRequests int
	// Rate is the most requests per second (default 5, at most MaxRate; an
	// origin an edge network fronts is held to FrontedRate).
	Rate float64
	// MaxBody is the most decoded body bytes read per answer (256 KiB).
	MaxBody int
	// MaxHeaderBytes bounds an answer's headers (64 KiB). The client's
	// transport should bound them too (http.Transport
	// MaxResponseHeaderBytes): this check runs after they were read.
	MaxHeaderBytes int
	// Deadline bounds one whole exchange, headers and body (10 s).
	Deadline time.Duration
	// MinRate is the slowest body, in bytes per second, accepted once
	// MinRateAfter has passed (512 B/s after 2 s).
	MinRate      int
	MinRateAfter time.Duration
	// MaxRatio is the largest expansion of a gzip body (100:1).
	MaxRatio int
	// Retries is how many times a 429, a 503 or a network error is
	// retried (2).
	Retries int
	// MinBackoff and MaxBackoff bound the wait before a retry (1 s, 30 s;
	// a Retry-After within them is used).
	MinBackoff, MaxBackoff time.Duration
	// RecalibrateAfter is how many requests a baseline serves before it is
	// taken again (200).
	RecalibrateAfter int
	// Rand is the source of the random names (crypto/rand).
	Rand io.Reader
}

func (o Options) withDefaults() Options {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&o.MaxBody, DefaultMaxBody)
	def(&o.MaxHeaderBytes, DefaultMaxHeaderBytes)
	def(&o.MinRate, DefaultMinRate)
	def(&o.MaxRatio, DefaultMaxRatio)
	def(&o.RecalibrateAfter, DefaultRecalibrate)
	if o.Retries < 0 {
		o.Retries = 0
	} else if o.Retries == 0 {
		o.Retries = DefaultRetries
	}
	if o.Rate <= 0 {
		o.Rate = DefaultRate
	}
	o.Rate = min(o.Rate, MaxRate)
	if o.Deadline <= 0 {
		o.Deadline = DefaultDeadline
	}
	if o.MinRateAfter <= 0 {
		o.MinRateAfter = DefaultMinRateAfter
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = DefaultMinBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultMaxBackoff
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = o.MinBackoff
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	return o
}

// Hit is a confirmed path: what discovery reports. It carries no body,
// title or header value.
type Hit struct {
	// Path is the path as requested (escaped).
	Path string
	// Status, ContentType, Size and Hash are the evidence of the answer:
	// its status, media type, decoded body bytes read and the 64-bit hash
	// of its normalised body (16 hex).
	Status      int
	ContentType string
	Size        int
	Hash        string
	// Auth is none, required or redirect_login.
	Auth string
	// Labels are LabelDirectory and the status labels.
	Labels []string
}

// Result is the outcome of one candidate.
type Result struct {
	Verdict Verdict
	// Hit is the confirmed hit (nil when the candidate is not one).
	Hit *Hit
	// Skipped is the gap reason when the candidate was not requested
	// (catch_all, unstable_baseline, scope_filtered).
	Skipped string
}

// ErrStopped is returned for every candidate once the origin is stopped;
// Prober.Stopped names the reason.
var ErrStopped = errors.New("webdiff: the origin is stopped")

// errBudget is the prober's own request budget running out.
var errBudget = errors.New("webdiff: request budget spent")

// Prober probes the candidates of one origin for one task. It is not safe
// for concurrent use.
type Prober struct {
	client  *http.Client
	origin  *url.URL
	o       Options
	limiter *rate.Limiter
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error

	classes map[classKey]*class
	// gen is the calibration generation; a class of an older one is taken
	// again before its next use.
	gen              int
	requests         int
	sinceCalibration int
	checks           int
	unexpected       int
	failures         int
	throttled        int

	root     *Sig
	catchAll bool
	stopped  string
	gaps     map[string]int
	foldCase bool
}

// New returns the prober of origin ("https://app.example.com[:port]"; a
// path, query or credentials in it are refused). client is copied with
// redirects off.
func New(client *http.Client, origin string, o Options) (*Prober, error) {
	if client == nil {
		return nil, errors.New("webdiff: no client")
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("webdiff: %q is not an origin", clip(origin, 128))
	}
	u.Path, u.RawPath = "", ""
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.Jar = nil
	o = o.withDefaults()
	p := &Prober{client: &c, origin: u, o: o, classes: map[classKey]*class{}, gaps: map[string]int{},
		limiter: rate.NewLimiter(rate.Limit(o.Rate), 1), now: time.Now}
	p.sleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	return p, nil
}

// Origin is the origin probed.
func (p *Prober) Origin() string { return p.origin.String() }

// Requests is how many requests the prober sent.
func (p *Prober) Requests() int { return p.requests }

// Stopped is why the origin was stopped ("" while it runs): one of the gap
// reasons.
func (p *Prober) Stopped() string { return p.stopped }

// Gaps are the gap reasons met so far, each with the number of candidates
// it concerned (1 for an origin-wide reason).
func (p *Prober) Gaps() map[string]int {
	out := make(map[string]int, len(p.gaps))
	for k, v := range p.gaps {
		out[k] = v
	}
	return out
}

// AddGap records a gap reason the caller met (n candidates; for example
// GapScopeFiltered for candidates it never handed over).
func (p *Prober) AddGap(reason string, n int) {
	if n > 0 {
		p.gaps[reason] += n
	}
}

// FoldsCase reports whether the origin was found to ignore the case of a
// path (CaseInsensitive).
func (p *Prober) FoldsCase() bool { return p.foldCase }

func (p *Prober) stop(reason string) error {
	if p.stopped == "" {
		p.stopped = reason
		p.gaps[reason]++
	}
	return ErrStopped
}

// Canary opens an origin: GET / (an edge challenge or block there stops the
// origin, edge_protected, and is returned before anything else is sent),
// then the root's bare baseline. A login redirect or a 401 records
// auth_wall; a random path that answers like / makes the origin catch-all
// (its bare and directory candidates are skipped, file shapes still run).
func (p *Prober) Canary(ctx context.Context) (edgeprotect.Verdict, error) {
	r, err := p.fetchRetry(ctx, "/", nil)
	if err != nil {
		return edgeprotect.Verdict{State: edgeprotect.Direct}, err
	}
	if r.edge.State.Stops() {
		return r.edge, p.stop(GapEdgeProtected)
	}
	if r.refused != "" {
		return r.edge, p.refusal(r)
	}
	s := r.sig
	p.root = &s
	if s.Status == http.StatusUnauthorized || (isRedirect(s.Status) && loginPattern(s.Location)) {
		p.gaps[GapAuthWall] = max(p.gaps[GapAuthWall], 1)
	}
	// The root's bare baseline tells a catch-all origin (a random path
	// answers like /) and a login wall before any candidate runs.
	if _, err := p.class(ctx, "/", ShapeBare); err != nil {
		return r.edge, err
	}
	return r.edge, nil
}

// Check probes one candidate path (escaped, starting with "/", no query):
// it calibrates the candidate's class when needed, requests the path,
// compares the answer, and confirms a difference before it reports a hit.
// It returns ErrStopped once the origin is stopped.
func (p *Prober) Check(ctx context.Context, cand string) (Result, error) {
	if p.stopped != "" {
		return Result{}, ErrStopped
	}
	if !strings.HasPrefix(cand, "/") || strings.ContainsAny(cand, "?#") || len(cand) > 2048 {
		return Result{}, fmt.Errorf("webdiff: %q is not a candidate path", clip(cand, 128))
	}
	p.maybeRecalibrate()
	dir, name, shape := Split(cand)
	if p.catchAll && (shape == ShapeBare || shape == ShapeSlash) {
		p.gaps[GapCatchAll]++
		return Result{Skipped: GapCatchAll}, nil
	}
	c, err := p.class(ctx, dir, shape)
	if err != nil {
		return Result{}, err
	}
	if p.catchAll && (shape == ShapeBare || shape == ShapeSlash) {
		p.gaps[GapCatchAll]++
		return Result{Skipped: GapCatchAll}, nil
	}
	if c.skip != "" {
		p.gaps[c.skip]++
		return Result{Skipped: c.skip}, nil
	}
	tokens := candidateTokens(name)
	first, v, err := p.probe(ctx, cand, tokens, c)
	if first != nil {
		p.checks++
	}
	if err != nil || v != Different {
		return Result{Verdict: v}, err
	}
	hit, err := p.confirm(ctx, cand, dir, shape, tokens, c, first)
	if err != nil {
		return Result{Verdict: Different}, err
	}
	if hit == nil {
		return Result{Verdict: Different}, nil
	}
	return Result{Verdict: Different, Hit: hit}, nil
}

// probe requests a candidate and compares its answer with the class. A
// NoSignal answer returns a nil sig.
func (p *Prober) probe(ctx context.Context, cand string, tokens []string, c *class) (*Sig, Verdict, error) {
	r, err := p.fetchRetry(ctx, cand, tokens)
	if err != nil {
		if errors.Is(err, ErrStopped) {
			return nil, NoSignal, err
		}
		return nil, NoSignal, nil
	}
	if r.refused != "" {
		return nil, NoSignal, p.refusal(r)
	}
	if r.edge.State.Stops() {
		return nil, NoSignal, p.stop(GapEdgeProtected)
	}
	if throttledAnswer(r) {
		return nil, NoSignal, p.noteThrottled()
	}
	p.throttled = 0
	s := r.sig
	return &s, c.compare(s), nil
}

// confirm repeats a different answer, checks a random child of a directory
// or a 403, and classifies the hit. A nil hit means the difference did not
// hold or does not show existence.
func (p *Prober) confirm(ctx context.Context, cand, dir, shape string, tokens []string, c *class, first *Sig) (*Hit, error) {
	b := c.samples[0]
	st := first.Status
	// A missing-path status never shows existence, whatever the baseline.
	if st == http.StatusNotFound || st == http.StatusGone || st == http.StatusTooManyRequests || st == http.StatusServiceUnavailable {
		return nil, nil
	}
	again, v, err := p.probe(ctx, cand, tokens, c)
	if err != nil {
		return nil, err
	}
	if v != Different || !c.consistent(*first, *again) {
		p.unexpected++
		return nil, nil
	}
	hit := &Hit{Path: cand, Status: st, ContentType: first.ContentType, Size: first.Size, Hash: first.Hash, Auth: AuthNone}
	needsChild := shape == ShapeSlash
	switch {
	case st >= 200 && st < 300:
	case st == http.StatusUnauthorized:
		hit.Auth = AuthRequired
	case isRedirect(st):
		switch {
		case first.Location == dirRedirect(dir):
			hit.Labels = append(hit.Labels, LabelDirectory)
			needsChild = true
		case loginPattern(first.Location) && !loginPattern(b.Location):
			hit.Auth = AuthRedirectLogin
		default:
			hit.Labels = append(hit.Labels, LabelRedirect)
		}
	case st == http.StatusForbidden:
		if !notFoundLike(b.Status) {
			p.unexpected++
			return nil, nil
		}
		hit.Labels = append(hit.Labels, LabelForbidden)
		needsChild = true
	case st == http.StatusMethodNotAllowed:
		hit.Labels = append(hit.Labels, LabelMethodNotAllowed)
	case st >= 500:
		if !notFoundLike(b.Status) {
			p.unexpected++
			return nil, nil
		}
		hit.Labels = append(hit.Labels, LabelError)
	default:
		return nil, nil
	}
	if shape == ShapeSlash && !containsLabel(hit.Labels, LabelDirectory) {
		hit.Labels = append(hit.Labels, LabelDirectory)
	}
	if needsChild {
		ok, err := p.childMissing(ctx, cand, dir)
		if err != nil {
			return nil, err
		}
		if !ok {
			p.unexpected++
			return nil, nil
		}
	}
	return hit, nil
}

// childMissing requests a random child of cand and reports whether it
// answers like a missing path: like the parent directory's bare baseline,
// or like a baseline of the child directory that is itself a 404 or 410.
// A firewall rule that refuses every path containing a word fails it: the
// child is refused too.
func (p *Prober) childMissing(ctx context.Context, cand, dir string) (bool, error) {
	childDir := strings.TrimSuffix(cand, "/") + "/"
	child := childDir + p.name()
	r, err := p.fetchRetry(ctx, child, []string{path.Base(child)})
	if err != nil {
		if errors.Is(err, ErrStopped) {
			return false, err
		}
		return false, nil
	}
	if r.refused != "" {
		return false, p.refusal(r)
	}
	if r.edge.State.Stops() {
		return false, p.stop(GapEdgeProtected)
	}
	if throttledAnswer(r) {
		return false, p.noteThrottled()
	}
	parent, err := p.class(ctx, dir, ShapeBare)
	if err != nil {
		return false, err
	}
	if parent.skip == "" && parent.compare(r.sig) == Same {
		return true, nil
	}
	cc, err := p.class(ctx, childDir, ShapeBare)
	if err != nil {
		return false, err
	}
	return cc.skip == "" && notFoundLike(cc.samples[0].Status) && cc.compare(r.sig) == Same, nil
}

// CaseInsensitive reports whether the origin ignores the case of a path: the
// hit's path with the case of its letters flipped answers like the hit and
// unlike the baseline. A caller then de-duplicates its remaining candidates
// ignoring case. One request (plus a calibration when needed).
func (p *Prober) CaseInsensitive(ctx context.Context, h *Hit) (bool, error) {
	if h == nil || p.stopped != "" {
		return false, nil
	}
	flipped := flipCase(h.Path)
	if flipped == h.Path {
		return false, nil
	}
	dir, name, shape := Split(flipped)
	c, err := p.class(ctx, dir, shape)
	if err != nil || c.skip != "" {
		return false, err
	}
	s, v, err := p.probe(ctx, flipped, candidateTokens(name), c)
	if err != nil || s == nil {
		return false, err
	}
	p.foldCase = v == Different && s.Status == h.Status && s.Family == Family(h.ContentType)
	return p.foldCase, nil
}

// refusal handles the sensor's own refusal of a request: past the request
// cap the origin stops (budget); any other refusal is a candidate the scope
// filtered.
func (p *Prober) refusal(r *response) error {
	if strings.Contains(r.refused, "request cap") {
		return p.stop(GapBudget)
	}
	p.gaps[GapScopeFiltered]++
	return nil
}

func (p *Prober) noteThrottled() error {
	p.throttled++
	if p.throttled >= maxConsecutiveThrottled {
		return p.stop(GapThrottled)
	}
	return nil
}

// throttledAnswer reports whether an answer is a rate limit (after its
// retries): never a signal.
func throttledAnswer(r *response) bool {
	return r.sig.Status == http.StatusTooManyRequests || r.sig.Status == http.StatusServiceUnavailable ||
		r.edge.State == edgeprotect.RateLimited
}

// fetchRetry fetches path, retrying a rate limit or a network error at most
// Retries times after a backoff. A bound broken stops the origin; network
// errors on maxConsecutiveFailures candidates in a row stop it (blocked).
func (p *Prober) fetchRetry(ctx context.Context, path string, tokens []string) (*response, error) {
	var last error
	for attempt := 0; ; attempt++ {
		if p.o.MaxRequests > 0 && p.requests >= p.o.MaxRequests {
			return nil, p.stop(GapBudget)
		}
		r, err := p.fetch(ctx, path, tokens)
		switch {
		case err == nil:
			p.failures = 0
			if !throttledAnswer(r) || r.edge.State.Stops() || attempt >= p.o.Retries {
				return r, nil
			}
			if err := p.sleep(ctx, p.backoff(attempt, r.retryAfter)); err != nil {
				return nil, err
			}
			continue
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.Is(err, errHostile):
			return nil, p.stop(GapHostileResponse)
		case errors.Is(err, errProtocol):
			return nil, p.stop(GapProtocol)
		}
		last = err
		if attempt >= p.o.Retries {
			p.failures++
			if p.failures >= maxConsecutiveFailures {
				return nil, p.stop(GapBlocked)
			}
			return nil, last
		}
		if err := p.sleep(ctx, p.backoff(attempt, "")); err != nil {
			return nil, err
		}
	}
}

// backoff is the wait before retry attempt+1: Retry-After within the bounds,
// else MinBackoff doubled per attempt.
func (p *Prober) backoff(attempt int, retryAfter string) time.Duration {
	d := p.o.MinBackoff << uint(min(attempt, 6))
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 {
		d = time.Duration(s) * time.Second
	} else if t, err := http.ParseTime(retryAfter); err == nil {
		d = t.Sub(p.now())
	}
	return min(max(d, p.o.MinBackoff), p.o.MaxBackoff)
}

// maybeRecalibrate starts a new calibration generation after
// RecalibrateAfter requests, or when more than 2 % of at least 50 compared
// candidates differed and then failed to confirm (the origin's behavior
// drifted: a firewall mode, a rate-limit page).
func (p *Prober) maybeRecalibrate() {
	if p.sinceCalibration >= p.o.RecalibrateAfter || (p.checks >= 50 && p.unexpected*50 > p.checks) {
		p.gen++
		p.sinceCalibration, p.checks, p.unexpected = 0, 0, 0
	}
}

// name is a fresh random name: 12 lower-case letters and digits.
func (p *Prober) name() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, nameLen)
	if _, err := io.ReadFull(p.o.Rand, b); err != nil {
		panic("webdiff: random source failed: " + err.Error())
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// candidateTokens are the forms of a candidate's own name that its answer
// may reflect (removed before comparing, as a baseline's random name is).
func candidateTokens(name string) []string {
	n := strings.TrimSuffix(name, "/")
	if u, err := url.PathUnescape(n); err == nil {
		n = u
	}
	out := []string{n}
	if i := strings.LastIndexByte(n, '.'); i > 0 {
		out = append(out, n[:i])
	}
	return out
}

func isRedirect(st int) bool { return st >= 300 && st < 400 && st != http.StatusNotModified }

// notFoundLike reports whether a baseline status means "missing".
func notFoundLike(st int) bool { return st == http.StatusNotFound || st == http.StatusGone }

// dirRedirect is the Location pattern of a redirect from a candidate of dir
// to the same path with a trailing slash.
func dirRedirect(dir string) string { return dir + "{r}/" }

// loginWords mark a redirect to a sign-in page.
var loginWords = []string{"login", "signin", "sign-in", "sign_in", "logon", "/auth", "sso", "oauth", "saml", "openid", "/account", "/cas/", "returnurl", "return_to"}

func loginPattern(loc string) bool {
	if loc == "" {
		return false
	}
	l := strings.ToLower(loc)
	for _, w := range loginWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func containsLabel(labels []string, l string) bool {
	for _, x := range labels {
		if x == l {
			return true
		}
	}
	return false
}

// flipCase swaps the case of every ASCII letter of a path's last segment.
func flipCase(p string) string {
	i := strings.LastIndexByte(strings.TrimSuffix(p, "/"), '/') + 1
	b := []byte(p)
	for j := i; j < len(b); j++ {
		switch c := b[j]; {
		case c >= 'a' && c <= 'z':
			b[j] = c - 32
		case c >= 'A' && c <= 'Z':
			b[j] = c + 32
		}
	}
	return string(b)
}
