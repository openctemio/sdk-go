package adapt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/contract/edgeprotect"

	"github.com/openctemio/sdk-go/pkg/useragent"
)

// CanaryBounds bound a task's canary requests (Canary).
type CanaryBounds struct {
	// Interval is the time between two requests to a host that answers
	// normally; FailInterval the time after a push-back or a failure.
	Interval     time.Duration
	FailInterval time.Duration
	// Timeout bounds one request.
	Timeout time.Duration
	// MaxHosts bounds the hosts one task watches; further hosts get none.
	MaxHosts int
}

// CanaryPace is the table of canary bounds. Why each value:
//
//   - Interval 10s, FailInterval 3s: one request every ten seconds is a
//     fiftieth of the Gentle budget of a host; three seconds after a
//     push-back sees a Retry-After of a few seconds end, and is the most the
//     canary ever adds to a host's rate (a third of a request a second).
//   - Timeout 10s: the pacing levels' own request timeout.
//   - MaxHosts 64: the canary is for the hosts a job works for minutes; a
//     sweep over thousands of hosts sends each a request or two and needs
//     none.
var CanaryPace = CanaryBounds{
	Interval:     10 * time.Second,
	FailInterval: 3 * time.Second,
	Timeout:      10 * time.Second,
	MaxHosts:     64,
}

// CanaryTarget is one host a canary watches: the host's key in the rate
// controller (HostKey, the key the task's forwarder counts the host's
// connections under) and the URL the canary requests (the origin's root).
// Addrs are the keys of the addresses the host is reached at
// (CanonicalHost of each; may be empty): what the canary is answered is
// reported to them too (HostRate.ReportAddr), so it slows every name of the
// task that is reached at the same address.
type CanaryTarget struct {
	Host  string
	URL   string
	Addrs []string
}

// CanaryTargets picks the hosts of a job's targets a canary can watch: one
// per HostKey (the canonical host, so two spellings of one host get one
// canary), for the first target of that host that is an http or https
// URL, requested at the URL's origin ("/"). A target that is not such a URL
// gets none (the scheme and port to ask on are not known, and a canary
// never sends a request the job did not name an origin for). It returns at
// most CanaryPace.MaxHosts targets and how many hosts got none.
func CanaryTargets(targets []string) (list []CanaryTarget, unwatched int) {
	seen := map[string]bool{}
	hosts := map[string]bool{}
	for _, t := range targets {
		key := HostKey(t)
		if key == "" {
			continue
		}
		hosts[key] = true
		if seen[key] {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(t))
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if len(list) >= CanaryPace.MaxHosts {
			continue
		}
		seen[key] = true
		list = append(list, CanaryTarget{Host: key, URL: u.Scheme + "://" + u.Host + "/"})
	}
	return list, len(hosts) - len(list)
}

// CanarySummary is what a task's canary did. Numbers only.
type CanarySummary struct {
	// Hosts were watched; Unwatched hosts of the job got no canary.
	Hosts     int `json:"hosts"`
	Unwatched int `json:"hosts_unwatched,omitempty"`
	// Probes is how many requests were sent; Pushback how many were
	// answered with a rate limit, a block or a challenge; Failed how many
	// were reset or timed out; Held how many were not sent because the
	// host's breaker was open or the host asked to wait.
	Probes   int `json:"probes"`
	Pushback int `json:"pushback,omitempty"`
	Failed   int `json:"failed,omitempty"`
	Held     int `json:"held,omitempty"`
	// Unverified is how many requests ended on a certificate that did not
	// verify: the canary reads nothing from such a host.
	Unverified int `json:"unverified,omitempty"`
}

// Canary watches the hosts of one task from outside the tool: a plain GET
// of each origin every CanaryPace.Interval, through the same way out as the
// tool's connections (the task's forwarder: its scope check, the addresses
// pinned at admission, the job's proxy pool), whose answer is fed to the
// task's HostRate. It exists because the controller cannot read what a host
// answers on an HTTPS connection the forwarder only passes through: the
// canary's own request is one it can read, without terminating the tool's
// TLS. A task without a forwarder gets no canary: there is no way out the
// runtime shares with the tool there, and nothing a canary could slow.
//
// The request is fixed: GET of the origin's root, no query, no body, and
// one header besides Host, the sensor's own User-Agent (useragent.String).
// Nothing a job or a platform setting says changes it; only the origin
// comes from the job's signed targets. A host that wants to recognize the
// scanner by it can: that is what a published identification is for.
//
// What an answer means: 429 or 503 (with Retry-After) and a vendor's
// rate-limit page are push-back, a vendor's challenge or block page and a
// 403 from a host that served the same request before are a refusal, a
// reset or a timeout from a host that served it before is push-back too.
// Each halves the host's rate. None of them opens the host's breaker or
// stops a tool by itself: the breaker opens only when the tool's own
// connections fail as well (HostRate, EvidenceCanaryAndConnection), because
// a host can answer the canary differently from the tool. Any other answer
// is health. A request waits while the host's breaker is not closed or the
// host asked to wait, takes a token of the host's rate when one is free
// (HostRate.AcquireProbe) and never waits behind the tool's requests, so
// it adds at most one request every FailInterval to the host's rate. It is
// never retried and follows no redirect.
//
// What it does not see: a limit that applies to the tool's requests only
// (a path, a payload or a session the canary does not use), a host no
// target names by URL, and a host whose certificate does not verify.
type Canary struct {
	rate *HostRate
	do   func(*http.Request) (*http.Response, error)
	b    CanaryBounds

	mu    sync.Mutex
	stats CanarySummary
}

// NewCanary returns the canary of one task. do sends one request through
// the task's way out, as it is, and must not follow redirects (CanaryDo).
func NewCanary(rate *HostRate, do func(*http.Request) (*http.Response, error)) *Canary {
	return &Canary{rate: rate, do: do, b: CanaryPace}
}

// canaryRequest is the canary's request for origin: the same for every
// job. The transport adds the Host header and nothing else (CanaryDo turns
// its own compression header off).
func canaryRequest(ctx context.Context, origin string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
	if err != nil {
		return nil, err
	}
	req.URL.Path, req.URL.RawPath, req.URL.RawQuery, req.URL.Fragment, req.URL.User = "/", "", "", "", nil
	req.Header = http.Header{"User-Agent": {useragent.String()}}
	return req, nil
}

// report feeds one signal of the canary to the host's state and to the
// states of the addresses the host is reached at.
func (c *Canary) report(t CanaryTarget, e Event) {
	e.Probe = true
	c.rate.Report(t.Host, e)
	for _, a := range t.Addrs {
		if a != t.Host {
			c.rate.ReportAddr(a, e)
		}
	}
}

// Run watches targets until ctx ends, then records its summary on the
// controller (HostRate.SetCanary). unwatched is CanaryTargets' count.
func (c *Canary) Run(ctx context.Context, targets []CanaryTarget, unwatched int) {
	c.mu.Lock()
	c.stats.Hosts, c.stats.Unwatched = len(targets), unwatched
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.watch(ctx, t)
		}()
	}
	wg.Wait()
	c.rate.SetCanary(c.Summary())
}

// Summary is what the canary did so far.
func (c *Canary) Summary() CanarySummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Canary) watch(ctx context.Context, t CanaryTarget) {
	base := 0
	for {
		wait := c.probe(ctx, t, &base)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Canary) add(f func(*CanarySummary)) {
	c.mu.Lock()
	f(&c.stats)
	c.mu.Unlock()
}

// probe sends one request and returns how long to wait before the next.
// base is the status of the host's first answer (0: none yet).
func (c *Canary) probe(ctx context.Context, t CanaryTarget, base *int) time.Duration {
	if err := c.rate.AcquireProbe(ctx, t.Host); err != nil {
		if errors.Is(err, ErrHostUnavailable) {
			c.add(func(s *CanarySummary) { s.Held++ })
		}
		return c.b.FailInterval
	}
	rctx, cancel := context.WithTimeout(ctx, c.b.Timeout)
	defer cancel()
	req, err := canaryRequest(rctx, t.URL)
	if err != nil {
		return c.b.Interval
	}
	c.add(func(s *CanarySummary) { s.Probes++ })
	resp, err := c.do(req)
	if err != nil {
		if ctx.Err() != nil {
			return c.b.Interval
		}
		if certUnverified(err) {
			// Not a host the canary reads: no signal, and no hurry.
			c.add(func(s *CanarySummary) { s.Unverified++ })
			return c.b.Interval
		}
		reason := FailureReason(err)
		if reason == "" && rctx.Err() != nil {
			reason = ReasonTimeout
		}
		if reason != "" {
			c.add(func(s *CanarySummary) { s.Failed++ })
			c.report(t, Event{Signal: Failed, Reason: reason})
			return c.b.FailInterval
		}
		return c.b.Interval
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, edgeprotect.MaxBody))
	_ = resp.Body.Close()
	v := edgeprotect.Classify(resp.StatusCode, resp.Header, "", body)
	status := resp.StatusCode
	if *base == 0 {
		*base = status
	}
	switch {
	case v.State.Stops():
		c.add(func(s *CanarySummary) { s.Pushback++ })
		c.report(t, Event{Signal: Forbidden, Reason: ReasonBlocked, Edge: v})
		return c.b.FailInterval
	case v.State == edgeprotect.RateLimited, IsThrottle(status):
		c.add(func(s *CanarySummary) { s.Pushback++ })
		reason := ReasonHTTP429
		if status == http.StatusServiceUnavailable {
			reason = ReasonHTTP503
		}
		c.report(t, Event{Signal: Congested, Reason: reason, Edge: v,
			RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), time.Now())})
		return c.b.FailInterval
	case status == http.StatusForbidden && *base != http.StatusForbidden:
		// The origin served this request before and forbids it now.
		c.add(func(s *CanarySummary) { s.Pushback++ })
		c.report(t, Event{Signal: Forbidden})
		return c.b.FailInterval
	}
	// Any other answer, a 403 from the first request on included (an
	// origin whose root needs a login), says the host answers.
	c.report(t, Event{Signal: Answered})
	return c.b.Interval
}

// CanaryDo returns the request function of a canary whose connections are
// opened by dial (the task's way out: its forwarder's DialTarget, which
// checks the scope, dials the addresses pinned at admission and goes
// through the job's proxy pool as the tool's connections do), and a
// function that releases it. A request uses one connection, which is closed
// when its answer was read, follows no redirect, goes through no proxy of
// the environment, and is sent as the canary built it: the transport adds
// no header of its own besides Host (no Accept-Encoding, and no Connection
// header: the connection is closed by the canary, not announced).
//
// The target's certificate is verified against roots (nil: the system's).
// A host whose certificate does not verify (self-signed, expired, another
// name) is not read: what an unauthenticated peer answers must not steer
// the scan's rate, and a sensor whose policy forbids unverified TLS stays
// inside it. Such a probe is counted (CanarySummary.Unverified) and says
// nothing about the host.
func CanaryDo(dial func(ctx context.Context, host string, port int) (net.Conn, error), roots *x509.CertPool) (do func(*http.Request) (*http.Response, error), release func()) {
	tr := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		MaxIdleConns:          1,
		IdleConnTimeout:       time.Second,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   CanaryPace.Timeout,
		ResponseHeaderTimeout: CanaryPace.Timeout,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, ps, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(ps)
			if err != nil {
				return nil, err
			}
			return dial(ctx, host, port)
		},
	}
	client := &http.Client{Transport: tr, Timeout: CanaryPace.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do = func(req *http.Request) (*http.Response, error) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		resp.Body = &closingBody{ReadCloser: resp.Body, done: tr.CloseIdleConnections}
		return resp, nil
	}
	return do, tr.CloseIdleConnections
}

// closingBody closes the canary's connection when its answer was read: the
// next request dials again, through the same checks.
type closingBody struct {
	io.ReadCloser
	done func()
}

func (b *closingBody) Close() error {
	err := b.ReadCloser.Close()
	b.done()
	return err
}

// certUnverified reports whether err is a certificate that did not verify.
func certUnverified(err error) bool {
	var cv *tls.CertificateVerificationError
	return errors.As(err, &cv)
}
