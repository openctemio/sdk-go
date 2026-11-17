package adapt

import (
	"context"
	"crypto/tls"
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
// controller and the URL the canary requests (the origin's root).
type CanaryTarget struct {
	Host string
	URL  string
}

// CanaryTargets picks the hosts of a job's targets a canary can watch: one
// per HostKey, for the first target of that host that is an http or https
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
}

// Canary watches the hosts of one task from outside the tool: a plain GET
// of each origin every CanaryPace.Interval, through the same way out as the
// tool's requests and with the job's identification, whose answer is fed to
// the task's HostRate. It exists because the controller cannot read what a
// host answers on an HTTPS connection the forwarder only passes through,
// and sees nothing at all of a tool that runs unconfined: the canary's own
// request is one it can read, without terminating the tool's TLS.
//
// What an answer means: 429 or 503 (with Retry-After) and a vendor's
// rate-limit page are push-back (the host's rate is halved, a run of them
// opens its breaker and makes it a GapThrottled gap); a vendor's challenge
// or block page is a block; a 403 from a host that served the same request
// before is a block after ThrottleRun of them in a row; a reset or a
// timeout is a failure that also halves the rate. Any other answer is
// health. A request respects the host's breaker and Retry-After and takes
// a token of the host's rate when one is free (HostRate.AcquireProbe); it
// never waits behind the tool's requests, so it adds at most one request
// every FailInterval to the host's rate. It is never retried and follows
// no redirect.
//
// What it does not see: a limit that applies to the tool's requests only
// (a path, a payload or a session the canary does not use), and a host no
// target names by URL.
type Canary struct {
	rate   *HostRate
	do     func(*http.Request) (*http.Response, error)
	header http.Header
	b      CanaryBounds

	mu    sync.Mutex
	stats CanarySummary
}

// NewCanary returns the canary of one task. do sends one request through
// the task's way out and must not follow redirects; header is the job's
// identification (may be nil).
func NewCanary(rate *HostRate, do func(*http.Request) (*http.Response, error), header http.Header) *Canary {
	return &Canary{rate: rate, do: do, header: header, b: CanaryPace}
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
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return c.b.Interval
	}
	for k, v := range c.header {
		req.Header[k] = append([]string(nil), v...)
	}
	c.add(func(s *CanarySummary) { s.Probes++ })
	resp, err := c.do(req)
	if err != nil {
		if ctx.Err() != nil {
			return c.b.Interval
		}
		reason := FailureReason(err)
		if reason == "" && rctx.Err() != nil {
			reason = ReasonTimeout
		}
		if reason != "" {
			c.add(func(s *CanarySummary) { s.Failed++ })
			c.rate.Report(t.Host, Event{Signal: Failed, Reason: reason, Probe: true})
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
	case v.State.Stops(), v.State == edgeprotect.RateLimited, IsThrottle(status):
		c.add(func(s *CanarySummary) { s.Pushback++ })
		c.rate.ReportResponse(t.Host, status, resp.Header.Get("Retry-After"), v)
		return c.b.FailInterval
	case status == http.StatusForbidden && *base != http.StatusForbidden:
		// The origin served this request before and forbids it now.
		c.add(func(s *CanarySummary) { s.Pushback++ })
		c.rate.Report(t.Host, Event{Signal: Forbidden, Probe: true})
		return c.b.FailInterval
	}
	// Any other answer, a 403 from the first request on included (an
	// origin whose root needs a login), says the host answers.
	c.rate.Report(t.Host, Event{Signal: Answered})
	return c.b.Interval
}

// CanaryDo returns the request function of a canary whose connections are
// opened by dial (the task's way out: its forwarder, or a dialer bound to
// the addresses the task's targets were admitted at), and a function that
// releases it. A request uses one connection and closes it, follows no
// redirect and goes through no proxy of the environment. The target's
// certificate is not verified, as the scan tools do not verify it (targets
// serve self-signed and expired certificates): the canary sends no secret
// and only classifies the status and the first bytes of the answer.
func CanaryDo(dial func(ctx context.Context, host string, port int) (net.Conn, error)) (do func(*http.Request) (*http.Response, error), release func()) {
	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // G402: scan targets, see above
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
	return client.Do, tr.CloseIdleConnections
}
