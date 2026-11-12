package ctlog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/ctlookup"
)

// fakeClock advances only when the client sleeps.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	c.sleeps = append(c.sleeps, d)
	return nil
}

// upstream records the requests of a fake CT source.
type upstream struct {
	mu   sync.Mutex
	reqs []*http.Request
	h    func(w http.ResponseWriter, r *http.Request, n int)
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.reqs = append(u.reqs, r)
	n := len(u.reqs)
	u.mu.Unlock()
	u.h(w, r, n)
}

func (u *upstream) count() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.reqs) }

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serve(body []byte) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write(body) }
}

func status(code int, retryAfter string) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(code)
	}
}

type harness struct {
	crt, cs *upstream
	clock   *fakeClock
	c       *Client
}

func newHarness(t *testing.T, crt, cs func(http.ResponseWriter, *http.Request, int), mod func(*Config)) *harness {
	t.Helper()
	h := &harness{crt: &upstream{h: crt}, cs: &upstream{h: cs}, clock: &fakeClock{t: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}}
	crtSrv := httptest.NewServer(h.crt)
	csSrv := httptest.NewServer(h.cs)
	t.Cleanup(crtSrv.Close)
	t.Cleanup(csSrv.Close)
	cfg := Config{HTTP: crtSrv.Client(), CRTSHURL: crtSrv.URL, CertSpotterURL: csSrv.URL, now: h.clock.now, sleep: h.clock.sleep}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.c = c
	return h
}

func (h *harness) lookup(t *testing.T, tenant, domain string) ctlookup.Output {
	t.Helper()
	out, err := h.c.Lookup(context.Background(), tenant, ctlookup.Input{Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func names(out ctlookup.Output) []string {
	var all []string
	for _, r := range out.Records {
		all = append(all, r.DNSNames...)
	}
	slices.Sort(all)
	return slices.Compact(all)
}

func TestCRTSHAnswerIsBoundToTheDomain(t *testing.T) {
	h := newHarness(t, serve(fixture(t, "crtsh_example.com.json")), status(500, ""), nil)
	out := h.lookup(t, "tenant-a", "Example.com")
	if want := []string{"*.dev.example.com", "api.example.com", "example.com", "www.example.com"}; !slices.Equal(names(out), want) {
		t.Fatalf("names %v, want %v", names(out), want)
	}
	if len(out.Records) != 3 {
		t.Fatalf("records %+v", out.Records)
	}
	r := out.Records[0]
	if r.Source != ctlookup.SourceCRTSH || r.EntryID != "9000000001" || r.Serial != "04a1b2c3d4e5f60718293a4b5c6d7e8f" ||
		r.NotAfter != "2026-11-30T23:59:59Z" || !strings.Contains(r.Issuer, "Example TLS CA 1") {
		t.Fatalf("record %+v", r)
	}
	if !slices.Equal(out.SourceStatus, []ctlookup.SourceStatus{{Source: ctlookup.SourceCRTSH, State: ctlookup.StateOK}}) {
		t.Fatalf("status %+v", out.SourceStatus)
	}
	if h.cs.count() != 0 {
		t.Fatal("Cert Spotter asked although crt.sh answered")
	}
	q := h.crt.reqs[0].URL.Query()
	if q.Get("q") != "%.example.com" || q.Get("output") != "json" || q.Get("deduplicate") != "Y" {
		t.Fatalf("crt.sh query %v", q)
	}
	if h.crt.reqs[0].Header.Get("Authorization") != "" {
		t.Fatal("a key went to crt.sh")
	}
}

func TestFallbackToCertSpotterWithKeyAndPages(t *testing.T) {
	cs := func(w http.ResponseWriter, r *http.Request, _ int) {
		switch r.URL.Query().Get("after") {
		case "":
			_, _ = w.Write(fixture(t, "certspotter_page1.json"))
		case "1002":
			_, _ = w.Write(fixture(t, "certspotter_page2.json"))
		default:
			_, _ = w.Write([]byte("[]"))
		}
	}
	h := newHarness(t, status(503, ""), cs, func(c *Config) { c.CertSpotterKey = func() string { return "k-123" } })
	out := h.lookup(t, "tenant-a", "example.com")
	if h.crt.count() != crtshAttempts {
		t.Fatalf("crt.sh asked %d times, want %d", h.crt.count(), crtshAttempts)
	}
	if want := []string{"*.mail.example.com", "example.com", "vpn.example.com", "www.example.com"}; !slices.Equal(names(out), want) {
		t.Fatalf("names %v", names(out))
	}
	want := []ctlookup.SourceStatus{{Source: ctlookup.SourceCRTSH, State: ctlookup.StateUnavailable}, {Source: ctlookup.SourceCertSpotter, State: ctlookup.StateOK}}
	if !slices.Equal(out.SourceStatus, want) {
		t.Fatalf("status %+v", out.SourceStatus)
	}
	if out.Records[1].Issuer != "C=US, O=Other CA" || out.Records[0].Serial == "" {
		t.Fatalf("records %+v", out.Records)
	}
	for _, r := range h.cs.reqs {
		if r.Header.Get("Authorization") != "Bearer k-123" {
			t.Fatal("Cert Spotter request without the key")
		}
		q := r.URL.Query()
		if r.URL.Path != "/v1/issuances" || q.Get("domain") != "example.com" || q.Get("include_subdomains") != "true" {
			t.Fatalf("Cert Spotter query %s %v", r.URL.Path, q)
		}
	}
	// Back-off between crt.sh attempts, within the bounds.
	if len(h.clock.sleeps) < crtshAttempts-1 {
		t.Fatalf("no back-off: %v", h.clock.sleeps)
	}
}

func TestRateLimitIsAStatusNotAFailure(t *testing.T) {
	h := newHarness(t, status(429, "120"), status(429, ""), nil)
	out, err := h.c.Lookup(context.Background(), "tenant-a", ctlookup.Input{Domain: "example.com"})
	if err != nil {
		t.Fatalf("a source failure is an error: %v", err)
	}
	if h.crt.count() != 1 {
		t.Fatalf("crt.sh retried after a 429: %d", h.crt.count())
	}
	want := []ctlookup.SourceStatus{{Source: ctlookup.SourceCRTSH, State: ctlookup.StateRateLimited, RetryAfterS: 120}, {Source: ctlookup.SourceCertSpotter, State: ctlookup.StateRateLimited}}
	if !slices.Equal(out.SourceStatus, want) || len(out.Records) != 0 || out.Records == nil {
		t.Fatalf("out %+v", out)
	}
	// crt.sh cools down for its Retry-After: the next lookup does not ask
	// it at all and reports rate_limited at once.
	out = h.lookup(t, "tenant-b", "example.org")
	if h.crt.count() != 1 || out.SourceStatus[0].State != ctlookup.StateRateLimited || out.SourceStatus[0].RetryAfterS < 60 {
		t.Fatalf("cool-down not honored: %d requests, %+v", h.crt.count(), out.SourceStatus)
	}
}

func TestFailedAnswersAreNotCached(t *testing.T) {
	h := newHarness(t, status(502, ""), status(500, ""), nil)
	h.lookup(t, "tenant-a", "example.com")
	h.lookup(t, "tenant-a", "example.com")
	if h.crt.count() != 2*crtshAttempts {
		t.Fatalf("crt.sh asked %d times", h.crt.count())
	}
}

func TestCacheIsPerTenant(t *testing.T) {
	h := newHarness(t, serve(fixture(t, "crtsh_example.com.json")), status(500, ""), nil)
	h.lookup(t, "tenant-a", "example.com")
	h.lookup(t, "tenant-a", "EXAMPLE.com.")
	if h.crt.count() != 1 {
		t.Fatalf("the same tenant's repeat asked again: %d", h.crt.count())
	}
	h.lookup(t, "tenant-b", "example.com")
	if h.crt.count() != 2 {
		t.Fatalf("another tenant was served from the first tenant's cache: %d", h.crt.count())
	}
	// Expired after the TTL.
	h.clock.t = h.clock.t.Add(DefaultCacheTTL + time.Minute)
	h.lookup(t, "tenant-a", "example.com")
	if h.crt.count() != 3 {
		t.Fatalf("expired answer reused: %d", h.crt.count())
	}
}

func TestOversizedAnswerIsRefusedWhole(t *testing.T) {
	h := newHarness(t, serve(fixture(t, "crtsh_example.com.json")), status(500, ""), func(c *Config) { c.MaxBodyBytes = 100 })
	out := h.lookup(t, "tenant-a", "example.com")
	if h.crt.count() != 1 || len(out.Records) != 0 || out.SourceStatus[0].State != ctlookup.StateTooLarge {
		t.Fatalf("out %+v after %d requests", out, h.crt.count())
	}
}

func TestBadAnswerIsUnavailable(t *testing.T) {
	h := newHarness(t, serve([]byte("<html>busy</html>")), serve([]byte("{")), nil)
	out := h.lookup(t, "tenant-a", "example.com")
	if h.crt.count() != 1 || out.SourceStatus[0].State != ctlookup.StateUnavailable || out.SourceStatus[1].State != ctlookup.StateUnavailable {
		t.Fatalf("out %+v", out)
	}
}

func TestCertSpotterOff(t *testing.T) {
	h := newHarness(t, status(503, ""), status(500, ""), func(c *Config) { c.CertSpotterOff = true })
	out := h.lookup(t, "tenant-a", "example.com")
	if h.cs.count() != 0 || len(out.SourceStatus) != 1 {
		t.Fatalf("out %+v", out)
	}
}

func TestBadInputAndCancel(t *testing.T) {
	h := newHarness(t, status(500, ""), status(500, ""), nil)
	for _, d := range []string{"", "*.example.com", "http://example.com", "com"} {
		if _, err := h.c.Lookup(context.Background(), "t", ctlookup.Input{Domain: d}); !errors.Is(err, ctlookup.ErrInvalid) {
			t.Errorf("domain %q: %v", d, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.c.Lookup(ctx, "t", ctlookup.Input{Domain: "example.com"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup: %v", err)
	}
}

func TestPaceBetweenRequests(t *testing.T) {
	h := newHarness(t, serve([]byte("[]")), status(500, ""), nil)
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		h.lookup(t, "t", d)
	}
	var waited time.Duration
	for _, s := range h.clock.sleeps {
		waited += s
	}
	if waited < 2*DefaultInterval {
		t.Fatalf("three requests to one source in %s", waited)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	for _, cfg := range []Config{{}, {HTTP: http.DefaultClient, CRTSHURL: "ftp://x"}, {HTTP: http.DefaultClient, CertSpotterURL: "https://u:p@x"}} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) accepted", cfg)
		}
	}
}

func TestJobChecksTheTarget(t *testing.T) {
	h := newHarness(t, serve(fixture(t, "crtsh_example.com.json")), status(500, ""), nil)
	ans, err := h.c.Job(context.Background(), "tenant-a", "example.com", []byte(`{"domain":"Example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if out := ans.(ctlookup.Output); len(out.Records) != 3 {
		t.Fatalf("out %+v", out)
	}
	for _, tc := range []struct{ target, input string }{
		{"example.org", `{"domain":"example.com"}`},
		{"example.com", `{"domain":"example.com","url":"http://169.254.169.254/"}`},
		{"example.com", `{"domain":"*.example.com"}`},
		{"example.com", `not json`},
	} {
		if _, err := h.c.Job(context.Background(), "tenant-a", tc.target, []byte(tc.input)); err == nil {
			t.Errorf("job %+v accepted", tc)
		}
	}
	if _, err := h.c.Job(context.Background(), "", "example.com", []byte(`{"domain":"example.com"}`)); err == nil {
		t.Error("job without an organization accepted")
	}
	if h.crt.count() != 1 {
		t.Fatalf("refused jobs reached the source: %d", h.crt.count())
	}
}
