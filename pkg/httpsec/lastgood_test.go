package httpsec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDNS answers lookups from a table; a name mapped to nil fails with
// Docker's embedded-DNS error.
type fakeDNS struct {
	mu    sync.Mutex
	table map[string][]string
	asked []string
	err   error
}

func (f *fakeDNS) set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.table == nil {
		f.table = map[string][]string{}
	}
	f.table[host] = addrs
}

func (f *fakeDNS) lookup(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	addrs, ok := f.table[host]
	if !ok || addrs == nil {
		if f.err != nil {
			return nil, f.err
		}
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, Server: "127.0.0.11:53", IsTemporary: true}
	}
	var out []net.IPAddr
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (f *fakeDNS) questions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

type eventLog struct {
	mu  sync.Mutex
	evs []LastGoodEvent
}

func (e *eventLog) add(ev LastGoodEvent) {
	e.mu.Lock()
	e.evs = append(e.evs, ev)
	e.mu.Unlock()
}

func (e *eventLog) states() []LastGoodState {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []LastGoodState
	for _, ev := range e.evs {
		out = append(out, ev.To)
	}
	return out
}

// tlsPlatform is a TLS server whose certificate is valid for example.com
// (and 127.0.0.1): the platform host name in these tests.
func tlsPlatform(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return srv, port
}

func lastGoodClient(srv *httptest.Server, lg *LastGood, proxy func(*http.Request) (*url.URL, error)) *http.Client {
	tr := guardedTransportResolve(isAPIDestinationBlocked, nil, lg.Resolve)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	tr.DisableKeepAlives = true // every request dials (and looks up)
	tr.Proxy = proxy
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: RefuseRedirects}
}

func newTestLastGood(dns *fakeDNS, now *time.Time) (*LastGood, *eventLog) {
	lg := NewLastGood()
	lg.SetLookup(dns.lookup)
	lg.SetClock(func() time.Time { return *now })
	ev := &eventLog{}
	lg.OnEvent(ev.add)
	return lg, ev
}

func lgGet(c *http.Client, u string) error {
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

// The incident: the platform host stops resolving ("server misbehaving");
// the client keeps reaching the platform at its last-known-good address,
// switches once (one event, not one per request) and back when DNS answers.
func TestLastGood_DNSFailureDialsLastKnownGood(t *testing.T) {
	srv, port := tlsPlatform(t)
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("example.com", "127.0.0.1")
	lg, ev := newTestLastGood(dns, &now)
	lg.Track("example.com", port)
	c := lastGoodClient(srv, lg, nil)
	u := "https://example.com:" + port + "/"

	if err := lgGet(c, u); err != nil {
		t.Fatalf("resolving: %v", err)
	}
	dns.set("example.com") // DNS down
	for i := 0; i < 3; i++ {
		now = now.Add(time.Minute)
		if err := lgGet(c, u); err != nil {
			t.Fatalf("request %d during the outage: %v (want the cached address dialed)", i, err)
		}
	}
	st := lg.Status()
	if len(st) != 1 || st[0].State != LastGoodCached || st[0].Cause != "server_misbehaving" {
		t.Fatalf("status = %+v, want cached with cause server_misbehaving", st)
	}
	dns.set("example.com", "127.0.0.1")
	now = now.Add(time.Minute)
	if err := lgGet(c, u); err != nil {
		t.Fatal(err)
	}
	got := ev.states()
	want := []LastGoodState{LastGoodResolving, LastGoodCached, LastGoodResolving}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v (one per change)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
	last := ev.evs[2]
	if last.FailedAt.IsZero() || !last.FailedAt.Before(last.Since) {
		t.Fatalf("recovery event %+v must name when the outage began", last)
	}
	if s := lg.Status()[0]; s.FailedAt.IsZero() || s.RecoveredAt.IsZero() {
		t.Fatalf("status %+v must keep the last outage", s)
	}
}

// The fallback changes the address dialed, never what is verified: a
// cached address whose server does not hold a certificate for the
// platform's name fails the TLS handshake.
func TestLastGood_TLSStillVerifiesHostName(t *testing.T) {
	srv, port := tlsPlatform(t) // certificate for example.com, not platform.example.net
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("platform.example.net", "127.0.0.1")
	lg, _ := newTestLastGood(dns, &now)
	lg.Track("platform.example.net", port)
	c := lastGoodClient(srv, lg, nil)
	u := "https://platform.example.net:" + port + "/"

	err := lgGet(c, u)
	var herr x509.HostnameError
	if !errors.As(err, &herr) {
		t.Fatalf("resolving: err = %v, want a host name error", err)
	}
	dns.set("platform.example.net")
	err = lgGet(c, u)
	if !errors.As(err, &herr) {
		t.Fatalf("cached address: err = %v, want the same host name error (TLS name check unchanged)", err)
	}
	if lg.Status()[0].State != LastGoodCached {
		t.Fatal("the cached address should have been dialed")
	}
}

// Only a lookup error triggers the fallback: another lookup error, a
// canceled request, a TLS or connect failure do not.
func TestLastGood_OnlyDNSErrors(t *testing.T) {
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("example.com", "127.0.0.1")
	lg, _ := newTestLastGood(dns, &now)
	lg.Track("example.com", "443")
	if _, err := lg.Resolve(context.Background(), "example.com", "443"); err != nil {
		t.Fatal(err)
	}
	dns.set("example.com")

	dns.err = errors.New("not a DNS error")
	if ips, err := lg.Resolve(context.Background(), "example.com", "443"); err == nil || len(ips) > 0 {
		t.Fatalf("non-DNS error: got %v, %v; want the error", ips, err)
	}
	dns.err = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ips, err := lg.Resolve(ctx, "example.com", "443"); err == nil || len(ips) > 0 {
		t.Fatalf("canceled request: got %v, %v; want the error", ips, err)
	}
	if st := lg.Status()[0].State; st != LastGoodResolving {
		t.Fatalf("state = %s: neither error is a DNS outage", st)
	}

	// A TLS failure with a working lookup: the lookup succeeded, so the
	// host stays resolving (nothing to fall back from).
	srv, port := tlsPlatform(t)
	dns.set("platform.example.net", "127.0.0.1")
	lg.Track("platform.example.net", port)
	c := lastGoodClient(srv, lg, nil)
	if err := lgGet(c, "https://platform.example.net:"+port+"/"); err == nil {
		t.Fatal("want a certificate error")
	}
	for _, s := range lg.Status() {
		if s.Host == "platform.example.net:"+port && s.State != LastGoodResolving {
			t.Fatalf("TLS failure changed the DNS state to %s", s.State)
		}
	}
}

// An untracked host (a plain-http URL, any other destination) is looked
// up as usual, and a failure is returned.
func TestLastGood_UntrackedHostNoFallback(t *testing.T) {
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("example.com", "127.0.0.1")
	lg, ev := newTestLastGood(dns, &now)
	lg.TrackURL("http://example.com:8080") // plain http: never tracked
	if _, err := lg.Resolve(context.Background(), "example.com", "8080"); err != nil {
		t.Fatal(err)
	}
	dns.set("example.com")
	if _, err := lg.Resolve(context.Background(), "example.com", "8080"); err == nil {
		t.Fatal("untracked host must not fall back")
	}
	if len(lg.Status()) != 0 || len(ev.states()) != 0 {
		t.Fatalf("untracked host has state: %+v", lg.Status())
	}
	lg.Track("10.0.0.5", "443") // an IP literal has nothing to resolve
	if len(lg.Status()) != 0 {
		t.Fatal("an IP literal must not be tracked")
	}
}

// An address older than the maximum age is not dialed (the platform may
// have moved); 0 turns the fallback off.
func TestLastGood_BoundedStaleness(t *testing.T) {
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("example.com", "127.0.0.1")
	lg, ev := newTestLastGood(dns, &now)
	lg.SetMaxAge(2 * time.Hour)
	lg.Track("example.com", "443")
	if _, err := lg.Resolve(context.Background(), "example.com", "443"); err != nil {
		t.Fatal(err)
	}
	dns.set("example.com")
	now = now.Add(time.Hour)
	if ips, err := lg.Resolve(context.Background(), "example.com", "443"); err != nil || len(ips) != 1 {
		t.Fatalf("within max age: %v, %v", ips, err)
	}
	now = now.Add(2 * time.Hour)
	_, err := lg.Resolve(context.Background(), "example.com", "443")
	var de *net.DNSError
	if !errors.As(err, &de) {
		t.Fatalf("beyond max age: err = %v, want the lookup error", err)
	}
	got := ev.states()
	if got[len(got)-1] != LastGoodFailed {
		t.Fatalf("events %v: want failed last", got)
	}
	if s := lg.Status()[0]; s.Since.IsZero() || !s.Since.Before(now) {
		t.Fatalf("the outage start %v must stay when the cache expires", s.Since)
	}

	off, _ := newTestLastGood(dns, &now)
	off.SetMaxAge(0)
	off.Track("example.com", "443")
	dns.set("example.com", "127.0.0.1")
	_, _ = off.Resolve(context.Background(), "example.com", "443")
	dns.set("example.com")
	if _, err := off.Resolve(context.Background(), "example.com", "443"); err == nil {
		t.Fatal("max age 0 must turn the fallback off")
	}
}

// With a proxy the transport dials the proxy, which resolves the platform:
// the platform's cached address is never dialed directly, and the proxy
// host (never tracked) gets no fallback.
func TestLastGood_ProxyResolves(t *testing.T) {
	srv, port := tlsPlatform(t)
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("example.com", "127.0.0.1")
	lg, _ := newTestLastGood(dns, &now)
	lg.Track("example.com", port)
	if _, err := lg.Resolve(context.Background(), "example.com", port); err != nil {
		t.Fatal(err)
	}
	dns.set("example.com")
	proxyURL, _ := url.Parse("http://proxy.example.net:3128")
	c := lastGoodClient(srv, lg, http.ProxyURL(proxyURL))
	dns.mu.Lock()
	dns.asked = nil
	dns.mu.Unlock()
	if err := lgGet(c, "https://example.com:"+port+"/"); err == nil {
		t.Fatal("the proxy does not resolve: the request must fail, not go direct")
	}
	for _, q := range dns.questions() {
		if q != "proxy.example.net" {
			t.Fatalf("looked up %q: with a proxy only the proxy host is resolved locally", q)
		}
	}
	if st := lg.Status()[0].State; st != LastGoodResolving {
		t.Fatalf("platform state = %s: it was never dialed", st)
	}
}

// The state file lets a sensor restarted during an outage reach the
// platform; it is 0600, bounded, and its addresses pass the dial guard.
func TestLastGood_StateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "platform-addrs.json")
	now := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	dns := &fakeDNS{}
	dns.set("example.com", "192.0.2.10", "169.254.169.254")
	lg, _ := newTestLastGood(dns, &now)
	lg.SetStateFile(path)
	lg.Track("example.com", "443")
	if _, err := lg.Resolve(context.Background(), "example.com", "443"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "169.254.169.254") {
		t.Fatalf("a blocked address was kept: %s", raw)
	}

	// A new process during the outage.
	dns.set("example.com")
	now = now.Add(time.Hour)
	next, _ := newTestLastGood(dns, &now)
	next.SetStateFile(path)
	if _, err := next.Resolve(context.Background(), "example.com", "443"); err == nil {
		t.Fatal("not tracked in this run: the file entry must not be used")
	}
	next.Track("example.com", "443")
	ips, err := next.Resolve(context.Background(), "example.com", "443")
	if err != nil || len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("after restart: %v, %v; want 192.0.2.10 from the state file", ips, err)
	}

	// Planted or broken content is ignored.
	for _, content := range []string{
		"not json",
		`{"v":1,"hosts":{"example.com:443":{"addrs":["169.254.169.254","224.0.0.1"],"resolved_at":"2026-11-06T08:00:00Z"}}}`,
		`{"v":1,"hosts":{"example.com:443":{"addrs":["192.0.2.10"],"resolved_at":"2030-01-01T00:00:00Z"}}}`,
		`{"v":2,"hosts":{"example.com:443":{"addrs":["192.0.2.10"],"resolved_at":"2026-11-06T08:00:00Z"}}}`,
		strings.Repeat(" ", maxLastGoodFileBytes+1),
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		lg3, _ := newTestLastGood(dns, &now)
		lg3.SetStateFile(path)
		lg3.Track("example.com", "443")
		if ips, err := lg3.Resolve(context.Background(), "example.com", "443"); err == nil {
			t.Fatalf("content %.60q: dialed %v, want the lookup error", content, ips)
		}
	}
}

func TestDNSCause(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "server misbehaving", IsTemporary: true}, "server_misbehaving"},
		{&net.DNSError{Err: "i/o timeout", IsTimeout: true}, "timeout"},
		{&net.DNSError{Err: "no such host", IsNotFound: true}, "not_found"},
		{&net.DNSError{Err: "x", IsTemporary: true}, "temporary"},
		{errors.New("x"), "other"},
	} {
		if got := DNSCause(tc.err); got != tc.want {
			t.Errorf("DNSCause(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}

func TestLastGood_TrackBounded(t *testing.T) {
	lg := NewLastGood()
	for i := 0; i < maxLastGoodHosts+4; i++ {
		lg.Track("h"+string(rune('a'+i))+".example.com", "443")
	}
	if n := len(lg.Status()); n != maxLastGoodHosts {
		t.Fatalf("%d hosts tracked, want at most %d", n, maxLastGoodHosts)
	}
}
