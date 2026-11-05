package webdiff

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fastOptions are the bounds of the fixture runs: the same checks, short
// waits.
func fastOptions() Options {
	return Options{Rate: 2000, Deadline: 3 * time.Second, MinRateAfter: 300 * time.Millisecond,
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}
}

// testClient is the client a sensor task gets, with the response header
// bound of a discovery task.
func testClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	tr := &http.Transport{MaxResponseHeaderBytes: DefaultMaxHeaderBytes, DisableCompression: true}
	if dial != nil {
		tr.DialContext = dial
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// run probes every candidate on srv as the webguess tool does: the canary,
// then each candidate; after the first hit it checks whether the origin
// ignores case and then skips candidates that differ only in case. It
// returns the hit paths and the prober.
func run(t *testing.T, srv *httptest.Server, cands []string, o Options) (map[string]*Hit, *Prober) {
	t.Helper()
	p, err := New(testClient(nil), srv.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	return runOn(t, p, cands), p
}

func runOn(t *testing.T, p *Prober, cands []string) map[string]*Hit {
	t.Helper()
	ctx := context.Background()
	hits := map[string]*Hit{}
	if _, err := p.Canary(ctx); err != nil {
		if errors.Is(err, ErrStopped) {
			return hits
		}
		t.Fatalf("canary: %v", err)
	}
	seen := map[string]bool{}
	caseChecked := false
	for _, c := range cands {
		if p.FoldsCase() {
			if seen[strings.ToLower(c)] {
				continue
			}
		}
		seen[strings.ToLower(c)] = true
		r, err := p.Check(ctx, c)
		if errors.Is(err, ErrStopped) {
			break
		}
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if r.Hit != nil {
			hits[r.Hit.Path] = r.Hit
			if !caseChecked {
				caseChecked = true
				if _, err := p.CaseInsensitive(ctx, r.Hit); err != nil && !errors.Is(err, ErrStopped) {
					t.Fatalf("case check: %v", err)
				}
			}
		}
	}
	return hits
}

func keys(m map[string]*Hit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// wantHits fails unless the hits are exactly want.
func wantHits(t *testing.T, hits map[string]*Hit, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := keys(hits); !slices.Equal(got, want) {
		t.Fatalf("hits %v, want %v", got, want)
	}
}

var notFoundPage = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"

func adminPage(n int) string {
	var b strings.Builder
	b.WriteString("<html><head><title>Admin console</title></head><body><h1>Administration</h1><ul>")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "<li><a href=\"/admin/section%d\">Section number %d of the console</a></li>", i, i)
	}
	b.WriteString("</ul></body></html>")
	return b.String()
}

// Plain 404 site: every planted path is found and classified; nothing else.
func TestPlain404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "<html><head><title>Home</title></head><body>welcome</body></html>")
		case "/admin":
			fmt.Fprint(w, adminPage(20))
		case "/backup.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("PK\x03\x04 a zip archive body"))
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=production\nDB_HOST=db\n")
		case "/static", "/static/":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><head><title>403 Forbidden</title></head><body>Directory listing is disabled</body></html>")
		case "/docs":
			http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
		case "/private":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/upload":
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, notFoundPage)
		}
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/admin", "/backup.zip", "/.env", "/static/", "/docs", "/private", "/api/upload",
		"/nothing", "/missing.php", "/.hidden", "/foo/", "/old.bak", "/api/v1"}, fastOptions())
	wantHits(t, hits, "/admin", "/backup.zip", "/.env", "/static/", "/docs", "/private", "/api/upload")
	if h := hits["/static/"]; !slices.Contains(h.Labels, LabelForbidden) || !slices.Contains(h.Labels, LabelDirectory) {
		t.Errorf("/static/ labels %v", h.Labels)
	}
	if h := hits["/docs"]; !slices.Contains(h.Labels, LabelDirectory) {
		t.Errorf("/docs labels %v", h.Labels)
	}
	if h := hits["/private"]; h.Auth != AuthRequired {
		t.Errorf("/private auth %q", h.Auth)
	}
	if h := hits["/backup.zip"]; h.ContentType != "application/zip" || h.Status != 200 || len(h.Hash) != 16 || h.Size == 0 {
		t.Errorf("/backup.zip evidence %+v", h)
	}
	if h := hits["/admin"]; h.Auth != AuthNone || h.Hash != hashOf(Normalize(adminPage(20), "admin")) {
		t.Errorf("/admin evidence %+v", h)
	}
	if p.Stopped() != "" || len(p.Gaps()) != 0 {
		t.Errorf("stopped %q gaps %v", p.Stopped(), p.Gaps())
	}
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// Soft-404: unknown paths answer 200 with a page that carries a timestamp,
// a CSRF token, a nonce and the requested path. None is a hit; the planted
// page is.
func TestSoft404WithDynamicContent(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Set-Cookie", fmt.Sprintf("sid=%x", sha256.Sum256([]byte(fmt.Sprint(i)))))
		if r.URL.Path == "/admin" || r.URL.Path == "/" {
			fmt.Fprint(w, adminPage(30))
			return
		}
		tok := sha256.Sum256([]byte(fmt.Sprint("csrf", i)))
		fmt.Fprintf(w, `<html><head><title>Oops</title><script nonce="%x">var t=1;</script></head><body>
<p>Sorry, the page %s does not exist. Generated at %s (request %d).</p>
<form><input type="hidden" name="csrf" value="%x"><input name="q"></form>
<footer>id %s</footer></body></html>`, tok[:8], r.URL.Path, time.Now().Format(time.RFC3339Nano), i, tok, hex.EncodeToString(tok[:12]))
	}))
	defer srv.Close()
	hits, _ := run(t, srv, []string{"/nothing", "/admin", "/config", "/backup", "/a/b/c", "/x.php", "/y.php", "/z/"}, fastOptions())
	wantHits(t, hits, "/admin")
}

// SPA catch-all: every path answers the app's index. Bare and directory
// guesses are skipped (catch_all); a file shape still runs, so an archive
// served with its own content type is found while a "file" answered with
// the index is not.
func TestSPACatchAll(t *testing.T) {
	index := "<!doctype html><html><head><title>App</title><script src=\"/static/js/main.js\"></script></head><body><div id=\"root\"></div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.zip" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("PK\x03\x04 archive"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, index)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/admin", "/login", "/settings/", "/backup.zip", "/site.tar.gz", "/db.sql", "/.env"}, fastOptions())
	wantHits(t, hits, "/backup.zip")
	if p.Gaps()[GapCatchAll] != 3 {
		t.Errorf("gaps %v, want catch_all for 3 candidates", p.Gaps())
	}
}

// Wildcard subtree: everything under /api/ answers 200 JSON; only the
// planted routes are hits, and the calibration of each directory keeps the
// wildcard answers out.
func TestWildcardAPISubtree(t *testing.T) {
	users := `{"users":[` + strings.Repeat(`{"id":0,"name":"user","email":"user@example.test","roles":["reader","writer"]},`, 40) + `{"id":1}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, users)
		case r.URL.Path == "/api/v1/health":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ok","checks":{"db":"up","cache":"up","queue":"up"},"version":"1.2.3","uptime_seconds":12345}`)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"error":"no route","path":%q}`, r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	hits, _ := run(t, srv, []string{"/api/users", "/api/orders", "/api/admin", "/api/v1/health", "/api/v1/status", "/api/v2/users", "/nothing"}, fastOptions())
	wantHits(t, hits, "/api/users", "/api/v1/health")
}

// Login wall: every path redirects to the login page with itself in the
// query. The redirects are not hits (auth_wall is recorded); a page that
// answers on its own is.
func TestLoginWall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			fmt.Fprint(w, "<html><head><title>Sign in</title></head><body><form>user password</form></body></html>")
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusFound)
		}
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/admin", "/status", "/dashboard", "/login", "/admin/users", "/x.php"}, fastOptions())
	wantHits(t, hits, "/status", "/login")
	if p.Gaps()[GapAuthWall] == 0 {
		t.Errorf("gaps %v, want auth_wall", p.Gaps())
	}
}

// Keyword firewall: every path containing "admin" is refused with 403. The
// child probe shows the refusal is about the word, not a directory: no
// admin path is a hit. A real forbidden directory (its children are 404)
// is.
func TestKeywordWAF403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(strings.ToLower(p), "admin"):
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><head><title>Request blocked</title></head><body>Your request was blocked by the security policy.</body></html>")
		case p == "/secret" || p == "/secret/":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><head><title>403 Forbidden</title></head><body>Forbidden</body></html>")
		case p == "/backup.sql":
			fmt.Fprint(w, "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	hits, _ := run(t, srv, []string{"/admin", "/administrator", "/admin/", "/wp-admin", "/admin.php", "/secret", "/backup.sql", "/other"}, fastOptions())
	wantHits(t, hits, "/secret", "/backup.sql")
	if !slices.Contains(hits["/secret"].Labels, LabelForbidden) {
		t.Errorf("labels %v", hits["/secret"].Labels)
	}
}

const challengePage = `<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></body></html>`

// Edge challenge: the canary meets a challenge page; the origin stops at
// once (edge_protected) and nothing more is sent.
func TestEdgeChallenge(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, challengePage)
	}))
	defer srv.Close()
	p, err := New(testClient(nil), srv.URL, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Canary(context.Background())
	if !errors.Is(err, ErrStopped) || !v.State.Stops() || p.Stopped() != GapEdgeProtected || n.Load() != 1 {
		t.Fatalf("canary: %v %+v stopped %q after %d requests", err, v, p.Stopped(), n.Load())
	}
	if _, err := p.Check(context.Background(), "/admin"); !errors.Is(err, ErrStopped) || n.Load() != 1 {
		t.Fatalf("a stopped origin was probed: %v (%d requests)", err, n.Load())
	}
}

// An edge challenge that starts mid-run stops the origin and is never a hit.
func TestEdgeChallengeMidRun(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) > 6 {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, challengePage)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/a", "/b", "/c", "/d", "/e"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != GapEdgeProtected {
		t.Errorf("stopped %q", p.Stopped())
	}
}

// 429 with Retry-After on every third request: the prober backs off and
// retries; no rate-limited answer is a hit and the planted path is found.
func TestRateLimited429(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%3 == 0 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "slow down")
			return
		}
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, adminPage(10))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/x1", "/admin", "/x2", "/x3", "/x4", "/x5"}, fastOptions())
	wantHits(t, hits, "/admin")
	if p.Stopped() != "" {
		t.Errorf("stopped %q", p.Stopped())
	}
}

// A host that answers 429 to everything stops the origin (throttled) and
// gives no hit.
func TestAlways429StopsThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, "home")
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/a", "/b", "/c", "/d"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != GapThrottled {
		t.Errorf("stopped %q, gaps %v", p.Stopped(), p.Gaps())
	}
}

// A host that answers some requests and resets the connection on the
// others: retried, never a hit, the planted path is still found.
func TestResetAfterAnswers(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%4 == 0 {
			hj, _ := w.(http.Hijacker)
			c, _, err := hj.Hijack()
			if err == nil {
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_ = c.Close()
			}
			return
		}
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, adminPage(10))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hits, _ := run(t, srv, []string{"/x1", "/admin", "/x2", "/x3", "/x4", "/x5", "/x6"}, fastOptions())
	wantHits(t, hits, "/admin")
}

// A flapping baseline (random paths answer 404 or 200 in turn): the class
// is skipped (unstable_baseline), never guessed from.
func TestFlappingBaseline(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, "home page")
			return
		}
		if n.Add(1)%2 == 0 {
			fmt.Fprint(w, "<html><head><title>Something</title></head><body>maybe</body></html>")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/a", "/b", "/c", "/d", "/e", "/f"}, fastOptions())
	wantHits(t, hits)
	if p.Gaps()[GapUnstableBaseline] == 0 {
		t.Errorf("gaps %v, want unstable_baseline", p.Gaps())
	}
}

// A server that ignores case: the planted path is found once; the case
// check makes the caller skip the other spellings.
func TestCaseInsensitiveServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.URL.Path, "/admin") {
			fmt.Fprint(w, adminPage(10))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/admin", "/Admin", "/ADMIN", "/nothing", "/Nothing"}, fastOptions())
	wantHits(t, hits, "/admin")
	if !p.FoldsCase() {
		t.Error("the case-insensitive server was not detected")
	}
	// A case-sensitive server is not read as one that folds case.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, adminPage(10))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv2.Close()
	hits, p = run(t, srv2, []string{"/admin", "/Admin"}, fastOptions())
	wantHits(t, hits, "/admin")
	if p.FoldsCase() {
		t.Error("a case-sensitive server was read as folding case")
	}
}

// SECURITY: a gzip bomb (1 GiB of zeros) is not decoded past the ratio
// bound: the origin stops (hostile_response) and the test ends quickly.
func TestGzipBomb(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bomb.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/zip")
		zw, _ := gzip.NewWriterLevel(w, gzip.BestCompression)
		zero := make([]byte, 1<<20)
		for i := 0; i < 1024; i++ {
			if _, err := zw.Write(zero); err != nil {
				return
			}
		}
		_ = zw.Close()
	}))
	defer srv.Close()
	start := time.Now()
	hits, p := run(t, srv, []string{"/a", "/bomb.zip", "/b"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != GapHostileResponse || time.Since(start) > 20*time.Second {
		t.Fatalf("stopped %q after %s", p.Stopped(), time.Since(start))
	}
}

// SECURITY: a body sent at one byte per second (slowloris) is cut at the
// minimum transfer rate: the origin stops (hostile_response).
func TestSlowloris(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 60; i++ {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-time.After(time.Second):
			case <-r.Context().Done():
				return
			case <-done:
				return
			}
		}
	}))
	defer srv.Close()
	defer close(done)
	start := time.Now()
	hits, p := run(t, srv, []string{"/a", "/slow"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != GapHostileResponse || time.Since(start) > 5*time.Second {
		t.Fatalf("stopped %q after %s", p.Stopped(), time.Since(start))
	}
}

// SECURITY: a 10 MB header is refused at the header bound (hostile_response).
func TestHugeHeader(t *testing.T) {
	big := strings.Repeat("a", 10<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/big" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Big", big)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/a", "/big"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != GapHostileResponse {
		t.Fatalf("stopped %q", p.Stopped())
	}
	// Without a transport bound, the prober's own check still refuses it.
	p2, _ := New(&http.Client{Transport: &http.Transport{DisableCompression: true}}, srv.URL, fastOptions())
	hits = runOn(t, p2, []string{"/a", "/big"})
	wantHits(t, hits)
	if p2.Stopped() != GapHostileResponse {
		t.Fatalf("no transport bound: stopped %q", p2.Stopped())
	}
}

// An endless chunked body is read up to MaxBody only: missing paths that
// stream forever compare alike, and the planted page is found.
func TestInfiniteChunked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, adminPage(10))
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, "home")
			return
		}
		line := []byte("streaming the same text over and over again\n")
		for {
			if _, err := w.Write(line); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	start := time.Now()
	hits, p := run(t, srv, []string{"/x", "/admin", "/y"}, fastOptions())
	wantHits(t, hits, "/admin")
	if p.Stopped() != "" || time.Since(start) > 10*time.Second {
		t.Fatalf("stopped %q after %s", p.Stopped(), time.Since(start))
	}
}

// SECURITY: redirects are never followed: a redirect to the metadata
// address or to another local service is only read as a pattern; no
// connection is attempted to either.
func TestRedirectsNeverFollowed(t *testing.T) {
	var other atomic.Int64
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		other.Add(1)
		fmt.Fprint(w, "internal")
	}))
	defer inner.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/meta":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/local":
			http.Redirect(w, r, inner.URL+"/x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var mu sync.Mutex
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		if strings.HasPrefix(addr, "169.254.") {
			return nil, errors.New("refused by the test")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	p, err := New(testClient(dial), srv.URL, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	hits := runOn(t, p, []string{"/meta", "/local", "/none"})
	wantHits(t, hits, "/meta", "/local")
	mu.Lock()
	defer mu.Unlock()
	srvHost := strings.TrimPrefix(srv.URL, "http://")
	for _, a := range dialed {
		if a != srvHost {
			t.Errorf("dialed %s", a)
		}
	}
	if other.Load() != 0 {
		t.Errorf("the other local service was requested %d times", other.Load())
	}
}

// The prober's own budget stops the origin (budget) and is never exceeded;
// the sensor's refusal of a request past the job's cap does the same.
func TestBudget(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	o := fastOptions()
	o.MaxRequests = 7
	hits, p := run(t, srv, []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g"}, o)
	wantHits(t, hits)
	if p.Stopped() != GapBudget || n.Load() != 7 || p.Requests() != 7 {
		t.Fatalf("stopped %q after %d requests (%d counted)", p.Stopped(), n.Load(), p.Requests())
	}
	var m atomic.Int64
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Add(1) > 5 {
			w.Header().Set("X-Openctem-Egress", "refused")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "outside the job's web scope: request cap reached: 5 requests to app.test")
			return
		}
		http.NotFound(w, r)
	}))
	defer refusing.Close()
	hits, p = run(t, refusing, []string{"/a", "/b", "/c"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != GapBudget {
		t.Fatalf("stopped %q", p.Stopped())
	}
}

// A path the sensor refuses for scope is counted as scope_filtered, not a
// hit and not a stop.
func TestScopeRefusalCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/private") {
			w.Header().Set("X-Openctem-Egress", "refused")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "outside the job's web scope: path /private is denied")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	hits, p := run(t, srv, []string{"/private", "/public"}, fastOptions())
	wantHits(t, hits)
	if p.Stopped() != "" || p.Gaps()[GapScopeFiltered] != 1 {
		t.Fatalf("stopped %q gaps %v", p.Stopped(), p.Gaps())
	}
}

// Baselines live in the prober: a new prober (a new task) calibrates again
// and keeps nothing of another's.
func TestBaselinesArePerProber(t *testing.T) {
	var paths sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths.Store(r.URL.Path, true)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, p1 := run(t, srv, []string{"/a"}, fastOptions())
	_, p2 := run(t, srv, []string{"/a"}, fastOptions())
	if p1.Requests() != p2.Requests() || p2.Requests() < 5 {
		t.Fatalf("requests %d and %d: the second task reused a baseline", p1.Requests(), p2.Requests())
	}
}

// The prober recalibrates after RecalibrateAfter requests.
func TestRecalibrates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	o := fastOptions()
	o.RecalibrateAfter = 10
	cands := make([]string, 30)
	for i := range cands {
		cands[i] = fmt.Sprintf("/c%d", i)
	}
	_, p := run(t, srv, cands, o)
	if p.gen < 2 {
		t.Fatalf("generation %d after %d requests", p.gen, p.Requests())
	}
}

func TestNewRefusesNonOrigins(t *testing.T) {
	for _, o := range []string{"", "ftp://x", "https://", "https://u:p@x", "https://x/path", "https://x?q=1", "https://x#f"} {
		if _, err := New(http.DefaultClient, o, Options{}); err == nil {
			t.Errorf("%q accepted", o)
		}
	}
	p, err := New(http.DefaultClient, "https://app.example.com:8443/", Options{})
	if err != nil || p.Origin() != "https://app.example.com:8443" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := p.Check(context.Background(), "admin"); err == nil {
		t.Error("a relative candidate was accepted")
	}
	if _, err := p.Check(context.Background(), "/a?x=1"); err == nil {
		t.Error("a candidate with a query was accepted")
	}
}
