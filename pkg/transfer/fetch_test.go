package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blobServer serves one blob with programmable faults.
type blobServer struct {
	data []byte
	mu   sync.Mutex
	// fault decides the answer of request n (1-based); nil: serve normally.
	fault  func(n int, w http.ResponseWriter, r *http.Request) bool
	n      int
	ranges []string
}

func (s *blobServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.n++
	n := s.n
	s.ranges = append(s.ranges, r.Header.Get("Range"))
	s.mu.Unlock()
	if s.fault != nil && s.fault(n, w, r) {
		return
	}
	serveRange(w, r, s.data)
}

func (s *blobServer) requests() int { s.mu.Lock(); defer s.mu.Unlock(); return s.n }

func serveRange(w http.ResponseWriter, r *http.Request, data []byte) {
	if rg := r.Header.Get("Range"); rg != "" {
		off, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rg, "bytes="), "-"))
		if off >= len(data) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, len(data)-1, len(data)))
		w.Header().Set("Content-Length", strconv.Itoa(len(data)-off))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(data[off:])
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// dropAfter writes half the body then kills the connection.
func dropAfter(w http.ResponseWriter, r *http.Request, data []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data[:len(data)/2])
	w.(http.Flusher).Flush()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return ctx.Err()
}

func newFetcher(t *testing.T, client *http.Client, origins ...Origin) (*Fetcher, *sleeps) {
	t.Helper()
	sl := &sleeps{}
	f, err := New(Config{Origins: origins, Client: client, CacheDir: t.TempDir(), sleep: sl.sleep,
		Policy: Policy{StallTimeout: 300 * time.Millisecond, AttemptTimeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	return f, sl
}

func TestBlob(t *testing.T) {
	data := payload(200_000)
	sum := digest(data)
	corrupt := append([]byte{}, data...)
	corrupt[1000] ^= 0xff

	cases := []struct {
		name      string
		primary   func(n int, w http.ResponseWriter, r *http.Request) bool
		noMirror  bool
		wantErr   error
		check     func(t *testing.T, st Stats, p, m *blobServer, sl *sleeps)
		mirrorErr bool
	}{
		{
			name: "dropped connection mid-chunk resumes with Range",
			primary: func(n int, w http.ResponseWriter, r *http.Request) bool {
				if n == 1 {
					dropAfter(w, r, data)
					return true
				}
				return false
			},
			check: func(t *testing.T, st Stats, p, m *blobServer, _ *sleeps) {
				if st.Resumes != 1 || st.Retries != 1 || st.Fallbacks != 0 {
					t.Fatalf("stats %+v", st)
				}
				if p.ranges[1] != fmt.Sprintf("bytes=%d-", len(data)/2) {
					t.Fatalf("second request Range %q", p.ranges[1])
				}
				if st.Bytes != uint64(len(data)) {
					t.Fatalf("downloaded %d bytes, want %d (no re-download)", st.Bytes, len(data))
				}
			},
		},
		{
			name: "server ignoring Range restarts from zero",
			primary: func(n int, w http.ResponseWriter, r *http.Request) bool {
				if n == 1 {
					dropAfter(w, r, data)
					return true
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				_, _ = w.Write(data) // 200 despite Range
				return true
			},
			check: func(t *testing.T, st Stats, _, _ *blobServer, _ *sleeps) {
				if st.Resumes != 0 || st.Retries != 1 {
					t.Fatalf("stats %+v", st)
				}
			},
		},
		{
			name: "stall guard aborts and resumes",
			primary: func(n int, w http.ResponseWriter, r *http.Request) bool {
				if n == 1 {
					w.Header().Set("Content-Length", strconv.Itoa(len(data)))
					_, _ = w.Write(data[:1000])
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
					case <-time.After(3 * time.Second):
					}
					return true
				}
				return false
			},
			check: func(t *testing.T, st Stats, _, _ *blobServer, _ *sleeps) {
				if st.Resumes != 1 {
					t.Fatalf("stats %+v", st)
				}
			},
		},
		{
			name: "corrupted chunk on primary falls back to mirror",
			primary: func(_ int, w http.ResponseWriter, r *http.Request) bool {
				serveRange(w, r, corrupt)
				return true
			},
			check: func(t *testing.T, st Stats, p, m *blobServer, _ *sleeps) {
				if st.Fallbacks != 1 || p.requests() != 1 || m.requests() != 1 {
					t.Fatalf("stats %+v primary=%d mirror=%d", st, p.requests(), m.requests())
				}
			},
		},
		{
			name: "429 storm honors Retry-After then succeeds",
			primary: func(n int, w http.ResponseWriter, _ *http.Request) bool {
				if n <= 3 {
					w.Header().Set("Retry-After", "7")
					w.WriteHeader(http.StatusTooManyRequests)
					return true
				}
				return false
			},
			check: func(t *testing.T, st Stats, _, m *blobServer, sl *sleeps) {
				if st.Retries != 3 || m.requests() != 0 {
					t.Fatalf("stats %+v mirror=%d", st, m.requests())
				}
				for _, d := range sl.d {
					if d != 7*time.Second {
						t.Fatalf("slept %v, want the Retry-After 7s", d)
					}
				}
			},
		},
		{
			name: "429 with Retry-After beyond the cap moves to the mirror",
			primary: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Retry-After", "86400")
				w.WriteHeader(http.StatusTooManyRequests)
				return true
			},
			check: func(t *testing.T, st Stats, p, _ *blobServer, sl *sleeps) {
				if st.Fallbacks != 1 || p.requests() != 1 || len(sl.d) != 0 {
					t.Fatalf("stats %+v primary=%d sleeps=%v", st, p.requests(), sl.d)
				}
			},
		},
		{
			name: "503 exhausts attempts then mirror",
			primary: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
				w.WriteHeader(http.StatusServiceUnavailable)
				return true
			},
			check: func(t *testing.T, st Stats, p, _ *blobServer, _ *sleeps) {
				if p.requests() != DefaultMaxAttempts || st.Fallbacks != 1 {
					t.Fatalf("stats %+v primary=%d", st, p.requests())
				}
			},
		},
		{
			name: "404 is not retried",
			primary: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
				w.WriteHeader(http.StatusNotFound)
				return true
			},
			check: func(t *testing.T, st Stats, p, _ *blobServer, _ *sleeps) {
				if p.requests() != 1 || st.Retries != 0 {
					t.Fatalf("stats %+v primary=%d", st, p.requests())
				}
			},
		},
		{
			name: "oversized body is refused",
			primary: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
				_, _ = w.Write(append(append([]byte{}, data...), 1, 2, 3))
				return true
			},
			noMirror: true,
			wantErr:  ErrTooLarge,
		},
		{
			name: "every origin corrupt fails",
			primary: func(_ int, w http.ResponseWriter, r *http.Request) bool {
				serveRange(w, r, corrupt)
				return true
			},
			mirrorErr: true,
			wantErr:   ErrHashMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &blobServer{data: data, fault: tc.primary}
			m := &blobServer{data: data}
			if tc.mirrorErr {
				m.fault = func(_ int, w http.ResponseWriter, r *http.Request) bool { serveRange(w, r, corrupt); return true }
			}
			ps, ms := httptest.NewServer(p), httptest.NewServer(m)
			defer ps.Close()
			defer ms.Close()
			origins := []Origin{{URL: ps.URL}}
			if !tc.noMirror {
				origins = append(origins, Origin{URL: ms.URL + "/mirror/"})
			}
			f, sl := newFetcher(t, ps.Client(), origins...)
			path, err := f.Blob(context.Background(), "sha256-"+sum+".jsonl.gz", sum, int64(len(data)))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrAllOriginsFailed) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if f.Stats().Failures != 1 {
					t.Fatalf("stats %+v", f.Stats())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, data) {
				t.Fatal("blob content differs")
			}
			if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
				t.Fatalf("blob mode %v", st.Mode().Perm())
			}
			tc.check(t, f.Stats(), p, m, sl)
		})
	}
}

func TestBlobCacheHitAndRestartResume(t *testing.T) {
	data := payload(50_000)
	sum := digest(data)
	p := &blobServer{data: data}
	ps := httptest.NewServer(p)
	defer ps.Close()
	cache := t.TempDir()
	// A previous process left half the blob in tmp.
	if err := os.MkdirAll(filepath.Join(cache, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "tmp", sum+".part"), data[:20_000], 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := New(Config{Origins: []Origin{{URL: ps.URL}}, Client: ps.Client(), CacheDir: cache})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Blob(context.Background(), "b", sum, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if p.ranges[0] != "bytes=20000-" || f.Stats().Resumes != 1 {
		t.Fatalf("range %q stats %+v", p.ranges[0], f.Stats())
	}
	if _, err := f.Blob(context.Background(), "b", sum, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if p.requests() != 1 || f.Stats().CacheHits != 1 {
		t.Fatalf("second Blob downloaded again: requests=%d stats=%+v", p.requests(), f.Stats())
	}
	// A tampered cache entry is detected and fetched again.
	if err := os.WriteFile(f.BlobPath(sum), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Blob(context.Background(), "b", sum, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if p.requests() != 2 {
		t.Fatalf("tampered cache not refetched: %d", p.requests())
	}
	if n, _ := f.PruneBlobs(map[string]bool{}); n != 1 {
		t.Fatalf("pruned %d", n)
	}
}

func TestBlobStaleResumeStartsOver(t *testing.T) {
	data := payload(30_000)
	sum := digest(data)
	p := &blobServer{data: data}
	ps := httptest.NewServer(p)
	defer ps.Close()
	cache := t.TempDir()
	_ = os.MkdirAll(filepath.Join(cache, "tmp"), 0o700)
	junk := bytes.Repeat([]byte{9}, 10_000) // not a prefix of data
	_ = os.WriteFile(filepath.Join(cache, "tmp", sum+".part"), junk, 0o600)
	f, _ := New(Config{Origins: []Origin{{URL: ps.URL}}, Client: ps.Client(), CacheDir: cache, sleep: (&sleeps{}).sleep})
	if _, err := f.Blob(context.Background(), "b", sum, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if p.requests() != 2 || p.ranges[1] != "" {
		t.Fatalf("requests=%d ranges=%q", p.requests(), p.ranges)
	}
}

func TestLocalOriginFallback(t *testing.T) {
	data := payload(10_000)
	sum := digest(data)
	dir := t.TempDir()
	name := "sha256-" + sum + ".jsonl.gz"
	_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "latest.json"), []byte("ptr"), 0o600)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer down.Close()
	f, _ := newFetcher(t, down.Client(), Origin{URL: down.URL}, Origin{Dir: dir})
	if _, err := f.Blob(context.Background(), name, sum, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	b, err := f.Small(context.Background(), "latest.json", 100)
	if err != nil || string(b) != "ptr" {
		t.Fatalf("small = %q, %v", b, err)
	}
	if f.Stats().Fallbacks != 2 {
		t.Fatalf("stats %+v", f.Stats())
	}
}

func TestCircuitBreakerSkipsFailingOrigin(t *testing.T) {
	var primary atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primary.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer good.Close()
	f, _ := newFetcher(t, bad.Client(), Origin{URL: bad.URL}, Origin{URL: good.URL})
	for range DefaultBreakerThreshold + 2 {
		if _, err := f.Small(context.Background(), "x.json", 10); err != nil {
			t.Fatal(err)
		}
	}
	if got := primary.Load(); got != int32(DefaultBreakerThreshold*DefaultMaxAttempts) {
		t.Fatalf("primary got %d requests, want %d (circuit should open)", got, DefaultBreakerThreshold*DefaultMaxAttempts)
	}
	if f.Stats().CircuitSkip != 2 {
		t.Fatalf("stats %+v", f.Stats())
	}
}

func TestSmallConditionalGet(t *testing.T) {
	var full atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("pointer-v1"))
	}))
	defer srv.Close()
	f, _ := newFetcher(t, srv.Client(), Origin{URL: srv.URL})
	for range 3 {
		b, err := f.Small(context.Background(), "latest.json", 100)
		if err != nil || string(b) != "pointer-v1" {
			t.Fatalf("%q %v", b, err)
		}
	}
	if full.Load() != 1 || f.Stats().NotModified != 2 {
		t.Fatalf("full=%d stats=%+v", full.Load(), f.Stats())
	}
	if _, err := f.Small(context.Background(), "latest.json", 5); !errors.Is(err, ErrTooLarge) {
		// the cached body is larger than this cap: a full GET is made and refused
		t.Fatalf("err = %v", err)
	}
}

func TestNamesAndConfig(t *testing.T) {
	f, _ := newFetcher(t, http.DefaultClient, Origin{Dir: t.TempDir()})
	for _, n := range []string{"../x", "a/b", "", ".hidden", "a..b", `a\b`} {
		if _, err := f.Small(context.Background(), n, 10); !errors.Is(err, ErrBadName) {
			t.Errorf("Small(%q) err = %v", n, err)
		}
	}
	if _, err := f.Blob(context.Background(), "x", "nothex", 1); err == nil {
		t.Error("bad digest accepted")
	}
	for _, o := range []Origin{{}, {URL: "ftp://x"}, {URL: "https://u:p@x"}, {URL: "https://x/?q=1"}} {
		if _, err := New(Config{Origins: []Origin{o}}); err == nil {
			t.Errorf("origin %+v accepted", o)
		}
	}
	if _, err := New(Config{}); err == nil {
		t.Error("no origin accepted")
	}
}

func TestOverallDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	f, err := New(Config{Origins: []Origin{{URL: srv.URL}}, Client: srv.Client(),
		Policy: Policy{Overall: 150 * time.Millisecond, BackoffBase: time.Second, MaxAttempts: 10}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = f.Small(context.Background(), "x", 10)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"": 0, "5": 5 * time.Second, "-1": 0, "junk": 0,
		now.Add(30 * time.Second).Format(http.TimeFormat): 30 * time.Second,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
	for a := 1; a < 10; a++ {
		d := backoff(time.Second, 8*time.Second, a)
		if d < 500*time.Millisecond || d > 8*time.Second {
			t.Fatalf("backoff(%d) = %v", a, d)
		}
	}
}
