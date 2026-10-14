package contentcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// platform is a fake of the platform's sensor content routes that counts
// the bytes it sends.
type platform struct {
	mu      sync.Mutex
	packs   map[string][]byte // digest -> canonical archive
	files   map[string]map[string][]byte
	desired DesiredState
	etag    string
	sent    map[string]int64 // route -> bytes
	tamper  bool             // serve a wrong file body
	srv     *httptest.Server
}

func newPlatform(t *testing.T) *platform {
	t.Helper()
	p := &platform{packs: map[string][]byte{}, files: map[string]map[string][]byte{}, sent: map[string]int64{}}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *platform) write(w http.ResponseWriter, route string, b []byte) {
	p.mu.Lock()
	p.sent[route] += int64(len(b))
	p.mu.Unlock()
	_, _ = w.Write(b)
}

func (p *platform) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	path := r.URL.Path
	switch {
	case path == "/desired":
		etag := p.etag
		doc, _ := json.Marshal(p.desired)
		p.mu.Unlock()
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		p.write(w, "desired", doc)
		return
	case strings.HasSuffix(path, "/index"):
		d := strings.TrimSuffix(strings.TrimPrefix(path, "/packs/"), "/index")
		var idx []IndexEntry
		for _, f := range mustRead(p.packs[d]) {
			idx = append(idx, IndexEntry{Path: f.path, SHA256: sha256Hex(f.data), Size: int64(len(f.data))})
		}
		b, _ := json.Marshal(idx)
		p.mu.Unlock()
		p.write(w, "index", b)
		return
	case strings.Contains(path, "/files/"):
		parts := strings.Split(strings.TrimPrefix(path, "/packs/"), "/files/")
		var body []byte
		for _, f := range mustRead(p.packs[parts[0]]) {
			if sha256Hex(f.data) == parts[1] {
				body = f.data
			}
		}
		tamper := p.tamper
		p.mu.Unlock()
		if body == nil {
			http.NotFound(w, r)
			return
		}
		if tamper {
			body = append([]byte("x"), body...)
		}
		p.write(w, "file", body)
		return
	case strings.HasPrefix(path, "/packs/"):
		b, ok := p.packs[strings.TrimPrefix(path, "/packs/")]
		p.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		p.write(w, "pack", b)
		return
	}
	p.mu.Unlock()
	http.NotFound(w, r)
}

func mustRead(b []byte) []file {
	fs, _ := readArchive(b, DefaultLimits)
	return fs
}

// publish makes a canonical pack of files, signed for tenant-a, and puts it
// in the desired set.
func (p *platform) publish(t *testing.T, f *fixture, files map[string]string) Pack {
	t.Helper()
	var fs []file
	for n, d := range files {
		fs = append(fs, file{n, []byte(d)})
	}
	b, err := canonicalTar(fs)
	if err != nil {
		t.Fatal(err)
	}
	d := digestOf(b)
	st := Statement{TenantID: "tenant-a", PackID: "p", Name: "n", Version: d[7:15], Content: "nuclei-templates", Digest: d, Size: int64(len(b)), Files: len(files), Tier: "T0"}
	pk := Pack{Digest: d, Scope: ScopeTenant, Size: int64(len(b)), Signature: sign(t, f.tenantK, st)}
	p.mu.Lock()
	p.packs[d] = b
	p.desired = DesiredState{Packs: []Pack{pk}}
	sum := sha256.Sum256([]byte(d))
	p.etag = `"` + hex.EncodeToString(sum[:8]) + `"`
	p.mu.Unlock()
	return pk
}

func (p *platform) fetcher() *HTTPFetcher {
	return &HTTPFetcher{BaseURL: p.srv.URL, Do: p.srv.Client().Do}
}

func (p *platform) bytes(route string) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent[route]
}

func corpus(n int, changed map[int]string) map[string]string {
	out := map[string]string{}
	for i := 0; i < n; i++ {
		body := fmt.Sprintf("id: template-%04d\ninfo:\n  name: t%d\n%s", i, i, strings.Repeat("# padding line\n", 20))
		if c, ok := changed[i]; ok {
			body += c
		}
		out[fmt.Sprintf("http/t-%04d.yaml", i)] = body
	}
	return out
}

// A new version of a held pack downloads only the files that changed; the
// rebuilt archive matches the signed digest, the stats show the savings.
func TestDeltaInstallFetchesOnlyChangedFiles(t *testing.T) {
	f := newFixture(t)
	p := newPlatform(t)
	fetch := p.fetcher()
	c, err := Open(filepath.Join(t.TempDir(), "c"), Options{TenantID: "tenant-a", TenantKeys: f.cache.opts.TenantKeys, Fetch: fetch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeTree(c.Root()) })
	v1 := p.publish(t, f, corpus(200, nil))
	if _, err := c.Install(context.Background(), v1); err != nil {
		t.Fatal(err)
	}
	full := p.bytes("pack")
	if full == 0 || c.Stats().Misses != 1 {
		t.Fatalf("first install: %d bytes, %+v", full, c.Stats())
	}
	v2 := p.publish(t, f, corpus(200, map[int]string{3: "# changed\n", 77: "# changed\n"}))
	dir, err := c.Install(context.Background(), v2)
	if err != nil {
		t.Fatal(err)
	}
	if p.bytes("pack") != full {
		t.Fatalf("the full archive was downloaded again")
	}
	files := p.bytes("file")
	if files == 0 || files > full/50 {
		t.Fatalf("delta fetched %d file bytes (full archive %d)", files, full)
	}
	got, err := os.ReadFile(filepath.Join(dir, "http", "t-0077.yaml"))
	if err != nil || !strings.HasSuffix(string(got), "# changed\n") {
		t.Fatalf("changed file not installed: %q %v", got, err)
	}
	st := c.Stats()
	if st.DeltaInstalls != 1 || st.BytesSaved <= 0 || st.BytesDownloaded != full+files {
		t.Fatalf("stats %+v (full %d, files %d)", st, full, files)
	}
	// Held: no request at all, a hit.
	before := p.bytes("pack") + p.bytes("file") + p.bytes("index")
	if _, err := c.Install(context.Background(), v2); err != nil {
		t.Fatal(err)
	}
	if after := p.bytes("pack") + p.bytes("file") + p.bytes("index"); after != before || c.Stats().Hits != 1 {
		t.Fatalf("a held pack was fetched again: %d -> %d, %+v", before, after, c.Stats())
	}
}

// SECURITY: files that do not match the index are refused; the install
// falls back to the full archive, which is verified against the signed
// digest, so tampered delta files never reach the cache.
func TestDeltaTamperedFileFallsBackToVerifiedArchive(t *testing.T) {
	f := newFixture(t)
	p := newPlatform(t)
	c, err := Open(filepath.Join(t.TempDir(), "c"), Options{TenantID: "tenant-a", TenantKeys: f.cache.opts.TenantKeys, Fetch: p.fetcher()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeTree(c.Root()) })
	if _, err := c.Install(context.Background(), p.publish(t, f, corpus(20, nil))); err != nil {
		t.Fatal(err)
	}
	p.tamper = true
	v2 := p.publish(t, f, corpus(20, map[int]string{1: "# changed\n"}))
	dir, err := c.Install(context.Background(), v2)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "http", "t-0001.yaml")); strings.HasPrefix(string(b), "x") {
		t.Fatal("tampered file installed")
	}
	if c.Stats().DeltaInstalls != 0 {
		t.Fatalf("tampered delta counted as installed: %+v", c.Stats())
	}
}

// The desired-state document is fetched with If-None-Match: unchanged, the
// platform answers 304 with no body and the last document is reused.
func TestDesiredConditional(t *testing.T) {
	f := newFixture(t)
	p := newPlatform(t)
	p.publish(t, f, corpus(5, nil))
	fetch := p.fetcher()
	d1, changed, err := fetch.Desired(context.Background())
	if err != nil || !changed || len(d1.Packs) != 1 {
		t.Fatalf("%+v %v %v", d1, changed, err)
	}
	sent := p.bytes("desired")
	d2, changed, err := fetch.Desired(context.Background())
	if err != nil || changed || d2 != d1 || p.bytes("desired") != sent {
		t.Fatalf("unchanged document resent: %v %v bytes %d->%d", changed, err, sent, p.bytes("desired"))
	}
	p.publish(t, f, corpus(5, map[int]string{0: "x"}))
	if _, changed, err := fetch.Desired(context.Background()); err != nil || !changed {
		t.Fatalf("new desired set not fetched: %v %v", changed, err)
	}
}

// Prefetch installs the desired set on a wake-up, before any scan asks.
func TestPrefetchOnWake(t *testing.T) {
	f := newFixture(t)
	p := newPlatform(t)
	pk := p.publish(t, f, corpus(10, nil))
	c, err := Open(filepath.Join(t.TempDir(), "c"), Options{TenantID: "tenant-a", TenantKeys: f.cache.opts.TenantKeys, Fetch: p.fetcher()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeTree(c.Root()) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	done := make(chan SyncReport, 4)
	go c.Prefetch(ctx, p.fetcher(), time.Hour, wake, func(r SyncReport, err error) {
		if err == nil {
			done <- r
		}
	})
	wake <- struct{}{}
	select {
	case r := <-done:
		if len(r.Installed) != 1 || r.Installed[0] != pk.Digest {
			t.Fatalf("report %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("prefetch did not run on wake")
	}
	if _, ok := c.Path(pk.Digest); !ok {
		t.Fatal("not held after prefetch")
	}
}
