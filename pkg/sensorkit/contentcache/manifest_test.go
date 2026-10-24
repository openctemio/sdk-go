package contentcache

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
)

func manifestOf(packs ...Pack) ContentManifest {
	m := ContentManifest{Version: 1}
	s := ManifestSlot{Slot: "rules", Kind: "semgrep-rules", DisabledRules: []string{"a:x"}, QuarantinedRules: []string{"a:y"}}
	for i, p := range packs {
		s.Sources = append(s.Sources, ManifestSource{Source: "src-" + string(rune('a'+i)), Digest: p.Digest, Scope: p.Scope, Size: p.Size, Signature: p.Signature})
	}
	m.Slots = []ManifestSlot{s}
	return m
}

func TestEnsureInstallsAndPrepareSetsPaths(t *testing.T) {
	f := newFixture(t)
	p1 := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r1.yaml": "a"})
	p2 := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"r2.yaml": "b"})
	m := manifestOf(p1, p2)
	var task tool.Task
	release, err := f.cache.Prepare(context.Background(), m, &task, EnsureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if len(task.Content) != 1 || len(task.Content[0].Packs) != 2 || task.Content[0].Packs[0].Source != "src-a" ||
		task.Content[0].Packs[0].Digest != p1.Digest || task.Content[0].Packs[1].Path == "" {
		t.Fatalf("task content %+v", task.Content)
	}
}

func TestEnsureCacheHitNoNetwork(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	m := manifestOf(p)
	if _, err := f.cache.Ensure(context.Background(), m, EnsureOptions{}); err != nil {
		t.Fatal(err)
	}
	before := f.fetch.calls
	f.fetch.blobs = map[string][]byte{} // upstream gone
	rep, err := f.cache.Ensure(context.Background(), m, EnsureOptions{})
	if err != nil || f.fetch.calls != before || len(rep.Held) != 1 || len(rep.Installed) != 0 {
		t.Fatalf("hit: %v calls %d->%d %+v", err, before, f.fetch.calls, rep)
	}
}

func TestEnsureRevokedDigestRefusedBeforeNetwork(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	m := manifestOf(p)
	m.Revoked = []string{p.Digest}
	if _, err := f.cache.Ensure(context.Background(), m, EnsureOptions{}); !errors.Is(err, ErrRevoked) || f.fetch.calls != 0 {
		t.Fatalf("revoked: %v calls %d", err, f.fetch.calls)
	}
	// The revocation sticks for a later manifest that does not list it.
	if _, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{}); !errors.Is(err, ErrRevoked) || f.fetch.calls != 0 {
		t.Fatalf("revoked later: %v calls %d", err, f.fetch.calls)
	}
}

func TestEnsureRevokingHeldPackRemovesIt(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	if _, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{}); err != nil {
		t.Fatal(err)
	}
	m := manifestOf(p)
	m.Revoked = []string{p.Digest}
	if _, err := f.cache.Ensure(context.Background(), m, EnsureOptions{}); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if len(f.cache.Held()) != 0 {
		t.Fatalf("held %v", f.cache.Held())
	}
}

func TestEnsureTamperedPackRefused(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	f.fetch.blobs[p.Digest] = tarOf(t, map[string]string{"r.yaml": "evil"}) // other bytes under the digest
	_, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{})
	if !errors.Is(err, ErrVerify) || len(f.cache.Held()) != 0 {
		t.Fatalf("tampered: %v held %v", err, f.cache.Held())
	}
}

func TestEnsureWrongDigestRefused(t *testing.T) {
	f := newFixture(t)
	p1 := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	p2 := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "b"})
	// p2's digest with p1's signature: the signed statement names another digest.
	bad := Pack{Digest: p2.Digest, Scope: p2.Scope, Size: p2.Size, Signature: p1.Signature}
	if _, err := f.cache.Ensure(context.Background(), manifestOf(bad), EnsureOptions{}); !errors.Is(err, ErrVerify) {
		t.Fatalf("wrong digest: %v", err)
	}
}

func TestEnsureUnpinnedKeyRefused(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.otherK, "tenant-a", map[string]string{"r.yaml": "a"})
	if _, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{}); !errors.Is(err, ErrVerify) || f.fetch.calls != 0 {
		t.Fatalf("unpinned: %v calls %d", err, f.fetch.calls)
	}
}

type slowFetcher struct{}

func (slowFetcher) Fetch(ctx context.Context, _ string) (io.ReadCloser, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestEnsureTimeoutIsUnavailable(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	f.cache.opts.Fetch = slowFetcher{}
	start := time.Now()
	_, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{PackTimeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrUnavailable) || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %v", err)
	}
}

func TestEnsureDownloadFailureIsUnavailable(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	f.fetch.blobs = map[string][]byte{}
	if _, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("download failure: %v", err)
	}
}

func TestManifestValidation(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	good := manifestOf(p)
	gb, _ := json.Marshal(good)
	if _, err := ParseManifest(gb); err != nil {
		t.Fatal(err)
	}
	// Unknown fields are tolerated (forward compatible within a version).
	withExtra := strings.Replace(string(gb), `"version":1`, `"version":1,"future":true`, 1)
	if _, err := ParseManifest([]byte(withExtra)); err != nil {
		t.Fatal(err)
	}
	mut := func(fn func(*ContentManifest)) error {
		m := manifestOf(p)
		fn(&m)
		b, _ := json.Marshal(m)
		_, err := ParseManifest(b)
		return err
	}
	for name, fn := range map[string]func(*ContentManifest){
		"newer version":  func(m *ContentManifest) { m.Version = 2 },
		"no version":     func(m *ContentManifest) { m.Version = 0 },
		"bad digest":     func(m *ContentManifest) { m.Slots[0].Sources[0].Digest = "sha256:zz" },
		"bad scope":      func(m *ContentManifest) { m.Slots[0].Sources[0].Scope = "other" },
		"no signature":   func(m *ContentManifest) { m.Slots[0].Sources[0].Signature = nil },
		"bad slug":       func(m *ContentManifest) { m.Slots[0].Sources[0].Source = "../x" },
		"repeated slot":  func(m *ContentManifest) { m.Slots = append(m.Slots, m.Slots[0]) },
		"bad revoked":    func(m *ContentManifest) { m.Revoked = []string{"nope"} },
		"empty rule id":  func(m *ContentManifest) { m.Slots[0].DisabledRules = []string{""} },
		"nonpositive sz": func(m *ContentManifest) { m.Slots[0].Sources[0].Size = 0 },
	} {
		if err := mut(fn); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseManifest([]byte("{")); !errors.Is(err, ErrManifest) {
		t.Errorf("garbage: %v", err)
	}
}

func TestManifestFetchConditional(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"r.yaml": "a"})
	body, _ := json.Marshal(manifestOf(p))
	var full, notMod atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer run-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			notMod.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	hf := &HTTPFetcher{Do: func(r *http.Request) (*http.Response, error) {
		r.Header.Set("Authorization", "Bearer run-token")
		return srv.Client().Do(r)
	}}
	u := srv.URL + "/api/v1/ci/runs/1/content?capability=sast"
	m, changed, err := hf.Manifest(context.Background(), u)
	if err != nil || !changed || len(m.Slots) != 1 {
		t.Fatalf("first: %v %v", err, changed)
	}
	m2, changed, err := hf.Manifest(context.Background(), u)
	if err != nil || changed || m2 != m || full.Load() != 1 || notMod.Load() != 1 {
		t.Fatalf("second: %v changed=%v full=%d 304=%d", err, changed, full.Load(), notMod.Load())
	}
	// A failing route is unavailable, not a manifest error.
	bad := &HTTPFetcher{Do: srv.Client().Do}
	if _, _, err := bad.Manifest(context.Background(), u); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("401: %v", err)
	}
}

// The sensor route and the CI route differ only in prefix and credentials:
// one HTTPFetcher serves both.
func TestEnsureOverHTTPFetcherPrefixes(t *testing.T) {
	f := newFixture(t)
	pl := newPlatform(t)
	p := pl.publish(t, &fixture{tenantK: f.tenantK}, map[string]string{"r.yaml": "a"})
	f.cache.opts.Fetch = pl.fetcher()
	if _, err := f.cache.Ensure(context.Background(), manifestOf(p), EnsureOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(f.cache.Held()) != 1 {
		t.Fatalf("held %v", f.cache.Held())
	}
}
