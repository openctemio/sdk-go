package sensorkit

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/localstore"
	"github.com/openctemio/sdk-go/pkg/sensorkit/contentcache"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

// contentPlatform serves the content routes of the platform for one pack and
// counts the downloads.
type contentPlatform struct {
	srv       *httptest.Server
	mu        sync.Mutex
	blobs     map[string][]byte
	desired   []contentcache.Pack
	etag      string
	downloads map[string]int
	key       ed25519.PrivateKey
}

func newContentPlatform(t *testing.T) *contentPlatform {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	p := &contentPlatform{blobs: map[string][]byte{}, downloads: map[string]int{}, key: priv, etag: `"v1"`}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, client.ContentPath)
		switch {
		case path == "/desired":
			w.Header().Set("ETag", p.etag)
			_ = json.NewEncoder(w).Encode(contentcache.DesiredState{Packs: p.desired})
		case strings.HasPrefix(path, "/packs/") && !strings.Contains(strings.TrimPrefix(path, "/packs/"), "/"):
			d := strings.TrimPrefix(path, "/packs/")
			b, ok := p.blobs[d]
			if !ok {
				http.NotFound(w, r)
				return
			}
			p.downloads[d]++
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// pack adds a platform pack signed with key (the platform's own unless
// another is given) and returns its desired-set entry.
func (p *contentPlatform) pack(t *testing.T, key ed25519.PrivateKey, files map[string]string) contentcache.Pack {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	sum := sha256.Sum256(buf.Bytes())
	digest := "sha256:" + hex.EncodeToString(sum[:])
	st := contentcache.Statement{Kind: contentcache.StatementKind, Scope: contentcache.ScopePlatform, PackID: "p", Name: "wordlists-s", Version: "1",
		Content: "wordlist", Digest: digest, Size: int64(buf.Len()), Files: len(files), Tier: "T0"}
	payload, _ := json.Marshal(st)
	pub := key.Public().(ed25519.PublicKey)
	env, _ := json.Marshal(core.SignedEnvelope{PayloadType: contentcache.StatementPayloadType, Payload: payload,
		Signatures: []core.EnvelopeSignature{{KeyID: core.TemplateKeyID(pub), Sig: ed25519.Sign(key, core.DSSEPreAuthEncoding(contentcache.StatementPayloadType, payload))}}})
	p.mu.Lock()
	p.blobs[digest] = buf.Bytes()
	p.mu.Unlock()
	return contentcache.Pack{Digest: digest, Scope: contentcache.ScopePlatform, Size: int64(buf.Len()), Signature: env}
}

func (p *contentPlatform) downloadsOf(d string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.downloads[d]
}

// contentKit is a kit paired to the fake platform with the platform's content
// key pinned in its identity, on a local store.
func contentKit(t *testing.T, p *contentPlatform, shared bool) *Kit {
	t.Helper()
	clearEnv(t)
	st, err := localstore.Open(localstore.Options{Dir: filepath.Join(t.TempDir(), "store"), CreateKey: true, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	k := &Kit{out: &syncBuffer{}, errw: &syncBuffer{}}
	k.ls = &localStore{store: st, dir: st.Dir()}
	k.client = client.New(&client.Config{BaseURL: p.srv.URL, APIKey: "key"})
	t.Cleanup(func() { _ = k.client.Close() })
	// Packs are read-only: make the tree removable for the test's cleanup.
	t.Cleanup(func() {
		_ = filepath.WalkDir(k.contentRoot(), func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	k.s.shared = shared
	k.s.identity = &identity.Identity{TenantID: "tenant-a", ContentPlatformKeys: []jobsig.PublicKey{jobsig.NewPublicKey(p.key.Public().(ed25519.PublicKey))}}
	if shared {
		k.s.identity.TenantID, k.s.identity.Scope = "", "instance"
	}
	return k
}

// holdOne installs the pack and marks it in use by a task, as a job that pins
// it does; the returned function releases it.
func holdOne(t *testing.T, c *contentcache.Cache, p contentcache.Pack) func() {
	t.Helper()
	if _, err := c.Install(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	_, rel, err := c.Acquire(p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// The cache the kit opens is the janitor's pack cache: the janitor counts its
// bytes in the one local-store quota and removes a revoked pack, but never
// one a running task holds.
func TestContentCacheIsPrunedByTheJanitor(t *testing.T) {
	p := newContentPlatform(t)
	k := contentKit(t, p, false)
	pack := p.pack(t, p.key, map[string]string{"dns/s.txt": "www\nmail\n"})
	cache := k.contentCache()
	if cache == nil {
		t.Fatal("no content cache although the identity pins a platform key")
	}
	release := holdOne(t, cache, pack)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := k.startJanitor(ctx)
	defer stop()
	j := k.janitorRef.Load()
	if j == nil {
		t.Fatal("no janitor")
	}
	if _, err := j.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := j.Status().Bytes[localstore.ClassContentPack]; got <= 0 {
		t.Fatalf("the janitor does not count the packs: %d bytes", got)
	}
	if err := cache.Revoke([]string{pack.Digest}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Path(pack.Digest); !ok {
		t.Fatal("the janitor removed a pack a running task holds")
	}
	release()
	if _, err := j.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Path(pack.Digest); ok {
		t.Fatal("the janitor kept a revoked pack nothing holds")
	}
}

// The heartbeat reports the digests held, the cache's counters and the
// desired-set version last synced; no tenant names, paths or file names.
func TestHeartbeatReportsHeldPacks(t *testing.T) {
	p := newContentPlatform(t)
	k := contentKit(t, p, false)
	pack := p.pack(t, p.key, map[string]string{"dns/s.txt": "www\n"})
	rel := holdOne(t, k.contentCache(), pack)
	defer rel()
	r := k.localStoreReport()
	if r == nil || r.Content == nil {
		t.Fatalf("no content in the heartbeat report: %+v", r)
	}
	c := r.Content
	sum := sha256.Sum256([]byte(pack.Digest))
	if c.HeldCount != 1 || len(c.Held) != 1 || c.Held[0] != pack.Digest || c.HeldSetSHA256 != hex.EncodeToString(sum[:]) ||
		c.Bytes <= 0 || c.Misses != 1 || c.BytesDownloaded != pack.Size {
		t.Fatalf("report %+v", c)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "dns/s.txt") || strings.Contains(string(raw), "tenant-a") {
		t.Fatalf("the report carries names: %s", raw)
	}
}

// A heartbeat answer with a new content version refreshes the cache at once,
// not at the next schedule; the same version does not refresh it again.
func TestHeartbeatContentVersionTriggersRefresh(t *testing.T) {
	p := newContentPlatform(t)
	k := contentKit(t, p, false)
	pack := p.pack(t, p.key, map[string]string{"dns/s.txt": "www\n"})
	p.desired = []contentcache.Pack{pack}
	cache := k.contentCache()

	ctx, cancel := context.WithCancel(context.Background())
	stop := k.startContentSync(ctx)
	defer func() { cancel(); stop() }()
	d := core.NewDoorbell(&core.DoorbellConfig{})
	d.SetContentHandler(k.wakeContent)

	waitHeld := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := cache.Path(pack.Digest); ok == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("pack held = %v after the heartbeat answer, want %v", !want, want)
	}
	if _, ok := cache.Path(pack.Digest); ok {
		t.Fatal("held before any refresh")
	}
	d.Handle(&core.HeartbeatHints{Present: true, ContentVersion: `"v1"`})
	waitHeld(true)
	if got := p.downloadsOf(pack.Digest); got != 1 {
		t.Fatalf("downloads %d", got)
	}
	if r := k.contentReport(); r == nil || r.DesiredVersion != `"v1"` {
		t.Fatalf("report %+v", r)
	}
}

// The content keys come from the pairing and nowhere else: a pack signed by a
// key the identity does not pin is never installed, even when the platform
// lists it as desired.
func TestContentPinnedKeysOnly(t *testing.T) {
	p := newContentPlatform(t)
	k := contentKit(t, p, false)
	_, rogue, _ := ed25519.GenerateKey(nil)
	bad := p.pack(t, rogue, map[string]string{"dns/s.txt": "evil\n"})
	good := p.pack(t, p.key, map[string]string{"dns/s.txt": "www\n"})
	p.desired = []contentcache.Pack{bad, good}
	cache := k.contentCache()
	d, _, err := k.client.ContentFetcher().Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rep := cache.Sync(context.Background(), d.Packs, d.Revoked)
	if _, ok := cache.Path(bad.Digest); ok || rep.Failed[bad.Digest] == "" {
		t.Fatalf("a pack signed by an unpinned key was installed: %+v", rep)
	}
	if _, ok := cache.Path(good.Digest); !ok {
		t.Fatalf("the genuine pack was not installed: %+v", rep)
	}
}

// A sensor with no content key pinned (paired before content delivery) has no
// cache: the janitor has no packs and a job that pins content is refused.
func TestNoContentKeyNoCache(t *testing.T) {
	p := newContentPlatform(t)
	k := contentKit(t, p, false)
	k.s.identity.ContentPlatformKeys = nil
	if k.contentCache() != nil || k.contentReport() != nil {
		t.Fatal("a content cache without a pinned key")
	}
}

// A shared sensor pins the platform key only: it installs platform packs once
// for every organization's jobs, and refuses an organization's pack even when
// the platform lists it.
func TestSharedSensorContentIsPlatformOnly(t *testing.T) {
	p := newContentPlatform(t)
	k := contentKit(t, p, true)
	if len(k.s.identity.ContentTenantKeys) != 0 {
		t.Fatal("setup: a shared identity with a tenant key")
	}
	pack := p.pack(t, p.key, map[string]string{"dns/s.txt": "www\n"})
	cache := k.contentCache()
	for range 2 { // two organizations' jobs
		rel := holdOne(t, cache, pack)
		defer rel()
	}
	if p.downloadsOf(pack.Digest) != 1 || len(cache.Held()) != 1 {
		t.Fatalf("downloads %d, held %v", p.downloadsOf(pack.Digest), cache.Held())
	}
	tenantPack := p.pack(t, p.key, map[string]string{"dns/t.txt": "private\n"})
	tenantPack.Scope = contentcache.ScopeTenant
	if _, err := cache.Install(context.Background(), tenantPack); err == nil {
		t.Fatal("a shared sensor installed an organization's pack")
	}
	if _, ok := cache.Path(tenantPack.Digest); ok {
		t.Fatal("tenant content reached the shared cache")
	}
}

// The local setting can only lower the pack budget the platform's policy
// sets, never raise it.
func TestPackBudgetOnlyLowered(t *testing.T) {
	clearEnv(t)
	pol := localstore.Policy{PackBudgetBytes: 1 << 30}
	if got := effectivePackPolicy(pol).PackBudgetBytes; got != 1<<30 {
		t.Fatalf("no override: %d", got)
	}
	t.Setenv(EnvContentBudgetMB, "256")
	if got := effectivePackPolicy(pol).PackBudgetBytes; got != 256<<20 {
		t.Fatalf("lowered: %d", got)
	}
	t.Setenv(EnvContentBudgetMB, "4096")
	if got := effectivePackPolicy(pol).PackBudgetBytes; got != 1<<30 {
		t.Fatalf("raised past the policy: %d", got)
	}
	t.Setenv(EnvContentBudgetMB, "lots")
	if got := effectivePackPolicy(pol).PackBudgetBytes; got != 1<<30 {
		t.Fatalf("invalid override changed the budget: %d", got)
	}
	if _, err := packBudgetOverride(); err == nil {
		t.Fatal("an invalid override was accepted")
	}
}

// The cache and the janitor share one default pack budget.
func TestOnePackBudgetDefault(t *testing.T) {
	if got := effectivePackPolicy(localstore.Policy{}).PackBudgetBytes; got != localstore.DefaultPackBudget {
		t.Fatalf("policy default %d", got)
	}
}
