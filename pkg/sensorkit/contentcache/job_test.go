package contentcache

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/localstore"
)

func item(slot string, p Pack, files ...string) core.JobContent {
	return core.JobContent{Slot: slot, Kind: "wordlist", Scope: p.Scope, Pack: "wordlists-s", Digest: p.Digest, Size: p.Size, Files: files, Signature: p.Signature}
}

func resolve(f *fixture, shared bool, items ...core.JobContent) (*core.ResolvedContent, func(), error) {
	return f.cache.ResolveContent(context.Background(), core.ContentRequest{Shared: shared, Tenant: "tenant-b", Items: items})
}

// A pack the job pins is fetched when missing, checked and held; it is in
// use (never evicted) until the job releases it.
func TestResolveContentHoldsPackForTheTask(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"dns/s.txt": "www\nmail\n"})
	rc, release, err := resolve(f, false, item("labels", p, "dns/s.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Slots) != 1 || rc.Slots[0].Slot != "labels" || len(rc.Slots[0].Packs) != 1 {
		t.Fatalf("resolved %+v", rc)
	}
	pk := rc.Slots[0].Packs[0]
	if b, err := os.ReadFile(filepath.Join(pk.Path, "dns", "s.txt")); err != nil || string(b) != "www\nmail\n" || pk.Digest != p.Digest || len(pk.Files) != 1 {
		t.Fatalf("pack %+v: %q %v", pk, b, err)
	}

	// Eviction keeps a pack a running task holds, however small the budget.
	f.cache.Sync(context.Background(), nil, nil)
	pol := localstore.PackPolicy{Budget: 1, MaxUnused: time.Nanosecond, EvictCold: true}
	time.Sleep(2 * time.Millisecond)
	if r := f.cache.Prune(context.Background(), pol); r.Removed != 0 {
		t.Fatalf("a pack pinned by a running task was evicted: %+v", r)
	}
	if _, ok := f.cache.Path(p.Digest); !ok {
		t.Fatal("pack gone while in use")
	}
	release()
	if r := f.cache.Prune(context.Background(), pol); r.Removed != 1 {
		t.Fatalf("released pack not evicted: %+v", r)
	}
	// A second job fetches it again; a third, while it is held, does not.
	calls := f.fetch.calls
	for range 2 {
		_, rel, err := resolve(f, false, item("labels", p, "dns/s.txt"))
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	if f.fetch.calls != calls+1 {
		t.Fatalf("downloads %d, want %d", f.fetch.calls-calls, 1)
	}
}

// Verify-on-load: a pack whose bytes do not hash to the digest, whose
// signature is not a pinned key's, or whose scope claims the wrong key is
// refused (a refusal, not "unavailable") and nothing is stored.
func TestResolveContentRefusesWhatDoesNotVerify(t *testing.T) {
	f := newFixture(t)
	files := map[string]string{"a.txt": "www\n"}

	// Bad digest: the platform serves other bytes under the digest.
	good := f.pack(t, ScopePlatform, f.platK, "", files)
	f.fetch.blobs[good.Digest] = tarOf(t, map[string]string{"a.txt": "evil\n"})
	// Bad signature: signed by a key the sensor never pinned.
	badSig := f.pack(t, ScopePlatform, f.otherK, "", map[string]string{"b.txt": "x\n"})
	// Wrong key: signed by the organization's key but claimed as a platform pack.
	wrongKey := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"c.txt": "x\n"})
	wrongKey.Scope = ScopePlatform
	// Statement for another digest swapped in.
	other := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"d.txt": "x\n"})
	swapped := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"e.txt": "x\n"})
	swapped.Signature = other.Signature

	for name, p := range map[string]Pack{"digest": good, "signature": badSig, "wrong key": wrongKey, "swapped statement": swapped} {
		t.Run(name, func(t *testing.T) {
			_, _, err := resolve(f, false, item("labels", p, "a.txt"))
			var pe *core.LocalPolicyError
			if !errors.As(err, &pe) || pe.Rule != core.RefusalRuleJobContent || errors.Is(err, core.ErrContentUnavailable) {
				t.Fatalf("err = %v, want a content refusal", err)
			}
			if _, ok := f.cache.Path(p.Digest); ok {
				t.Fatal("an unverified pack was stored")
			}
		})
	}
}

// A pack already held is still checked against the signature the job names:
// a job cannot mount a held pack with a statement the sensor does not trust.
func TestResolveContentChecksSignatureOfHeldPack(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"a.txt": "www\n"})
	_, rel, err := resolve(f, false, item("labels", p, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	rel()
	forged := p
	forged.Signature = f.pack(t, ScopePlatform, f.otherK, "", map[string]string{"zz.txt": "q\n"}).Signature
	if _, _, err := resolve(f, false, item("labels", forged, "a.txt")); err == nil {
		t.Fatal("a held pack was mounted with a signature the sensor does not trust")
	}
	if _, _, err := resolve(f, false, item("labels", p, "a.txt")); err != nil {
		t.Fatalf("the genuine job: %v", err)
	}
}

func TestResolveContentUnavailableIsDistinct(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"a.txt": "www\n"})
	delete(f.fetch.blobs, p.Digest) // the platform cannot deliver it
	_, _, err := resolve(f, false, item("labels", p, "a.txt"))
	if !errors.Is(err, core.ErrContentUnavailable) {
		t.Fatalf("err = %v, want content_unavailable", err)
	}
}

// Cross-tenant: a shared sensor holds platform packs only. An organization's
// pack is refused on it before anything is fetched, and even a validly signed
// one cannot be installed there (no organization on the cache).
func TestSharedSensorMountsPlatformPacksOnly(t *testing.T) {
	f := newFixture(t)
	tenantPack := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.txt": "private\n"})
	calls := f.fetch.calls
	if _, _, err := resolve(f, true, item("labels", tenantPack, "a.txt")); err == nil {
		t.Fatal("a shared sensor mounted an organization's pack")
	}
	if f.fetch.calls != calls {
		t.Fatal("the organization's pack was fetched for a shared job")
	}
	// The cache of a shared sensor has no organization: the tenant statement
	// fails there even if the request were not marked shared.
	shared, err := Open(filepath.Join(t.TempDir(), "content"), Options{PlatformKeys: []ed25519.PublicKey{f.platK.Public().(ed25519.PublicKey)}, Fetch: f.fetch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeTree(shared.Root()) })
	if _, _, err := shared.ResolveContent(context.Background(), core.ContentRequest{Tenant: "tenant-a", Items: []core.JobContent{item("labels", tenantPack, "a.txt")}}); err == nil {
		t.Fatal("a cache without an organization installed an organization's pack")
	}
	if len(shared.Held()) != 0 {
		t.Fatal("tenant content reached the shared cache")
	}
	// Two organizations' jobs on the shared sensor share one copy of a
	// platform pack: one download.
	pp := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"dns/s.txt": "www\n"})
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		_, rel, err := shared.ResolveContent(context.Background(), core.ContentRequest{Shared: true, Tenant: tenant, Items: []core.JobContent{item("labels", pp, "dns/s.txt")}})
		if err != nil {
			t.Fatal(err)
		}
		defer rel()
	}
	if f.fetch.calls != calls+1 || len(shared.Held()) != 1 {
		t.Fatalf("downloads %d held %v", f.fetch.calls-calls, shared.Held())
	}
}

// Concurrent jobs claiming the same missing digest share one download and
// one stored copy, and every one of them gets the pack.
func TestConcurrentClaimsOfOneDigestDownloadOnce(t *testing.T) {
	f := newFixture(t)
	slow := &delayFetcher{inner: f.fetch, delay: 80 * time.Millisecond}
	f.cache.opts.Fetch = slow
	p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"dns/s.txt": "www\nmail\n"})
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	paths := make(chan string, n)
	releases := make(chan func(), n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, rel, err := resolve(f, false, item("labels", p, "dns/s.txt"))
			if err != nil {
				errs <- err
				return
			}
			paths <- rc.Slots[0].Packs[0].Path
			releases <- rel
		}()
	}
	wg.Wait()
	close(errs)
	close(paths)
	close(releases)
	for err := range errs {
		t.Fatal(err)
	}
	for rel := range releases {
		t.Cleanup(rel)
	}
	if got := slow.n.Load(); got != 1 {
		t.Fatalf("%d downloads for one digest, want 1", got)
	}
	seen := map[string]bool{}
	for p := range paths {
		seen[p] = true
	}
	if len(seen) != 1 || len(f.cache.Held()) != 1 {
		t.Fatalf("copies: paths %v held %v", seen, f.cache.Held())
	}
	entries, _ := os.ReadDir(filepath.Join(f.root, "packs"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") {
			t.Fatalf("staging left behind: %s", e.Name())
		}
	}
}
