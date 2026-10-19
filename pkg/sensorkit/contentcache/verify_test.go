package contentcache

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

// writable makes a stored pack writable again, as an attacker with the
// sensor's user (or root, or an offline editor) can.
func writable(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			mode := os.FileMode(0o600)
			if d.IsDir() {
				mode = 0o700
			}
			_ = os.Chmod(p, mode)
		}
		return nil
	})
}

func installT(t *testing.T, f *fixture, files map[string]string) (Pack, string) {
	t.Helper()
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", files)
	dir, err := f.cache.Install(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return p, dir
}

func TestAcquireDetectsTampering(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"content changed, same size": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: evil"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"content changed, modification time put back": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "a.yaml")
			fi, _ := os.Stat(p)
			if err := os.WriteFile(p, []byte("id: evil"), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(p, fi.ModTime(), fi.ModTime())
		},
		"file added": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "extra.yaml"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"file removed": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "b.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"file replaced by a symbolic link": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "a.yaml")
			_ = os.Remove(p)
			if err := os.Symlink("/etc/hostname", p); err != nil {
				t.Fatal(err)
			}
		},
		"statement removed": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, statementFile)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p, dir := installT(t, f, map[string]string{"a.yaml": "id: good", "b.yaml": "id: two"})
			// A first load verifies and caches the verdict.
			_, rel, err := f.cache.Acquire(p.Digest)
			if err != nil {
				t.Fatal(err)
			}
			rel()
			writable(t, dir)
			time.Sleep(10 * time.Millisecond) // a distinct change time
			tamper(t, dir)
			if _, _, err := f.cache.Acquire(p.Digest); !errors.Is(err, ErrVerify) {
				t.Fatalf("Acquire after tampering: %v, want ErrVerify", err)
			}
			if _, ok := f.cache.Path(p.Digest); ok {
				t.Fatal("tampered pack kept")
			}
			if s := f.cache.Stats(); s.VerifyFailures != 1 {
				t.Fatalf("stats %+v", s)
			}
		})
	}
}

func TestAcquireRefusesKeyNoLongerPinned(t *testing.T) {
	f := newFixture(t)
	p, _ := installT(t, f, map[string]string{"a.yaml": "id: good"})
	// The operator rotates the pinned tenant key: packs signed only by the
	// old key no longer load, even though they were verified at install.
	_, newK, _ := ed25519.GenerateKey(nil)
	c2, err := Open(f.root, Options{TenantID: "tenant-a", TenantKeys: []ed25519.PublicKey{newK.Public().(ed25519.PublicKey)}, Fetch: f.fetch})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c2.Acquire(p.Digest); !errors.Is(err, ErrVerify) {
		t.Fatalf("Acquire under an unpinned key: %v", err)
	}
	// And a pack for another organization does not load on this one.
	c3, err := Open(f.root, Options{TenantID: "tenant-b", TenantKeys: []ed25519.PublicKey{f.tenantK.Public().(ed25519.PublicKey)}, Fetch: f.fetch})
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := installT(t, f, map[string]string{"z.yaml": "id: z"})
	if _, _, err := c3.Acquire(p2.Digest); !errors.Is(err, ErrVerify) {
		t.Fatalf("Acquire of another organization's pack: %v", err)
	}
}

func TestStatementSwappedBetweenPacks(t *testing.T) {
	f := newFixture(t)
	p1, d1 := installT(t, f, map[string]string{"a.yaml": "id: one"})
	_, d2 := installT(t, f, map[string]string{"a.yaml": "id: two"})
	writable(t, d1)
	st2, _ := os.ReadFile(filepath.Join(d2, statementFile))
	if err := os.WriteFile(filepath.Join(d1, statementFile), st2, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.cache.Acquire(p1.Digest); !errors.Is(err, ErrVerify) {
		t.Fatalf("Acquire with another pack's statement: %v", err)
	}
}

func TestReverifyInterval(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.cache.now = func() time.Time { return now }
	p, _ := installT(t, f, map[string]string{"a.yaml": "id: good"})
	for range 3 {
		_, rel, err := f.cache.Acquire(p.Digest)
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	if n := f.cache.Stats().FullVerifications; n != 1 {
		t.Fatalf("full verifications = %d, want 1 (unchanged pack within the interval)", n)
	}
	now = now.Add(DefaultReverifyEvery)
	if _, rel, err := f.cache.Acquire(p.Digest); err != nil {
		t.Fatal(err)
	} else {
		rel()
	}
	if n := f.cache.Stats().FullVerifications; n != 2 {
		t.Fatalf("full verifications = %d, want 2 after the interval", n)
	}
}

// storeFixture opens a cache with a localstore for the index and the
// revocation set.
func storeFixture(t *testing.T, f *fixture, st *localstore.Store) *Cache {
	t.Helper()
	z, err := st.Sealer("tenant-a", "content-index")
	if err != nil {
		t.Fatal(err)
	}
	kv, err := st.KV("tenant-a", "content")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(f.root, Options{TenantID: "tenant-a", TenantKeys: []ed25519.PublicKey{f.tenantK.Public().(ed25519.PublicKey)},
		PlatformKeys: []ed25519.PublicKey{f.platK.Public().(ed25519.PublicKey)}, Fetch: f.fetch, Index: z, State: kv})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func openStore(t *testing.T, dir string) *localstore.Store {
	t.Helper()
	st, err := localstore.Open(localstore.Options{Dir: dir, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// nonCanonicalPack serves an archive that is not in canonical form (a
// directory entry, files out of order): only the sealed index can verify
// it on load.
func nonCanonicalPack(t *testing.T, f *fixture) Pack {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, e := range []struct{ n, d string }{{"dir/z.yaml", "id: z"}, {"a.yaml", "id: a"}} {
		_ = tw.WriteHeader(&tar.Header{Name: e.n, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(e.d))})
		_, _ = tw.Write([]byte(e.d))
	}
	_ = tw.Close()
	b := buf.Bytes()
	d := digestOf(b)
	f.fetch.blobs[d] = b
	st := Statement{TenantID: "tenant-a", PackID: "p", Name: "n", Version: "1", Content: "nuclei", Digest: d, Size: int64(len(b)), Files: 2, Tier: "T0"}
	return Pack{Digest: d, Scope: ScopeTenant, Size: int64(len(b)), Signature: sign(t, f.tenantK, st)}
}

func TestSealedIndexVerifiesNonCanonicalPacks(t *testing.T) {
	f := newFixture(t)
	st := openStore(t, t.TempDir())
	c := storeFixture(t, f, st)
	p := nonCanonicalPack(t, f)
	if _, err := c.Install(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, rel, err := c.Acquire(p.Digest); err != nil {
		t.Fatalf("Acquire with the sealed index: %v", err)
	} else {
		rel()
	}
	// Without the sealed index the same pack cannot be checked on load
	// (it is not canonical): refused, never trusted.
	c2, _ := Open(f.root, Options{TenantID: "tenant-a", TenantKeys: []ed25519.PublicKey{f.tenantK.Public().(ed25519.PublicKey)}, Fetch: f.fetch})
	if _, _, err := c2.Acquire(p.Digest); !errors.Is(err, ErrVerify) {
		t.Fatalf("non-canonical pack without an index: %v", err)
	}
	// Reinstall and tamper: the sealed index catches it.
	dir, err := c.Install(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	writable(t, dir)
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: X"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Acquire(p.Digest); !errors.Is(err, ErrVerify) {
		t.Fatalf("tampered pack with the sealed index: %v", err)
	}
}

func TestSealedIndexBoundToItsPack(t *testing.T) {
	f := newFixture(t)
	st := openStore(t, t.TempDir())
	c := storeFixture(t, f, st)
	p1 := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.yaml": "id: one"})
	p2 := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.yaml": "id: two"})
	d1, err := c.Install(context.Background(), p1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := c.Install(context.Background(), p2)
	if err != nil {
		t.Fatal(err)
	}
	// Copy pack 2's files and sealed index over pack 1, keeping pack 1's
	// statement: the index is sealed for pack 2's digest and does not open.
	writable(t, d1)
	for _, n := range []string{"a.yaml", sealedIndexFile} {
		b, _ := os.ReadFile(filepath.Join(d2, n))
		if err := os.WriteFile(filepath.Join(d1, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := c.Acquire(p1.Digest); !errors.Is(err, ErrVerify) {
		t.Fatalf("Acquire with another pack's index: %v", err)
	}
	if st.Stats().Tampered == 0 {
		t.Fatal("the store did not report the foreign index")
	}
}

func TestRevocationsPersistAndOnlyGrow(t *testing.T) {
	f := newFixture(t)
	storeDir := t.TempDir()
	st := openStore(t, storeDir)
	c := storeFixture(t, f, st)
	ctx := context.Background()
	a := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.yaml": "id: a"})
	b := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"b.yaml": "id: b"})
	if rep := c.Sync(ctx, []Pack{a, b}, nil); len(rep.Installed) != 2 {
		t.Fatalf("sync %+v", rep)
	}
	_, rel, err := c.Acquire(a.Digest) // in use: survives the revocation on disk
	if err != nil {
		t.Fatal(err)
	}
	if rep := c.Sync(ctx, []Pack{b}, []string{a.Digest}); rep.RevocationsError != "" {
		t.Fatalf("sync %+v", rep)
	}
	rel()
	// A restart while the platform is unreachable: a new cache on the same
	// directories still refuses a, and removes it since nothing holds it.
	c2 := storeFixture(t, f, st)
	if _, _, err := c2.Acquire(a.Digest); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked pack after restart: %v", err)
	}
	if _, ok := c2.Path(a.Digest); ok {
		t.Fatal("revoked pack kept after restart")
	}
	// A later list that no longer names a does not un-revoke it.
	c2.Sync(ctx, []Pack{a, b}, nil)
	if _, err := c2.Install(ctx, a); !errors.Is(err, ErrRevoked) {
		t.Fatalf("install after a list without the revocation: %v", err)
	}
	c3 := storeFixture(t, f, st)
	if _, err := c3.Install(ctx, a); !errors.Is(err, ErrRevoked) {
		t.Fatalf("install after restart: %v", err)
	}
}

func TestTamperedRevocationsFailClosed(t *testing.T) {
	f := newFixture(t)
	storeDir := t.TempDir()
	st := openStore(t, storeDir)
	c := storeFixture(t, f, st)
	ctx := context.Background()
	a := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.yaml": "id: a"})
	b := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"b.yaml": "id: b"})
	c.Sync(ctx, []Pack{a, b}, []string{a.Digest})
	// Someone edits the revocation record to resurrect a.
	rec := filepath.Join(storeDir, "kv", "tenant-a", "content", "revoked.rec")
	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(rec, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c2 := storeFixture(t, f, st)
	if _, _, err := c2.Acquire(b.Digest); !errors.Is(err, ErrRevocationsUnknown) {
		t.Fatalf("Acquire with unknown revocations: %v", err)
	}
	// The platform's next sync restores a known state.
	c2.Sync(ctx, []Pack{b}, []string{a.Digest})
	if _, rel, err := c2.Acquire(b.Digest); err != nil {
		t.Fatalf("Acquire after sync: %v", err)
	} else {
		rel()
	}
	if _, _, err := c2.Acquire(a.Digest); !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrNotHeld) {
		t.Fatalf("a after sync: %v", err)
	}
}

// TestRemovedRevocationsFailClosed: deleting the revocation record (to
// resurrect a revoked pack restored from a snapshot) does not make the
// cache forget: with packs held and no record, nothing loads until the
// next Sync. A cache that synced without revocations keeps working
// offline after a restart.
func TestRemovedRevocationsFailClosed(t *testing.T) {
	f := newFixture(t)
	storeDir := t.TempDir()
	st := openStore(t, storeDir)
	c := storeFixture(t, f, st)
	ctx := context.Background()
	a := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.yaml": "id: a"})
	if rep := c.Sync(ctx, []Pack{a}, nil); len(rep.Installed) != 1 || rep.RevocationsError != "" {
		t.Fatalf("sync %+v", rep)
	}
	c2 := storeFixture(t, f, st)
	if _, rel, err := c2.Acquire(a.Digest); err != nil {
		t.Fatalf("restart after a sync without revocations: %v", err)
	} else {
		rel()
	}
	if err := os.Remove(filepath.Join(storeDir, "kv", "tenant-a", "content", "revoked.rec")); err != nil {
		t.Fatal(err)
	}
	c3 := storeFixture(t, f, st)
	if _, _, err := c3.Acquire(a.Digest); !errors.Is(err, ErrRevocationsUnknown) {
		t.Fatalf("Acquire with the revocation record removed: %v", err)
	}
}
