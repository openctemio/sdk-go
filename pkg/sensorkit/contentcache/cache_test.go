package contentcache

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

type memFetcher struct {
	mu    sync.Mutex
	blobs map[string][]byte
	calls int
}

func (f *memFetcher) Fetch(_ context.Context, d string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	b, ok := f.blobs[d]
	if !ok {
		return nil, errors.New("404")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func tarOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for n, d := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(d))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(d))
	}
	_ = tw.Close()
	return buf.Bytes()
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// sign makes the platform's DSSE envelope of a statement.
func sign(t *testing.T, priv ed25519.PrivateKey, st Statement) json.RawMessage {
	t.Helper()
	st.Kind = StatementKind
	payload, _ := json.Marshal(st)
	pub, _ := priv.Public().(ed25519.PublicKey)
	env := core.SignedEnvelope{PayloadType: StatementPayloadType, Payload: payload,
		Signatures: []core.EnvelopeSignature{{KeyID: core.TemplateKeyID(pub), Sig: ed25519.Sign(priv, core.DSSEPreAuthEncoding(StatementPayloadType, payload))}}}
	b, _ := json.Marshal(env)
	return b
}

type fixture struct {
	cache          *Cache
	fetch          *memFetcher
	tenantK, platK ed25519.PrivateKey
	otherK         ed25519.PrivateKey
	root           string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, tk, _ := ed25519.GenerateKey(nil)
	_, pk, _ := ed25519.GenerateKey(nil)
	_, ok, _ := ed25519.GenerateKey(nil)
	f := &fixture{fetch: &memFetcher{blobs: map[string][]byte{}}, tenantK: tk, platK: pk, otherK: ok, root: filepath.Join(t.TempDir(), "content")}
	c, err := Open(f.root, Options{TenantID: "tenant-a", TenantKeys: []ed25519.PublicKey{tk.Public().(ed25519.PublicKey)},
		PlatformKeys: []ed25519.PublicKey{pk.Public().(ed25519.PublicKey)}, Fetch: f.fetch})
	if err != nil {
		t.Fatal(err)
	}
	f.cache = c
	// Packs are read-only: make them removable for the test cleanup.
	t.Cleanup(func() { _ = removeTree(f.root) })
	return f
}

// pack serves an archive and returns a desired-set entry signed by key.
func (f *fixture) pack(t *testing.T, scope string, key ed25519.PrivateKey, tenant string, files map[string]string) Pack {
	t.Helper()
	b := tarOf(t, files)
	d := digestOf(b)
	f.fetch.blobs[d] = b
	st := Statement{TenantID: tenant, PackID: "p", Name: "n", Version: "1", Content: "wordlist", Digest: d, Size: int64(len(b)), Files: len(files), Tier: "T0"}
	if scope == ScopePlatform {
		st.Scope, st.TenantID = ScopePlatform, ""
	}
	return Pack{Digest: d, Scope: scope, Size: int64(len(b)), Signature: sign(t, key, st)}
}

func TestInstallVerifiesAndStoresReadOnly(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"dirs/common.txt": "admin\n", "a.txt": "x\n"})
	dir, err := f.cache.Install(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "dirs", "common.txt")); err != nil || string(b) != "admin\n" {
		t.Fatalf("content %q %v", b, err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "a.txt")); st.Mode().Perm() != 0o400 {
		t.Fatalf("file mode %v", st.Mode())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o500 {
		t.Fatalf("dir mode %v", st.Mode())
	}
	if st, _ := os.Stat(f.root); st.Mode().Perm() != 0o700 {
		t.Fatalf("root mode %v", st.Mode())
	}
	// Installed once: a second install does not fetch again.
	if _, err := f.cache.Install(context.Background(), p); err != nil || f.fetch.calls != 1 {
		t.Fatalf("reinstall: %v calls %d", err, f.fetch.calls)
	}
	if held := f.cache.Held(); len(held) != 1 || held[0] != p.Digest {
		t.Fatalf("held %v", held)
	}
	pp := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"t.yaml": "id: x"})
	if _, err := f.cache.Install(context.Background(), pp); err != nil {
		t.Fatalf("platform pack: %v", err)
	}
}

// SECURITY: nothing is stored unless the bytes, the signature, the key's
// scope and the organization all check out.
func TestInstallRefusals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	files := map[string]string{"w.txt": "a\n"}
	cases := map[string]Pack{
		"another organization": f.pack(t, ScopeTenant, f.tenantK, "tenant-b", files),
		"unpinned key":         f.pack(t, ScopeTenant, f.otherK, "tenant-a", map[string]string{"x.txt": "1"}),
		"tenant key as platform": func() Pack {
			p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"y.txt": "1"})
			p.Scope = ScopePlatform
			return p
		}(),
		"platform key as tenant": func() Pack {
			p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"z.txt": "1"})
			p.Scope = ScopeTenant
			return p
		}(),
		"unknown scope": func() Pack {
			p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"s.txt": "1"})
			p.Scope = "global"
			return p
		}(),
	}
	// Bytes that do not match the digest.
	tampered := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"t.txt": "1"})
	b := bytes.Clone(f.fetch.blobs[tampered.Digest])
	b[len(b)-1100] ^= 1
	f.fetch.blobs[tampered.Digest] = b
	cases["tampered bytes"] = tampered
	// A statement for another digest.
	other := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"o.txt": "1"})
	swapped := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"q.txt": "1"})
	swapped.Signature = other.Signature
	cases["statement of another digest"] = swapped
	// An archive with a symbolic link, correctly hashed and signed.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	_ = tw.Close()
	link := buf.Bytes()
	ld := digestOf(link)
	f.fetch.blobs[ld] = link
	cases["symlink archive"] = Pack{Digest: ld, Scope: ScopeTenant, Size: int64(len(link)),
		Signature: sign(t, f.tenantK, Statement{TenantID: "tenant-a", PackID: "p", Digest: ld, Size: int64(len(link))})}

	for name, p := range cases {
		if _, err := f.cache.Install(ctx, p); !errors.Is(err, ErrVerify) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if held := f.cache.Held(); len(held) != 0 {
		t.Fatalf("refused packs were stored: %v", held)
	}
}

func TestSyncRevokeAndBudget(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"a.txt": strings.Repeat("a", 1000)})
	b := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"b.txt": strings.Repeat("b", 1000)})
	rep := f.cache.Sync(ctx, []Pack{a, b}, nil)
	if len(rep.Installed) != 2 || len(rep.Failed) != 0 {
		t.Fatalf("sync %+v", rep)
	}
	// A pack in use survives revocation until released, and is refused from
	// then on; revoked packs are never installed again.
	_, release, err := f.cache.Acquire(a.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.cache.Sync(ctx, []Pack{b}, []string{a.Digest})
	if _, ok := f.cache.Path(a.Digest); !ok {
		t.Fatal("a pack in use was removed")
	}
	if _, _, err := f.cache.Acquire(a.Digest); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked acquire: %v", err)
	}
	release()
	f.cache.Sync(ctx, []Pack{b}, []string{a.Digest})
	if _, ok := f.cache.Path(a.Digest); ok {
		t.Fatal("a revoked pack was kept")
	}
	if _, err := f.cache.Install(ctx, a); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked install: %v", err)
	}

	// Over budget: packs outside the desired set go, least recently used
	// first; the desired set stays.
	f.cache.opts.Budget = 1500
	c := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"c.txt": strings.Repeat("c", 1000)})
	f.cache.Sync(ctx, []Pack{b, c}, nil)
	rep = f.cache.Sync(ctx, []Pack{c}, nil)
	if _, ok := f.cache.Path(b.Digest); ok || len(rep.Removed) != 1 {
		t.Fatalf("budget: %+v", rep)
	}
	if _, ok := f.cache.Path(c.Digest); !ok {
		t.Fatal("a desired pack was removed")
	}
	// A failed fetch leaves the rest and reports it.
	gone := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"g.txt": "g"})
	delete(f.fetch.blobs, gone.Digest)
	if rep := f.cache.Sync(ctx, []Pack{c, gone}, nil); rep.Failed[gone.Digest] == "" {
		t.Fatalf("failure not reported: %+v", rep)
	}
}

func TestOpenRemovesStaging(t *testing.T) {
	f := newFixture(t)
	st := filepath.Join(f.root, "packs", ".staging-x")
	_ = os.MkdirAll(filepath.Join(st, "d"), 0o500)
	if _, err := Open(f.root, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st); !os.IsNotExist(err) {
		t.Fatal("staging left behind")
	}
}

// A task gets the cached paths of its packs, whatever path a job sent, and
// holds them until released; a pack not held fails the task.
func TestResolveTask(t *testing.T) {
	f := newFixture(t)
	p := f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{"w.txt": "a\n"})
	if _, err := f.cache.Install(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	task := tool.Task{Content: []tool.TaskContent{{Slot: "words", Packs: []tool.ContentPack{{Digest: p.Digest, Path: "/etc"}}}}}
	release, err := f.cache.Resolve(&task)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := f.cache.Path(p.Digest)
	if got := task.Content[0].Packs[0].Path; got != want {
		t.Fatalf("path %q, want %q", got, want)
	}
	m := tool.Manifest{Content: []tool.ContentSlot{{Slot: "words", Kind: "wordlist"}}}
	if _, err := tool.CheckTaskContent(m, task, f.cache.Root()); err != nil {
		t.Fatalf("the tool host would refuse the resolved path: %v", err)
	}
	f.cache.Sync(context.Background(), nil, []string{p.Digest})
	if _, ok := f.cache.Path(p.Digest); !ok {
		t.Fatal("a pack in use by a task was removed")
	}
	release()
	missing := tool.Task{Content: []tool.TaskContent{{Slot: "words", Packs: []tool.ContentPack{{Digest: "sha256:" + strings.Repeat("0", 64)}}}}}
	if _, err := f.cache.Resolve(&missing); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("missing pack: %v", err)
	}
}

// TestPlatformVector: a pack the platform built and signed (openctem
// api pkg/domain/contentpack: Canonicalize, Signer.Sign and SignPlatform,
// master 0x01*32) installs here with the keys the platform publishes. It
// pins both sides to the same statement, envelope and archive format.
func TestPlatformVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/platform-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Digest      string          `json:"digest"`
		Tar         string          `json:"tar"`
		Size        int64           `json:"size"`
		TenantEnv   json.RawMessage `json:"tenant_env"`
		PlatformEnv json.RawMessage `json:"platform_env"`
		TenantPub   string          `json:"tenant_pub"`
		PlatformPub string          `json:"platform_pub"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tarBytes, _ := base64.StdEncoding.DecodeString(v.Tar)
	tpub, _ := base64.StdEncoding.DecodeString(v.TenantPub)
	ppub, _ := base64.StdEncoding.DecodeString(v.PlatformPub)
	fetch := &memFetcher{blobs: map[string][]byte{v.Digest: tarBytes}}
	for _, tc := range []struct {
		scope string
		env   json.RawMessage
	}{{ScopeTenant, v.TenantEnv}, {ScopePlatform, v.PlatformEnv}} {
		root := filepath.Join(t.TempDir(), "c")
		c, err := Open(root, Options{TenantID: "tenant-a", TenantKeys: []ed25519.PublicKey{tpub}, PlatformKeys: []ed25519.PublicKey{ppub}, Fetch: fetch})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = removeTree(root) })
		dir, err := c.Install(context.Background(), Pack{Digest: v.Digest, Scope: tc.scope, Size: v.Size, Signature: tc.env})
		if err != nil {
			t.Fatalf("%s: %v", tc.scope, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "dirs", "common.txt")); string(b) != "admin\n" {
			t.Fatalf("%s: content %q", tc.scope, b)
		}
	}
}
