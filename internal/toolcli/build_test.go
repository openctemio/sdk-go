package toolcli

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/openctemio/sdk-go/pkg/tool/pack"
)

// testRegistry serves an in-memory registry holding a two-platform base
// image; it returns the base reference pinned by digest.
func testRegistry(t *testing.T) (host, base string) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		cf, _ := img.ConfigFile()
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture = "linux", arch
		cf.Config.Entrypoint = []string{"/bin/base-default"}
		img, err = mutate.ConfigFile(img, cf)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	idx := mutate.AppendManifests(empty.Index, adds...)
	ref, _ := name.ParseReference(u.Host + "/base:1")
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	d, _ := idx.Digest()
	return u.Host, u.Host + "/base@" + d.String()
}

// copyPack copies the example pack to a fresh directory.
func copyPack(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "examples", "packs", "http-title")
	dst := filepath.Join(t.TempDir(), "http-title")
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			if info.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// packLayer returns the files of the last layer of one platform's image in
// an OCI layout: name to (mode, content).
func packLayer(t *testing.T, idx v1.ImageIndex, platform string) (v1.Image, map[string]tar.Header, map[string][]byte) {
	t.Helper()
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range im.Manifests {
		if m.Platform.OS+"/"+m.Platform.Architecture != platform {
			continue
		}
		img, err := idx.Image(m.Digest)
		if err != nil {
			t.Fatal(err)
		}
		layers, _ := img.Layers()
		rc, err := layers[len(layers)-1].Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		heads, bodies := map[string]tar.Header{}, map[string][]byte{}
		tr := tar.NewReader(rc)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			heads[h.Name] = *h
			b, _ := io.ReadAll(tr)
			bodies[h.Name] = b
		}
		return img, heads, bodies
	}
	t.Fatalf("no %s manifest", platform)
	return nil, nil, nil
}

func TestBuildPackImage(t *testing.T) {
	host, base := testRegistry(t)
	dir := copyPack(t)
	// A compiled program per architecture comes from .build/<os>-<arch>/.
	for _, arch := range []string{"amd64", "arm64"} {
		p := filepath.Join(dir, pack.BuildDir, "linux-"+arch, "bin", "probe")
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte("binary for "+arch), 0o700)
	}
	_ = os.MkdirAll(filepath.Join(dir, "__pycache__"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "__pycache__", "x.pyc"), []byte("cache"), 0o644)
	out := filepath.Join(t.TempDir(), "oci")
	code, log := run(t, "build", dir, "--base", base, "--output", out)
	if code != ExitOK || !strings.Contains(log, "built "+out+"@sha256:") {
		t.Fatalf("build: %d %s", code, log)
	}
	lp, err := layout.FromPath(out)
	if err != nil {
		t.Fatal(err)
	}
	top, _ := lp.ImageIndex()
	tm, _ := top.IndexManifest()
	idx, err := top.ImageIndex(tm.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	im, _ := idx.IndexManifest()
	if len(im.Manifests) != 2 || im.Annotations[pack.LabelTier] != "T1" || im.Annotations[pack.LabelName] != "http-title" {
		t.Fatalf("index %+v", im)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		img, heads, bodies := packLayer(t, idx, "linux/"+arch)
		root := strings.TrimPrefix(pack.ImageRoot, "/") + "/"
		if h, ok := heads[root+"http-title.py"]; !ok || h.Mode != 0o755 || h.Uid != 0 || !h.ModTime.Equal(heads[root+"pack.yaml"].ModTime) {
			t.Fatalf("%s: http-title.py %+v", arch, h)
		}
		if h := heads[root+"pack.yaml"]; h.Mode != 0o644 || h.ModTime.Unix() != 0 {
			t.Fatalf("%s: pack.yaml %+v", arch, h)
		}
		if got := string(bodies[root+"bin/probe"]); got != "binary for "+arch {
			t.Fatalf("%s: overlay %q", arch, got)
		}
		for n := range heads {
			if strings.Contains(n, ".build") || strings.Contains(n, "__pycache__") {
				t.Fatalf("%s: %s in the image", arch, n)
			}
		}
		cf, _ := img.ConfigFile()
		if cf.Config.Labels[pack.LabelDigest] == "" || cf.Config.User != "65532:65532" || len(cf.Config.Entrypoint) != 0 ||
			cf.Config.WorkingDir != pack.ImageRoot || !cf.Created.IsZero() {
			t.Fatalf("%s: config %+v", arch, cf.Config)
		}
	}
	// Reproducible: a second build gives the same digest; a push sends it.
	d1, _ := idx.Digest()
	code, log = run(t, "build", dir, "--base", base, "--push", host+"/packs/http-title:0.1.0")
	if code != ExitOK || !strings.Contains(log, "@"+d1.String()) {
		t.Fatalf("second build: %d %s (want %s)", code, log, d1)
	}
	ref, _ := name.ParseReference(host + "/packs/http-title@" + d1.String())
	if _, err := remote.Index(ref); err != nil {
		t.Fatalf("pushed index: %v", err)
	}
}

// What the image holds is the pack: extracted, it validates and passes the
// kit as the source directory does.
func TestBuiltImageIsThePack(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	_, base := testRegistry(t)
	out := filepath.Join(t.TempDir(), "oci")
	if code, log := run(t, "build", copyPack(t), "--base", base, "--output", out, "--platform", "linux/amd64"); code != ExitOK {
		t.Fatalf("build: %s", log)
	}
	lp, _ := layout.FromPath(out)
	top, _ := lp.ImageIndex()
	tm, _ := top.IndexManifest()
	idx, _ := top.ImageIndex(tm.Manifests[0].Digest)
	_, heads, bodies := packLayer(t, idx, "linux/amd64")
	ext := t.TempDir()
	for n, h := range heads {
		p := filepath.Join(ext, filepath.FromSlash(n))
		if h.Typeflag == tar.TypeDir {
			_ = os.MkdirAll(p, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, bodies[n], os.FileMode(h.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(ext, filepath.FromSlash(strings.TrimPrefix(pack.ImageRoot, "/")))
	if code, log := run(t, "test", "--capability", dir); code != ExitOK || !strings.Contains(log, "PASS") {
		t.Fatalf("test extracted pack: %s", log)
	}
}

func TestBuildRefuses(t *testing.T) {
	_, base := testRegistry(t)
	dir := copyPack(t)
	out := filepath.Join(t.TempDir(), "oci")
	// SECURITY: a symbolic link (here to a file outside the pack) is never
	// packed.
	_ = os.Symlink("/etc/hostname", filepath.Join(dir, "leak"))
	if code, log := run(t, "build", dir, "--base", base, "--output", out); code != ExitFail || !strings.Contains(log, "leak is a symbolic link") {
		t.Fatalf("symlink: %d %s", code, log)
	}
	_ = os.Remove(filepath.Join(dir, "leak"))
	// A base by tag can move under a signed pack.
	if code, log := run(t, "build", dir, "--base", "example.com/base:latest", "--output", out); code != ExitFail || !strings.Contains(log, "pinned by digest") {
		t.Fatalf("tag base: %d %s", code, log)
	}
	if code, log := run(t, "build", dir, "--base", base, "--output", out, "--platform", "linux/s390x"); code != ExitFail || !strings.Contains(log, "not one of the pack's") {
		t.Fatalf("platform: %d %s", code, log)
	}
	// A pack that does not validate is not built.
	b, _ := os.ReadFile(filepath.Join(dir, "pack.yaml"))
	_ = os.WriteFile(filepath.Join(dir, "pack.yaml"), bytes.Replace(b, []byte("tier: T1"), []byte("tier: T0"), 1), 0o644)
	if code, log := run(t, "build", dir, "--base", base, "--output", out); code != ExitFail || !strings.Contains(log, "/tier") {
		t.Fatalf("invalid pack: %d %s", code, log)
	}
	if code, _ := run(t, "build", dir); code != ExitUsage {
		t.Fatal("build without --output or --push accepted")
	}
	if code, _ := run(t, "build", t.TempDir(), "--output", out); code != ExitUsage {
		t.Fatal("build of a directory without pack.yaml accepted")
	}
}
