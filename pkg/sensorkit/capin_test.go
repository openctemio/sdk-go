package sensorkit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key}
}

func (ca *testCA) leaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "platform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func pemOf(cs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

func pinOf(c *x509.Certificate) []byte { s := certSHA256(c); return s[:] }

// platform serves leaf + intermediate (never the root) and the CA bundle.
func platform(t *testing.T, root, inter *testCA, bundle []byte, hits *atomic.Int32) *url.URL {
	t.Helper()
	leaf := inter.leaf(t)
	leaf.Certificate = append(leaf.Certificate, inter.cert.Raw)
	mux := http.NewServeMux()
	mux.HandleFunc(platformCAPath, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(bundle)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u
}

func trusted(u *url.URL) bool {
	ok, _ := probeTrust(context.Background(), u, httpsec.APIRootCAs())
	return ok
}

func run(t *testing.T, u *url.URL, dir string, pins ...[]byte) string {
	t.Helper()
	httpsec.SetAPIRootCAs(nil)
	httpsec.SetContentRootCAs(nil)
	t.Cleanup(func() { httpsec.SetAPIRootCAs(nil); httpsec.SetContentRootCAs(nil) })
	var out bytes.Buffer
	autoTrustPlatformCA(context.Background(), u.String(), dir, pins, &out)
	return out.String()
}

func TestAutoTrustFetchesStoresAndReuses(t *testing.T) {
	root := newTestCA(t, "Test Root", nil)
	inter := newTestCA(t, "Test Intermediate", root)
	var hits atomic.Int32
	u := platform(t, root, inter, pemOf(root.cert, inter.cert), &hits)
	if trusted(u) {
		t.Fatal("the private CA must be untrusted before")
	}
	dir := t.TempDir()
	out := run(t, u, dir, pinOf(root.cert))
	if !trusted(u) || !strings.Contains(out, "Test Root") {
		t.Fatalf("not trusted after a pinned fetch; output %q", out)
	}
	fi, err := os.Stat(filepath.Join(dir, platformCAFile))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("stored file: %v %v", fi, err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, platformCAFile))
	if got := parseCertPEM(data); len(got) != 1 || !got[0].Equal(root.cert) {
		t.Fatal("only the pinned certificate may be stored")
	}
	// A second start reuses the stored CA: no new request to the platform.
	before := hits.Load()
	run(t, u, dir, pinOf(root.cert))
	if !trusted(u) || hits.Load() != before {
		t.Fatalf("stored CA not reused (hits %d -> %d)", before, hits.Load())
	}
}

func TestAutoTrustRefusals(t *testing.T) {
	root := newTestCA(t, "Test Root", nil)
	inter := newTestCA(t, "Test Intermediate", root)
	other := newTestCA(t, "Unrelated Root", nil)
	evil := newTestCA(t, "Evil Root", nil)
	evilInter := newTestCA(t, "Evil Intermediate", evil)
	var hits atomic.Int32

	t.Run("wrong pin", func(t *testing.T) {
		u := platform(t, root, inter, pemOf(root.cert, inter.cert), &hits)
		dir := t.TempDir()
		out := run(t, u, dir, pinOf(other.cert))
		if trusted(u) || !strings.Contains(out, "matches") {
			t.Fatalf("a wrong pin must not trust: %q", out)
		}
		if _, err := os.Stat(filepath.Join(dir, platformCAFile)); err == nil {
			t.Fatal("nothing may be stored")
		}
	})
	t.Run("pin matches an unrelated certificate that does not sign the chain", func(t *testing.T) {
		u := platform(t, root, inter, pemOf(root.cert, other.cert), &hits)
		out := run(t, u, t.TempDir(), pinOf(other.cert))
		if trusted(u) || !strings.Contains(out, "does not sign") {
			t.Fatalf("an unrelated pinned certificate must be refused: %q", out)
		}
	})
	t.Run("man in the middle serving the real root with its own chain", func(t *testing.T) {
		u := platform(t, evil, evilInter, pemOf(root.cert), &hits)
		dir := t.TempDir()
		out := run(t, u, dir, pinOf(root.cert))
		if trusted(u) || !strings.Contains(out, "does not sign") {
			t.Fatalf("a chain the pinned root did not sign must be refused: %q", out)
		}
		if _, err := os.Stat(filepath.Join(dir, platformCAFile)); err == nil {
			t.Fatal("nothing may be stored")
		}
	})
	t.Run("no pin, no trust", func(t *testing.T) {
		u := platform(t, root, inter, pemOf(root.cert), &hits)
		if _, err := ParseCAPins(""); err == nil {
			t.Fatal("an empty pin list must be an error")
		}
		if trusted(u) {
			t.Fatal("unpinned CA trusted")
		}
	})
}

func TestAutoTrustRotationAcceptsAnyPin(t *testing.T) {
	root := newTestCA(t, "New Root", nil)
	inter := newTestCA(t, "New Intermediate", root)
	old := newTestCA(t, "Old Root", nil)
	var hits atomic.Int32
	u := platform(t, root, inter, pemOf(root.cert, inter.cert), &hits)
	run(t, u, t.TempDir(), pinOf(old.cert), pinOf(root.cert))
	if !trusted(u) {
		t.Fatal("the new root's pin in the list must be enough")
	}
}

func TestStoredCAIgnoredWhenPinChanged(t *testing.T) {
	root := newTestCA(t, "Test Root", nil)
	inter := newTestCA(t, "Test Intermediate", root)
	other := newTestCA(t, "Other", nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, platformCAFile), pemOf(root.cert), 0o644); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	u := platform(t, root, inter, pemOf(root.cert), &hits)
	run(t, u, dir, pinOf(other.cert))
	if trusted(u) {
		t.Fatal("a stored CA that no longer matches a pin must not be trusted")
	}
}

func TestParseCAPins(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("CD", 32)
	pins, err := ParseCAPins(a + ", sha256:" + b)
	if err != nil || len(pins) != 2 {
		t.Fatalf("%v %v", pins, err)
	}
	if _, err := ParseCAPins("zz"); err == nil {
		t.Fatal("bad hex accepted")
	}
}
