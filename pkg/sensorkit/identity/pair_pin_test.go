package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "platform CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key}
}

// tlsFakePlatform is the pairing fake over HTTPS with a leaf from ca (the
// CA certificate sent in the chain), listening on localhost.
func tlsFakePlatform(t *testing.T, ca *testCA) (*fakePlatform, string) {
	t.Helper()
	_, pk, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakePlatform{t: t, platformKey: pk, finalStatus: pairing.StatusApproved}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "platform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return f, "https://localhost:" + port
}

func pairTLS(t *testing.T, url string) (*Identity, *Store, string) {
	t.Helper()
	var out bytes.Buffer
	store := NewStore(t.TempDir())
	id, err := Pair(context.Background(), PairOptions{BaseURL: url, Store: store, Out: &out,
		Host:  DefaultHostFacts("openctemio-sensor", "0.0.0-test", "dmz-01"),
		sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	return id, store, out.String()
}

// Pairing over HTTPS stores the SHA-256 of the trust anchor's
// SubjectPublicKeyInfo in identity.json.
func TestPairStoresThePlatformTLSPin(t *testing.T) {
	ca := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpsec.SetAPIRootCAs(pool)
	t.Cleanup(func() { httpsec.SetAPIRootCAs(nil) })
	_, url := tlsFakePlatform(t, ca)

	id, store, out := pairTLS(t, url)
	sum := sha256.Sum256(ca.cert.RawSubjectPublicKeyInfo)
	want := httpsec.FormatFingerprint(sum[:])
	if id.PlatformTLSPin != want || id.PlatformTLSPinElement != httpsec.PinElementAnchorSPKI {
		t.Fatalf("pin %q (%s), want %q (anchor_spki)", id.PlatformTLSPin, id.PlatformTLSPinElement, want)
	}
	b, _ := os.ReadFile(filepath.Join(store.Dir(), IdentityFile))
	var onDisk map[string]any
	_ = json.Unmarshal(b, &onDisk)
	if onDisk["platform_tls_pin"] != want || onDisk["platform_tls_pin_element"] != "anchor_spki" {
		t.Fatalf("identity.json: %s", b)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("the pin is not shown:\n%s", out)
	}
	loaded, _, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	element, fp, err := loaded.TLSPin()
	if err != nil || element != httpsec.PinElementAnchorSPKI || httpsec.FormatFingerprint(fp) != want {
		t.Fatalf("TLSPin: %s %x %v", element, fp, err)
	}
}

// SENSOR_CA_FINGERPRINT at pairing wins and is what the identity stores.
func TestPairStoresTheEnvironmentFingerprint(t *testing.T) {
	ca := newTestCA(t)
	sum := sha256.Sum256(ca.cert.Raw)
	httpsec.SetAPIPinnedCA(sum[:])
	t.Cleanup(func() { httpsec.SetAPIPinnedCA(nil) })
	_, url := tlsFakePlatform(t, ca)

	id, _, _ := pairTLS(t, url)
	if id.PlatformTLSPin != httpsec.FormatFingerprint(sum[:]) || id.PlatformTLSPinElement != httpsec.PinElementCACert {
		t.Fatalf("pin %q (%s)", id.PlatformTLSPin, id.PlatformTLSPinElement)
	}
}

// Over plain http there is nothing to pin, and an identity without a pin
// (an older SDK's) loads with none.
func TestPairWithoutTLSStoresNoPin(t *testing.T) {
	_, srv := newFakePlatform(t)
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.HTTPClient = nil
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	b, _ := os.ReadFile(filepath.Join(o.Store.Dir(), IdentityFile))
	if id.PlatformTLSPin != "" || strings.Contains(string(b), "platform_tls_pin") {
		t.Fatalf("plain http stored a pin: %s", b)
	}
	if element, fp, err := id.TLSPin(); element != "" || fp != nil || err != nil {
		t.Fatalf("TLSPin of an identity without a pin: %q %x %v", element, fp, err)
	}
}

func TestIdentityTLSPinRejectsMalformedPins(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	for _, id := range []Identity{
		{PlatformTLSPin: good},
		{PlatformTLSPin: good, PlatformTLSPinElement: "leaf"},
		{PlatformTLSPin: strings.Repeat("ab", 32), PlatformTLSPinElement: httpsec.PinElementAnchorSPKI},
		{PlatformTLSPin: "sha256:abcd", PlatformTLSPinElement: httpsec.PinElementAnchorSPKI},
	} {
		if _, _, err := id.TLSPin(); err == nil {
			t.Fatalf("accepted %+v", id)
		}
	}
}
