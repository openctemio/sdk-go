package sensorkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

type pinCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newPinCA(t *testing.T) *pinCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pinCA{cert: c, key: key}
}

// server is an HTTPS server on 127.0.0.1 with a fresh leaf from ca.
func (ca *pinCA) server(t *testing.T) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func getAPI(url string) error {
	resp, err := httpsec.NewAPIClient(5 * time.Second).Get(url)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

func resetPins(t *testing.T) {
	t.Helper()
	httpsec.SetAPIPinnedCA(nil)
	httpsec.SetAPIPinnedSPKI(nil)
	t.Cleanup(func() { httpsec.SetAPIPinnedCA(nil); httpsec.SetAPIPinnedSPKI(nil); httpsec.SetAPIRootCAs(nil) })
}

// A sensor paired with a pin enforces it on every platform client: a
// platform certificate from another CA is refused even though the trust
// store (here a CA file trusting both) accepts it; a new leaf from the
// pinned CA is accepted; the posture reports fingerprint.
func TestStoredTLSPinIsEnforced(t *testing.T) {
	resetPins(t)
	paired, other := newPinCA(t), newPinCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(paired.cert)
	pool.AddCert(other.cert)
	httpsec.SetAPIRootCAs(pool)

	sum := sha256.Sum256(paired.cert.RawSubjectPublicKeyInfo)
	id := &identity.Identity{PlatformTLSPin: httpsec.FormatFingerprint(sum[:]), PlatformTLSPinElement: httpsec.PinElementAnchorSPKI}
	var out, errw bytes.Buffer
	k := &Kit{out: &out, errw: &errw}
	if err := k.applyTLSPin(id); err != nil {
		t.Fatal(err)
	}
	if err := getAPI(paired.server(t).URL); err != nil {
		t.Fatalf("new leaf from the pinned CA: %v", err)
	}
	if err := getAPI(other.server(t).URL); !errors.Is(err, httpsec.ErrPlatformPinMismatch) {
		t.Fatalf("another CA after pairing: %v", err)
	}
	if got := core.PlatformTLSPin(); got != core.TLSPinFingerprint {
		t.Fatalf("posture pin %q", got)
	}
	if !strings.Contains(out.String(), id.PlatformTLSPin) {
		t.Fatalf("the start log does not name the pin:\n%s", out.String())
	}
}

// SENSOR_CA_FINGERPRINT wins over the stored pin.
func TestEnvironmentFingerprintWinsOverTheStoredPin(t *testing.T) {
	resetPins(t)
	envCA := newPinCA(t)
	envSum := sha256.Sum256(envCA.cert.Raw)
	httpsec.SetAPIPinnedCA(envSum[:])
	stored := sha256.Sum256(newPinCA(t).cert.RawSubjectPublicKeyInfo)
	id := &identity.Identity{PlatformTLSPin: httpsec.FormatFingerprint(stored[:]), PlatformTLSPinElement: httpsec.PinElementAnchorSPKI}
	k := &Kit{out: &bytes.Buffer{}, errw: &bytes.Buffer{}}
	if err := k.applyTLSPin(id); err != nil {
		t.Fatal(err)
	}
	if len(httpsec.APIPinnedSPKI()) != 0 || !bytes.Equal(httpsec.APIPinnedCA(), envSum[:]) {
		t.Fatal("the stored pin replaced SENSOR_CA_FINGERPRINT")
	}
}

// An identity without a pin (an older SDK, plain http) keeps today's
// behavior: no pin, posture none, a warning; a malformed pin stops the
// sensor.
func TestIdentityWithoutPinIsUnchanged(t *testing.T) {
	resetPins(t)
	var errw bytes.Buffer
	k := &Kit{out: &bytes.Buffer{}, errw: &errw}
	if err := k.applyTLSPin(&identity.Identity{SensorID: "s", KeyID: "k"}); err != nil {
		t.Fatal(err)
	}
	if httpsec.HasAPIPin() || core.PlatformTLSPin() != core.TLSPinNone {
		t.Fatal("an identity without a pin enabled one")
	}
	if !strings.Contains(errw.String(), "without a platform TLS pin") {
		t.Fatalf("no warning:\n%s", errw.String())
	}
	if err := k.applyTLSPin(&identity.Identity{PlatformTLSPin: "sha256:00", PlatformTLSPinElement: httpsec.PinElementAnchorSPKI}); err == nil {
		t.Fatal("a malformed pin was accepted")
	}
}
