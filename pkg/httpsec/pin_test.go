package httpsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func serverWithChain(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, sendCA bool, dnsNames ...string) *httptest.Server {
	t.Helper()
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "platform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: dnsNames, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca == nil { // self-signed platform certificate
		tpl.IsCA, tpl.BasicConstraintsValid = true, true
		tpl.KeyUsage |= x509.KeyUsageCertSign
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		srv := newLocalhostServer(t)
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{der}
	if sendCA {
		chain = append(chain, ca.Raw)
	}
	srv := newLocalhostServer(t)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newLocalhostServer listens on "localhost", so the server and the client
// resolve the name the same way (::1 first on some hosts, 127.0.0.1 on others).
func newLocalhostServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.Listener.Close()
	srv.Listener = ln
	return srv
}

// byName is the server URL with the host name localhost: a pinned connection
// needs a host name to check the certificate against.
func byName(srv *httptest.Server) string {
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "https://localhost:" + port
}

// byIP is the server URL with its IP address literal.
func byIP(srv *httptest.Server) string {
	return "https://" + srv.Listener.Addr().String()
}

func get(t *testing.T, url string) error {
	t.Helper()
	c := NewAPIClient(5 * time.Second)
	resp, err := c.Get(url)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestPinnedCA(t *testing.T) {
	ca, caKey := newCA(t)
	other, _ := newCA(t)
	sum := sha256.Sum256(ca.Raw)
	otherSum := sha256.Sum256(other.Raw)
	t.Cleanup(func() { SetAPIPinnedCA(nil) })

	withCA := serverWithChain(t, ca, caKey, true)
	SetAPIPinnedCA(sum[:])
	if err := get(t, byName(withCA)); err != nil {
		t.Fatalf("pinned CA in the chain: %v", err)
	}
	SetAPIPinnedCA(otherSum[:])
	if err := get(t, byName(withCA)); err == nil {
		t.Fatal("another pin must refuse the server")
	}
	withoutCA := serverWithChain(t, ca, caKey, false)
	SetAPIPinnedCA(sum[:])
	if err := get(t, byName(withoutCA)); err == nil {
		t.Fatal("a chain without the pinned certificate must be refused")
	}
	// The leaf itself may be pinned (self-signed platform certificate).
	self := serverWithChain(t, nil, nil, false)
	leaf := sha256.Sum256(self.Certificate().Raw)
	SetAPIPinnedCA(leaf[:])
	if err := get(t, byName(self)); err != nil {
		t.Fatalf("pinned self-signed certificate: %v", err)
	}
}

// crypto/tls leaves the server name empty for an IP address (no SNI) and
// x509 then skips the name check, so a pinned connection to an IP address is
// refused instead of verified without a name.
func TestPinnedCARefusesAnIPAddressURL(t *testing.T) {
	ca, caKey := newCA(t)
	sum := sha256.Sum256(ca.Raw)
	t.Cleanup(func() { SetAPIPinnedCA(nil) })
	srv := serverWithChain(t, ca, caKey, true)
	SetAPIPinnedCA(sum[:])
	err := get(t, byIP(srv))
	if err == nil || !strings.Contains(err.Error(), "host name") {
		t.Fatalf("a pinned connection to an IP address must be refused: %v", err)
	}
}

func TestParseCAFingerprint(t *testing.T) {
	h := hex.EncodeToString(make([]byte, 32))
	for _, s := range []string{h, "SHA256:" + h, "00:" + h[2:]} {
		if _, err := ParseCAFingerprint(s); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "abc", h + "00"} {
		if _, err := ParseCAFingerprint(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

// A pin replaces the trust store, not the rest of the verification: a
// certificate issued by the pinned CA for another name is still refused.
func TestPinnedCAStillChecksTheName(t *testing.T) {
	ca, caKey := newCA(t)
	sum := sha256.Sum256(ca.Raw)
	t.Cleanup(func() { SetAPIPinnedCA(nil) })
	srv := serverWithChain(t, ca, caKey, true, "platform.invalid") // not issued for localhost
	SetAPIPinnedCA(sum[:])
	err := get(t, byName(srv))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate for another name must be refused under a pin: %v", err)
	}
}
