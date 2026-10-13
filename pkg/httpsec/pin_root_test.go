package httpsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// pkiChain is a root CA, an intermediate CA signed by it and a server
// certificate signed by the intermediate: the shape of the built-in
// gateway's internal CA.
type pkiChain struct {
	root, inter, leaf *x509.Certificate
	leafKey           *ecdsa.PrivateKey
}

func newPKIChain(t *testing.T, leafName string) pkiChain {
	t.Helper()
	root, rootKey := newCA(t)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	interDER, err := x509.CreateCertificate(rand.Reader, interTpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "platform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{leafName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return pkiChain{root: root, inter: inter, leaf: leaf, leafKey: leafKey}
}

// serve starts a server that sends certs (leaf first) and no others.
func (p pkiChain) serve(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	chain := make([][]byte, 0, len(certs))
	for _, c := range certs {
		chain = append(chain, c.Raw)
	}
	srv := newLocalhostServer(t)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: p.leafKey}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return byName(srv)
}

func fingerprint(c *x509.Certificate) []byte {
	sum := sha256.Sum256(c.Raw)
	return sum[:]
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func pinWith(t *testing.T, pin []byte, roots *x509.CertPool) {
	t.Helper()
	t.Cleanup(func() { SetAPIPinnedCA(nil); SetAPIRootCAs(nil) })
	SetAPIRootCAs(roots)
	SetAPIPinnedCA(pin)
}

// The gateway sends the leaf and the intermediate only; the operator pins
// the root's fingerprint (the one the console shows) and gives the root in
// the CA file. The chain verifies against the CA file and contains the pin.
func TestPinnedRootNotSentVerifiesFromTheCAFile(t *testing.T) {
	p := newPKIChain(t, "localhost")
	url := p.serve(t, p.leaf, p.inter)
	pinWith(t, fingerprint(p.root), poolOf(p.root))
	if err := get(t, url); err != nil {
		t.Fatalf("pinned root in the CA file, not sent by the server: %v", err)
	}
}

// Without the root anywhere (no CA file, not in the system store, not
// sent), nothing can show the chain leads to the pin: refused.
func TestPinnedRootNotSentAndNotTrustedIsRefused(t *testing.T) {
	p := newPKIChain(t, "localhost")
	url := p.serve(t, p.leaf, p.inter)
	pinWith(t, fingerprint(p.root), nil)
	if err := get(t, url); err == nil || !errors.Is(err, ErrPinnedCAMismatch) {
		t.Fatalf("a root nobody provides must be refused with ErrPinnedCAMismatch: %v", err)
	}
}

// A sent intermediate may be pinned: it becomes the only root, so no CA
// file is needed.
func TestPinnedIntermediate(t *testing.T) {
	p := newPKIChain(t, "localhost")
	url := p.serve(t, p.leaf, p.inter)
	pinWith(t, fingerprint(p.inter), nil)
	if err := get(t, url); err != nil {
		t.Fatalf("pinned intermediate sent by the server: %v", err)
	}
	// An intermediate that is not sent but reached through the CA file.
	url = p.serve(t, p.leaf)
	pinWith(t, fingerprint(p.inter), poolOf(p.root, p.inter))
	if err := get(t, url); err != nil {
		t.Fatalf("pinned intermediate from the CA file: %v", err)
	}
}

// A pin that is not in the verified chain is refused even when the server's
// chain verifies against the CA file: another trusted CA (an interception
// proxy's, a second CA in the file) cannot stand in for the pinned one.
func TestWrongPinIsRefusedEvenWhenTheChainIsTrusted(t *testing.T) {
	platform := newPKIChain(t, "localhost")
	proxy := newPKIChain(t, "localhost")
	url := proxy.serve(t, proxy.leaf, proxy.inter)
	pinWith(t, fingerprint(platform.root), poolOf(platform.root, proxy.root))
	if err := get(t, url); err == nil || !errors.Is(err, ErrPinnedCAMismatch) {
		t.Fatalf("a chain to another trusted CA must be refused: %v", err)
	}
	// A pin of a certificate that is in the CA file but not a CA of this
	// chain is refused too.
	url = platform.serve(t, platform.leaf, platform.inter)
	pinWith(t, fingerprint(proxy.root), poolOf(platform.root, proxy.root))
	if err := get(t, url); err == nil || !errors.Is(err, ErrPinnedCAMismatch) {
		t.Fatalf("a pin outside the verified chain must be refused: %v", err)
	}
}

// The trust-store path keeps the name check: a certificate for another name
// under the pinned root is refused.
func TestPinnedRootFromTheCAFileStillChecksTheName(t *testing.T) {
	p := newPKIChain(t, "platform.invalid")
	url := p.serve(t, p.leaf, p.inter)
	pinWith(t, fingerprint(p.root), poolOf(p.root))
	if err := get(t, url); err == nil {
		t.Fatal("a certificate for another name must be refused under a pin")
	}
}

// A pinned self-signed server certificate keeps working with a CA file set.
func TestPinnedSelfSignedLeafWithACAFile(t *testing.T) {
	self := serverWithChain(t, nil, nil, false)
	other, _ := newCA(t)
	pinWith(t, fingerprint(self.Certificate()), poolOf(other))
	if err := get(t, byName(self)); err != nil {
		t.Fatalf("pinned self-signed certificate: %v", err)
	}
	pinWith(t, fingerprint(other), poolOf(other))
	if err := get(t, byName(self)); err == nil {
		t.Fatal("a self-signed certificate that is not pinned must be refused")
	}
}
