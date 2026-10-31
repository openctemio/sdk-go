package httpsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCA(t *testing.T, root bool) string {
	t.Helper()
	rkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rtpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "R"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, _ := x509.CreateCertificate(rand.Reader, rtpl, rtpl, &rkey.PublicKey, rkey)
	rcert, _ := x509.ParseCertificate(rder)
	der := rder
	if !root {
		ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		itpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "I"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, _ = x509.CreateCertificate(rand.Reader, itpl, rcert, &ikey.PublicKey, rkey)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCAFileErrorsNameThePath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.pem")
	if _, err := LoadCAFile(missing); err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("missing: %v", err)
	}
	notPEM := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(notPEM, []byte("hello"), 0o600)
	if _, err := LoadCAFile(notPEM); err == nil || !strings.Contains(err.Error(), notPEM) || !strings.Contains(err.Error(), "not a PEM") {
		t.Fatalf("not pem: %v", err)
	}
}

func TestLoadCAFileDetectsAnIntermediateOnlyFile(t *testing.T) {
	p := writeCA(t, false)
	if _, err := LoadCAFile(p); err != nil {
		t.Fatal(err)
	}
	if CAFileIntermediateOnly() != p {
		t.Fatal("an intermediate-only file must be reported")
	}
	if _, err := LoadCAFile(writeCA(t, true)); err != nil {
		t.Fatal(err)
	}
	if CAFileIntermediateOnly() != "" {
		t.Fatal("a file with a root must not be reported")
	}
}
