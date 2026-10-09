package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// issuingCA is a CA that certifies the sensor key, as the platform's
// certificate service does.
type issuingCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newIssuingCA(t *testing.T) *issuingCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sensor CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &issuingCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *issuingCA) clientCert(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// stubIssuer answers IssueCertificate with its chain, CA bundle and
// endpoint.
type stubIssuer struct {
	sensorv3connect.SensorServiceClient
	chain, bundle, endpoint string
}

func (s stubIssuer) IssueCertificate(context.Context, *connect.Request[sensorv3.IssueCertificateRequest]) (*connect.Response[sensorv3.IssueCertificateResponse], error) {
	return connect.NewResponse(&sensorv3.IssueCertificateResponse{CertificateChainPem: s.chain, CaBundlePem: s.bundle, GrpcEndpoint: s.endpoint}), nil
}

func stickyManager(t *testing.T, dir string) (*v3Manager, *sensorsig.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sensorsig.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return &v3Manager{signer: signer, opts: TransportOptions{CertDir: dir, Logf: t.Logf}}, signer
}

// The gRPC CA bundle pinned by an earlier run is sticky: a certificate
// answer for another endpoint with another bundle, over a channel without a
// platform TLS pin, does not replace it; the same bundle, or an answer over
// a pinned channel, is accepted.
func TestTransportV3_CABundleIsSticky(t *testing.T) {
	dir := t.TempDir()
	first, rogue := newIssuingCA(t), newIssuingCA(t)

	m, signer := stickyManager(t, dir)
	pub := signer.PublicKey()
	ctx := context.Background()
	if err := m.issue(ctx, stubIssuer{chain: first.clientCert(t, pub), bundle: first.pem, endpoint: "grpc-a:443"}, false); err != nil {
		t.Fatalf("first certificate: %v", err)
	}
	pinPath := filepath.Join(dir, pinFile)
	if b, _ := os.ReadFile(pinPath); string(b) != first.pem {
		t.Fatal("the first CA bundle was not persisted")
	}

	// A new run: the advertised endpoint changed and the unpinned HTTPS
	// answer carries another CA bundle.
	m2, _ := stickyManager(t, dir)
	m2.signer = signer
	err := m2.issue(ctx, stubIssuer{chain: rogue.clientCert(t, pub), bundle: rogue.pem, endpoint: "grpc-b:443"}, false)
	if !errors.Is(err, ErrCABundleChanged) {
		t.Fatalf("an endpoint change replaced the pinned CA over an unpinned channel: %v", err)
	}
	if b, _ := os.ReadFile(pinPath); string(b) != first.pem {
		t.Fatal("the persisted CA bundle changed")
	}
	if m2.pinPEM != "" || m2.cert.Load() != nil {
		t.Fatal("the refused answer was installed")
	}

	// The same bundle for the new endpoint is fine.
	if err := m2.issue(ctx, stubIssuer{chain: first.clientCert(t, pub), bundle: first.pem, endpoint: "grpc-b:443"}, false); err != nil {
		t.Fatalf("same bundle, new endpoint: %v", err)
	}
	// A new bundle over a pinned channel (gRPC renewal, or HTTPS under a
	// platform TLS pin) replaces it.
	if err := m2.issue(ctx, stubIssuer{chain: rogue.clientCert(t, pub), bundle: rogue.pem, endpoint: "grpc-b:443"}, true); err != nil {
		t.Fatalf("new bundle over a pinned channel: %v", err)
	}
	if b, _ := os.ReadFile(pinPath); string(b) != rogue.pem {
		t.Fatal("the CA bundle received over a pinned channel was not persisted")
	}
}
