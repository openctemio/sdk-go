package httpsec

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func spkiOf(c *x509.Certificate) []byte {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return sum[:]
}

// The anchor key pinned at pairing: a new leaf from the same CA is
// accepted; a server from another CA is refused even though the trust
// store trusts that CA (no fallback to it); a CA certificate pin
// (SENSOR_CA_FINGERPRINT) wins over the stored one.
func TestStoredAnchorPin(t *testing.T) {
	ca, caKey := newCA(t)
	other, otherKey := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pool.AddCert(other)
	SetAPIRootCAs(pool)
	t.Cleanup(func() { SetAPIRootCAs(nil); SetAPIPinnedSPKI(nil); SetAPIPinnedCA(nil) })

	first := serverWithChain(t, ca, caKey, false)
	renewed := serverWithChain(t, ca, caKey, false)
	foreign := serverWithChain(t, other, otherKey, true)
	if err := get(t, byName(foreign)); err != nil {
		t.Fatalf("without a pin the trust store accepts the other CA: %v", err)
	}

	SetAPIPinnedSPKI(spkiOf(ca))
	if !HasAPIPin() {
		t.Fatal("HasAPIPin")
	}
	if err := get(t, byName(first)); err != nil {
		t.Fatalf("pinned CA: %v", err)
	}
	if err := get(t, byIP(renewed)); err != nil {
		t.Fatalf("a new leaf from the pinned CA (by IP address): %v", err)
	}
	err := get(t, byName(foreign))
	if !errors.Is(err, ErrPlatformPinMismatch) {
		t.Fatalf("another CA must be refused with the pin error, got %v", err)
	}

	// SENSOR_CA_FINGERPRINT wins: the other CA's certificate is pinned.
	sum := sha256.Sum256(other.Raw)
	SetAPIPinnedCA(sum[:])
	if err := get(t, byName(foreign)); err != nil {
		t.Fatalf("the CA certificate pin must win over the stored pin: %v", err)
	}
}

// The pairing recorder pins the anchor key of the first verified
// connection and refuses a later connection of the same pairing to another
// CA.
func TestPinRecorder(t *testing.T) {
	ca, caKey := newCA(t)
	other, otherKey := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pool.AddCert(other)
	SetAPIRootCAs(pool)
	t.Cleanup(func() { SetAPIRootCAs(nil) })

	rec := &PinRecorder{}
	c := NewAPIClientRecordingPin(5*time.Second, rec)
	do := func(url string) error {
		resp, err := c.Get(url)
		if err == nil {
			_ = resp.Body.Close()
		}
		c.CloseIdleConnections()
		return err
	}
	if err := do(byName(serverWithChain(t, ca, caKey, false))); err != nil {
		t.Fatal(err)
	}
	if got := FormatFingerprint(rec.Pin()); got != FormatFingerprint(spkiOf(ca)) {
		t.Fatalf("recorded %s, want the CA key", got)
	}
	if err := do(byName(serverWithChain(t, ca, caKey, false))); err != nil {
		t.Fatalf("same CA, new leaf: %v", err)
	}
	if err := do(byName(serverWithChain(t, other, otherKey, false))); !errors.Is(err, ErrPlatformChangedDuringPairing) {
		t.Fatalf("another CA during pairing: %v", err)
	}

	// A self-signed platform certificate is its own anchor.
	self := serverWithChain(t, nil, nil, false)
	selfPool := x509.NewCertPool()
	selfPool.AddCert(self.Certificate())
	SetAPIRootCAs(selfPool)
	rec2 := &PinRecorder{}
	c2 := NewAPIClientRecordingPin(5*time.Second, rec2)
	resp, err := c2.Get(byName(self))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if FormatFingerprint(rec2.Pin()) != FormatFingerprint(spkiOf(self.Certificate())) {
		t.Fatal("self-signed: not pinned to its own key")
	}
}
