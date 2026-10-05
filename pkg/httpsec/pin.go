package httpsec

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

// A pinned platform CA (api RFC-052 §4.7, SENSOR_CA_FINGERPRINT): the
// install snippet carries the SHA-256 fingerprint of a CA certificate the
// platform presents in its TLS chain (its root or an intermediate), or of a
// self-signed platform certificate. With a pin, an API client accepts a
// server only when its chain verifies up to the certificate with exactly
// that fingerprint (name, validity and usage are still checked); neither the system
// trust store nor an interception proxy's CA can stand in for it. The first
// contact of a new sensor (pairing) therefore cannot be answered by a fake
// platform, even one holding a publicly trusted certificate for the name.
var (
	apiPinMu sync.RWMutex
	apiPin   []byte
)

// ErrPinnedCAMismatch is a server whose chain does not lead to the pinned CA.
var ErrPinnedCAMismatch = errors.New("httpsec: the platform's certificate chain does not contain the pinned CA")

// ParseCAFingerprint reads a SHA-256 fingerprint written as 64 hex digits,
// optionally with colons and an "SHA256:" prefix.
func ParseCAFingerprint(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "SHA256:"), "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("httpsec: CA fingerprint must be 64 hex digits (SHA-256)")
	}
	return b, nil
}

// SetAPIPinnedCA pins every API client created afterwards to the CA with
// this SHA-256 fingerprint (nil removes the pin).
func SetAPIPinnedCA(fingerprint []byte) {
	apiPinMu.Lock()
	apiPin = append([]byte(nil), fingerprint...)
	if len(fingerprint) == 0 {
		apiPin = nil
	}
	apiPinMu.Unlock()
}

// APIPinnedCA returns the pin set with SetAPIPinnedCA.
func APIPinnedCA() []byte {
	apiPinMu.RLock()
	defer apiPinMu.RUnlock()
	return apiPin
}

// pinnedTLSConfig verifies the chain against the pinned CA only. Go's
// default verification is replaced (InsecureSkipVerify) by VerifyConnection,
// which performs the full x509 verification with the pinned certificate as
// the only root: name, validity, key usage and chain all still apply.
func pinnedTLSConfig(pin []byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below, which verifies against the pinned CA
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinned(cs, pin)
		},
	}
}

func verifyPinned(cs tls.ConnectionState, pin []byte) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrPinnedCAMismatch
	}
	var root *x509.Certificate
	intermediates := x509.NewCertPool()
	for _, c := range cs.PeerCertificates {
		sum := sha256.Sum256(c.Raw)
		if bytes.Equal(sum[:], pin) {
			root = c
			continue
		}
		intermediates.AddCert(c)
	}
	if root == nil {
		return ErrPinnedCAMismatch
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leaf := cs.PeerCertificates[0]
	if leaf == root {
		// A pinned self-signed server certificate.
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: cs.ServerName})
		return err
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: cs.ServerName})
	return err
}
