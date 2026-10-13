package httpsec

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// A pinned platform CA (api RFC-052 §4.7, SENSOR_CA_FINGERPRINT): the
// install snippet carries the SHA-256 fingerprint of a CA certificate of the
// platform's TLS chain (its root or an intermediate), or of a self-signed
// platform certificate. A root the platform does not send is taken from the
// API trust (SENSOR_CA_CERT_FILE, else the system trust store). With a pin, an API client accepts a
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

// pinnedTLSConfig verifies the chain against the pinned CA. Go's default
// verification is replaced (InsecureSkipVerify) by VerifyConnection, which
// performs the full x509 verification itself: name, validity, key usage and
// chain all still apply. roots is the API trust (SetAPIRootCAs, nil: the
// system trust store) at the time the client is created; it is used only to
// find a pinned root the server does not send (see verifyPinned).
func pinnedTLSConfig(pin []byte, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below, which verifies against the pinned CA
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinned(cs, pin, roots)
		},
	}
}

// ErrPinnedCANoServerName is a pinned connection without a server name to
// check the certificate against. crypto/tls leaves ConnectionState.ServerName
// empty when the platform URL is an IP address (no SNI), and x509 skips the
// name check for an empty DNSName, so such a connection is refused: with a
// pin, the platform URL must use a host name.
var ErrPinnedCANoServerName = errors.New("httpsec: a pinned platform CA needs a host name in the platform URL, not an IP address")

// verifyPinned accepts a server only when its certificate verifies up to
// the pinned certificate.
//
// When the server sends the pinned certificate (a root, an intermediate or
// a self-signed server certificate), that certificate is the only root the
// chain is verified against. Many servers do not send their root: the
// built-in gateway's internal CA sends the leaf and the intermediate only,
// while the console shows the root's fingerprint. The chain is then
// verified against the API trust (the CA file, else the system trust
// store), and accepted only when one of the verified chains contains the
// pinned certificate. Either way the pin must match a certificate of a
// chain that verified; a trusted CA that is not the pinned one (a public
// CA, an interception proxy's CA) cannot stand in for it.
func verifyPinned(cs tls.ConnectionState, pin []byte, roots *x509.CertPool) error {
	if cs.ServerName == "" {
		return ErrPinnedCANoServerName
	}
	if len(cs.PeerCertificates) == 0 {
		return ErrPinnedCAMismatch
	}
	var pinned *x509.Certificate
	intermediates := x509.NewCertPool()
	for _, c := range cs.PeerCertificates {
		if matchesPin(c, pin) {
			pinned = c
			continue
		}
		intermediates.AddCert(c)
	}
	leaf := cs.PeerCertificates[0]
	if pinned != nil {
		only := x509.NewCertPool()
		only.AddCert(pinned)
		opts := x509.VerifyOptions{Roots: only, DNSName: cs.ServerName}
		if leaf != pinned {
			opts.Intermediates = intermediates
		}
		_, err := leaf.Verify(opts)
		return err
	}
	// The pinned certificate was not sent: it must be in a chain that
	// verifies against the configured trust.
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: cs.ServerName})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPinnedCAMismatch, err)
	}
	for _, chain := range chains {
		for _, c := range chain {
			if matchesPin(c, pin) {
				return nil
			}
		}
	}
	return ErrPinnedCAMismatch
}

func matchesPin(c *x509.Certificate, pin []byte) bool {
	sum := sha256.Sum256(c.Raw)
	return bytes.Equal(sum[:], pin)
}
