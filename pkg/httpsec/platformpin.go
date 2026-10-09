package httpsec

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"
)

// The platform TLS pin recorded at pairing (api RFC-040 §11.4 Q10): a
// sensor paired without SENSOR_CA_FINGERPRINT pins the SHA-256 of the
// SubjectPublicKeyInfo of the trust anchor its pairing connection verified
// (the root CA of the verified chain, or the platform's self-signed
// certificate), and from then on accepts a platform certificate only when
// its verified chain still leads to that key.
//
// Why the anchor's key: a server rarely sends its root, so a pin must be on
// something the sensor reconstructs itself, which the verified chain is. A
// leaf or intermediate pin breaks on routine renewal (public CAs rotate
// their issuing intermediates on their own), while the anchor's key stays
// the same across leaf and intermediate rotation and across a re-issued
// root certificate with the same key. A certificate from any other CA (a
// TLS-inspecting proxy whose CA is in the trust store, a publicly trusted
// certificate from another CA) leads to another anchor and is refused. The
// trust store (system roots plus SENSOR_CA_CERT_FILE) still verifies the
// chain, name and validity first: the pin narrows it, never widens it.

// Platform TLS pin elements, as identity.json records them.
const (
	// PinElementAnchorSPKI: SHA-256 of the SubjectPublicKeyInfo of the
	// verified chain's trust anchor, recorded at pairing.
	PinElementAnchorSPKI = "anchor_spki"
	// PinElementCACert: SHA-256 of a CA certificate in the presented chain
	// (SENSOR_CA_FINGERPRINT; see SetAPIPinnedCA).
	PinElementCACert = "ca_cert"
)

// ErrPlatformPinMismatch is a platform certificate whose verified chain does
// not lead to the key pinned at pairing. It is never answered by trusting
// the system roots instead.
var ErrPlatformPinMismatch = errors.New("httpsec: platform certificate does not match the pin stored at pairing; re-pair or set SENSOR_CA_FINGERPRINT")

// ErrPlatformChangedDuringPairing is a pairing whose later connections
// presented a certificate leading to another anchor than the first.
var ErrPlatformChangedDuringPairing = errors.New("httpsec: the platform's certificate chain changed to another CA during pairing")

var (
	apiSPKIMu sync.RWMutex
	apiSPKI   []byte
)

// SetAPIPinnedSPKI pins every API client created afterwards to the trust
// anchor key with this SHA-256 SubjectPublicKeyInfo fingerprint (nil
// removes the pin). A CA certificate pin (SetAPIPinnedCA) wins over it.
func SetAPIPinnedSPKI(fingerprint []byte) {
	apiSPKIMu.Lock()
	apiSPKI = nil
	if len(fingerprint) > 0 {
		apiSPKI = append([]byte(nil), fingerprint...)
	}
	apiSPKIMu.Unlock()
}

// APIPinnedSPKI returns the pin set with SetAPIPinnedSPKI.
func APIPinnedSPKI() []byte {
	apiSPKIMu.RLock()
	defer apiSPKIMu.RUnlock()
	return apiSPKI
}

// HasAPIPin reports whether API clients created now pin the platform's TLS
// identity (a CA certificate or an anchor key).
func HasAPIPin() bool { return len(APIPinnedCA()) > 0 || len(APIPinnedSPKI()) > 0 }

// FormatFingerprint is a SHA-256 fingerprint as "sha256:<64 hex digits>".
func FormatFingerprint(fp []byte) string { return "sha256:" + hex.EncodeToString(fp) }

// AnchorSPKI is the pin of a verified connection: the SHA-256 of the
// SubjectPublicKeyInfo of the trust anchor of its shortest verified chain
// (nil without a verified chain).
func AnchorSPKI(chains [][]*x509.Certificate) []byte {
	var best []*x509.Certificate
	for _, c := range chains {
		if len(c) > 0 && (best == nil || len(c) < len(best)) {
			best = c
		}
	}
	if best == nil {
		return nil
	}
	sum := sha256.Sum256(best[len(best)-1].RawSubjectPublicKeyInfo)
	return sum[:]
}

// chainsHaveSPKI reports whether a certificate of any verified chain has
// the pinned key (the anchor, or a cross-signed certificate of it).
func chainsHaveSPKI(chains [][]*x509.Certificate, pin []byte) bool {
	for _, chain := range chains {
		for _, c := range chain {
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if bytes.Equal(sum[:], pin) {
				return true
			}
		}
	}
	return false
}

// verifySPKI checks a connection, already verified against the trust
// store, against the anchor key pin.
func verifySPKI(pin []byte) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if !chainsHaveSPKI(cs.VerifiedChains, pin) {
			return ErrPlatformPinMismatch
		}
		return nil
	}
}

// PinRecorder learns the platform pin of a pairing: the anchor key of the
// first verified connection, which every later connection of the same
// client must then lead to as well.
type PinRecorder struct {
	mu  sync.Mutex
	pin []byte
}

// Pin is the recorded anchor key fingerprint (nil: no verified TLS
// connection yet, a plain http platform, or a connection a CA certificate
// pin verified, whose pin is that certificate's).
func (r *PinRecorder) Pin() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pin
}

func (r *PinRecorder) verify(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 {
		// A CA certificate pin verified the chain itself (pinnedTLSConfig).
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pin == nil {
		r.pin = AnchorSPKI(cs.VerifiedChains)
		return nil
	}
	if !chainsHaveSPKI(cs.VerifiedChains, r.pin) {
		return ErrPlatformChangedDuringPairing
	}
	return nil
}

// NewAPIClientRecordingPin is NewAPIClient that also records the platform's
// pin in r (pairing).
func NewAPIClientRecordingPin(timeout time.Duration, r *PinRecorder) *http.Client {
	c := NewAPIClient(timeout)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		return c
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tr.TLSClientConfig != nil {
		cfg = tr.TLSClientConfig.Clone()
	}
	prev := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if prev != nil {
			if err := prev(cs); err != nil {
				return err
			}
		}
		return r.verify(cs)
	}
	tr.TLSClientConfig = cfg
	return c
}
