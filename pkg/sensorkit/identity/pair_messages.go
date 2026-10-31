package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

// maxLinkLen bounds the approval link a platform may have printed.
const maxLinkLen = 512

// safeLink returns the approval link the platform sent when it is an
// absolute http(s) URL of printable characters, else "". The link reaches
// the operator's terminal: a control character could rewrite what the
// terminal shows, so none is ever printed.
func safeLink(raw string) string {
	if raw == "" || len(raw) > maxLinkLen {
		return ""
	}
	for _, r := range raw {
		if r < 0x21 || r == 0x7f || r > 0x7e {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return ""
	}
	return raw
}

// UntrustedTLSError: the platform presented a certificate chain this host
// does not trust (a private certificate authority, or something between the
// sensor and the platform). Retrying cannot fix it.
type UntrustedTLSError struct {
	// RootSHA256 is the SHA-256 of the last certificate the platform
	// presented (its authority when the chain is complete), hex with
	// colons; "" when no certificate was seen.
	RootSHA256 string
	cause      error
}

func (e *UntrustedTLSError) Error() string {
	fp := ""
	if e.RootSHA256 != "" {
		fp = " (it presented an authority with SHA-256 " + e.RootSHA256 + ")"
	}
	return "pairing: the platform's TLS certificate is signed by an authority this host does not trust" + fp +
		". If the platform uses a private certificate authority, compare this fingerprint with the one under the " +
		"console's install command, then use that command (it installs the authority) or set SENSOR_CA_CERT_FILE; " +
		"otherwise something between this host and the platform is intercepting TLS"
}

func (e *UntrustedTLSError) Unwrap() error { return e.cause }

// explainUntrustedTLS turns a certificate-verification failure into an
// UntrustedTLSError that says what to do; any other error is returned as is.
func explainUntrustedTLS(err error) error {
	if err == nil {
		return nil
	}
	var already *UntrustedTLSError
	if errors.As(err, &already) {
		return err
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		var ua x509.UnknownAuthorityError
		if !errors.As(cve.Err, &ua) {
			return err
		}
		out := &UntrustedTLSError{cause: err}
		if n := len(cve.UnverifiedCertificates); n > 0 {
			out.RootSHA256 = certFingerprint(cve.UnverifiedCertificates[n-1])
		}
		return out
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		out := &UntrustedTLSError{cause: err}
		if ua.Cert != nil {
			out.RootSHA256 = certFingerprint(ua.Cert)
		}
		return out
	}
	return err
}

func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}
