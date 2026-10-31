package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/openctemio/sdk-go/pkg/httpsec"
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

// PresentedCert is one certificate of the chain the platform presented.
type PresentedCert struct {
	Subject string // common name (or the full subject when it has none)
	Issuer  string // issuer common name
	SHA256  string // hex with colons
}

// UntrustedTLSError reports that the platform presented a certificate chain this host
// does not trust (a private certificate authority, or something between the
// sensor and the platform). Retrying cannot fix it.
type UntrustedTLSError struct {
	// RootSHA256 is the SHA-256 of the last certificate the platform
	// presented (its authority when the chain is complete), hex with
	// colons; "" when no certificate was seen. It is usually an intermediate:
	// the root is not sent, see Presented and the issuer of the last one.
	RootSHA256 string
	// Presented lists every certificate the platform sent, leaf first.
	Presented []PresentedCert
	cause     error
}

func (e *UntrustedTLSError) Error() string {
	var b strings.Builder
	b.WriteString("pairing: the platform's TLS certificate is signed by an authority this host does not trust")
	if n := len(e.Presented); n > 0 {
		b.WriteString(". The platform presented:")
		for i, c := range e.Presented {
			fmt.Fprintf(&b, " [%d] %s (SHA-256 %s)", i+1, c.Subject, c.SHA256)
			if i < n-1 {
				b.WriteString(";")
			}
		}
		if top := e.Presented[n-1]; top.Issuer != "" && top.Issuer != top.Subject {
			fmt.Fprintf(&b, ". The last one is issued by %q: you need that root authority (the platform does not send it), "+
				"not only the intermediate; its SHA-256 is under the console's install command", top.Issuer)
		}
	} else if e.RootSHA256 != "" {
		b.WriteString(" (it presented an authority with SHA-256 " + e.RootSHA256 + ")")
	}
	b.WriteString(". If the platform uses a private certificate authority, set SENSOR_CA_SHA256 to the root's SHA-256 " +
		"(the console's install command does) so this sensor fetches and trusts exactly that root, or give it the root " +
		"with SENSOR_CA_CERT_FILE; otherwise something between this host and the platform is intercepting TLS")
	if p := httpsec.CAFileIntermediateOnly(); p != "" {
		fmt.Fprintf(&b, ". SENSOR_CA_CERT_FILE %s holds only an intermediate certificate, no root: add the root (self-signed) certificate to it", p)
	}
	return b.String()
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
		for _, c := range cve.UnverifiedCertificates {
			out.Presented = append(out.Presented, PresentedCert{Subject: certName(c.Subject.CommonName, c.Subject.String()),
				Issuer: c.Issuer.CommonName, SHA256: certFingerprint(c)})
		}
		if n := len(out.Presented); n > 0 {
			out.RootSHA256 = out.Presented[n-1].SHA256
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

func certName(cn, full string) string {
	if cn != "" {
		return cn
	}
	return full
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
