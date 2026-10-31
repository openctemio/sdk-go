package httpsec

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
)

// The certificate authorities the OpenCTEM API clients (NewAPIClient) trust.
// A platform behind a private CA (the built-in gateway's internal CA, a
// corporate CA) is reached by adding that CA here, once at start-up, instead
// of installing it in the host's or image's trust store. nil (the default)
// is the system trust store.
var (
	apiRootsMu sync.RWMutex
	apiRoots   *x509.CertPool
)

// SetAPIRootCAs makes every API client created afterwards (NewAPIClient)
// trust pool instead of the system trust store; nil goes back to the system
// trust store. Clients created before keep their trust.
func SetAPIRootCAs(pool *x509.CertPool) {
	apiRootsMu.Lock()
	apiRoots = pool
	apiRootsMu.Unlock()
}

// APIRootCAs returns the pool set with SetAPIRootCAs (nil: system trust).
func APIRootCAs() *x509.CertPool {
	apiRootsMu.RLock()
	defer apiRootsMu.RUnlock()
	return apiRoots
}

// LoadCAFile returns the system trust store plus the PEM certificates in
// path, for SetAPIRootCAs: the platform's private CA is trusted and the
// public CAs keep working (a proxy or a platform that later moves to a public
// certificate). A file without a certificate is an error.
func LoadCAFile(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) // #nosec G304 -- operator-configured CA file
	if err != nil {
		return nil, fmt.Errorf("CA certificate file %s cannot be read: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	certs := parseCAFileCerts(pem)
	if len(certs) == 0 {
		return nil, fmt.Errorf("CA certificate file %s is not a PEM certificate file (no -----BEGIN CERTIFICATE----- block): %w", path, errNoCertificate)
	}
	root := false
	for _, c := range certs {
		pool.AddCert(c)
		if c.CheckSignatureFrom(c) == nil && string(c.RawIssuer) == string(c.RawSubject) {
			root = true
		}
	}
	setCAFileInfo(path, !root)
	return pool, nil
}

func parseCAFileCerts(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

var (
	caFileMu               sync.Mutex
	caFilePath             string
	caFileIntermediateOnly bool
)

func setCAFileInfo(path string, intermediateOnly bool) {
	caFileMu.Lock()
	caFilePath, caFileIntermediateOnly = path, intermediateOnly
	caFileMu.Unlock()
}

// CAFileIntermediateOnly returns the path of the CA file loaded with
// LoadCAFile when it holds no root (self-signed) certificate, else "".
func CAFileIntermediateOnly() string {
	caFileMu.Lock()
	defer caFileMu.Unlock()
	if caFileIntermediateOnly {
		return caFilePath
	}
	return ""
}

var errNoCertificate = errors.New("no PEM certificate in the file")

// apiTLSConfig is the TLS configuration of a new API client: nil (Go's
// defaults) unless SetAPIRootCAs set a pool or SetAPIPinnedSPKI a pin; a
// CA certificate pin (SetAPIPinnedCA) wins. An anchor key pin keeps the
// trust store's verification and then requires the verified chain to lead
// to the pinned key: a mismatch fails the handshake, with no other trust
// to fall back on.
func apiTLSConfig() *tls.Config {
	if pin := APIPinnedCA(); len(pin) > 0 {
		return pinnedTLSConfig(pin, APIRootCAs())
	}
	pool, spki := APIRootCAs(), APIPinnedSPKI()
	if pool == nil && len(spki) == 0 {
		return nil
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if len(spki) > 0 {
		cfg.VerifyConnection = verifySPKI(spki)
	}
	return cfg
}
