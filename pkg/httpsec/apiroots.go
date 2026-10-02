package httpsec

import (
	"crypto/tls"
	"crypto/x509"
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
		return nil, fmt.Errorf("CA certificate file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA certificate file %s: %w", path, errNoCertificate)
	}
	return pool, nil
}

var errNoCertificate = errors.New("no PEM certificate in the file")

// apiTLSConfig is the TLS configuration of a new API client: nil (Go's
// defaults) unless SetAPIRootCAs set a pool.
func apiTLSConfig() *tls.Config {
	pool := APIRootCAs()
	if pool == nil {
		return nil
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
