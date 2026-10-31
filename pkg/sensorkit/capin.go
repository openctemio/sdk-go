package sensorkit

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

const (
	// EnvCASHA256 lists the SHA-256 fingerprints (64 hex digits, colons
	// optional, comma separated so a root can be rotated) of the platform's
	// private root CA. With it, a sensor whose platform certificate this host
	// does not trust fetches the platform's public CA bundle itself and trusts
	// only a certificate that matches a pin and signs the chain the server
	// presents. Without it nothing is ever trusted automatically.
	EnvCASHA256 = "SENSOR_CA_SHA256"

	// platformCAPath is the public, unauthenticated endpoint that serves the
	// platform's CA certificates (never a key).
	platformCAPath = "/api/v1/sensors/platform-ca"
	// platformCAFile is where the accepted CA is kept in the state directory.
	platformCAFile = "platform-ca.pem"

	maxPlatformCABytes = 256 << 10
	platformCATimeout  = 15 * time.Second
)

// ParseCAPins parses a SENSOR_CA_SHA256 value: SHA-256 fingerprints separated
// by commas or spaces.
func ParseCAPins(s string) ([][]byte, error) {
	var pins [][]byte
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		fp, err := httpsec.ParseCAFingerprint(f)
		if err != nil {
			return nil, err
		}
		pins = append(pins, fp)
	}
	if len(pins) == 0 {
		return nil, errors.New("no fingerprint given")
	}
	return pins, nil
}

func certSHA256(c *x509.Certificate) [sha256.Size]byte { return sha256.Sum256(c.Raw) }

func matchesPin(c *x509.Certificate, pins [][]byte) bool {
	sum := certSHA256(c)
	for _, p := range pins {
		if string(p) == string(sum[:]) {
			return true
		}
	}
	return false
}

// parseCertPEM returns the certificates of a PEM bundle; other blocks (a key
// must never be in it) are ignored.
func parseCertPEM(data []byte) []*x509.Certificate {
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

// verifyPinnedBundle accepts a fetched bundle only when a certificate in it
// matches a pin AND that certificate (with the intermediates the server sent)
// signs the leaf the server presented for host. It returns the pinned
// certificates, the only ones that become trust anchors.
func verifyPinnedBundle(bundle, presented []*x509.Certificate, host string, pins [][]byte) ([]*x509.Certificate, error) {
	var pinned []*x509.Certificate
	for _, c := range bundle {
		if matchesPin(c, pins) {
			pinned = append(pinned, c)
		}
	}
	if len(pinned) == 0 {
		return nil, fmt.Errorf("no certificate in the platform's CA bundle matches %s; refusing to trust it", EnvCASHA256)
	}
	if len(presented) == 0 {
		return nil, errors.New("the server presented no certificate")
	}
	roots := x509.NewCertPool()
	for _, c := range pinned {
		roots.AddCert(c)
	}
	inter := x509.NewCertPool()
	for _, c := range presented[1:] {
		inter.AddCert(c)
	}
	for _, c := range bundle {
		inter.AddCert(c)
	}
	if _, err := presented[0].Verify(x509.VerifyOptions{
		DNSName: host, Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("the certificate matching %s does not sign the chain this server presents (%v); refusing to trust it", EnvCASHA256, err)
	}
	return pinned, nil
}

// fetchPlatformCA downloads the CA bundle without verifying the chain (it is
// what the sensor does not trust yet) and returns it with the chain the
// server presented on that same connection. The caller must verify both
// against the pin before trusting anything.
func fetchPlatformCA(ctx context.Context, apiURL *url.URL) (bundle, presented []*x509.Certificate, err error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // G402: verified against the pin by verifyPinnedBundle before anything is trusted
			VerifyConnection: func(cs tls.ConnectionState) error {
				presented = cs.PeerCertificates
				return nil
			},
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: platformCATimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := *apiURL
	u.Path = strings.TrimRight(u.Path, "/") + platformCAPath
	u.RawQuery, u.Fragment = "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s answered HTTP %d (the platform has no private CA configured, or is too old)", platformCAPath, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPlatformCABytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxPlatformCABytes {
		return nil, nil, errors.New("the CA bundle is too large")
	}
	return parseCertPEM(body), presented, nil
}

// probeTrust dials host with the pool and reports whether the chain verifies;
// unknown is true only when the failure is an unknown authority.
func probeTrust(ctx context.Context, apiURL *url.URL, pool *x509.CertPool) (ok, unknown bool) {
	port := apiURL.Port()
	if port == "" {
		port = "443"
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: apiURL.Hostname()}}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(apiURL.Hostname(), port))
	if err == nil {
		_ = c.Close()
		return true, false
	}
	var ua x509.UnknownAuthorityError
	return false, errors.As(err, &ua)
}

func basePool() *x509.CertPool {
	if p := httpsec.APIRootCAs(); p != nil {
		return p.Clone()
	}
	p, err := x509.SystemCertPool()
	if err != nil || p == nil {
		return x509.NewCertPool()
	}
	return p
}

func setPlatformRoots(pool *x509.CertPool) {
	httpsec.SetAPIRootCAs(pool)
	httpsec.SetContentRootCAs(pool)
}

func describeCert(c *x509.Certificate) string {
	sum := certSHA256(c)
	return fmt.Sprintf("%s (SHA-256 %s)", c.Subject.CommonName, formatFP(sum[:]))
}

func formatFP(b []byte) string {
	h := strings.ToUpper(fmt.Sprintf("%x", b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// autoTrustPlatformCA makes a platform behind a private CA reachable when
// SENSOR_CA_SHA256 is set. It never fails the start: when the CA cannot be
// established the sensor goes on and reports its own untrusted-TLS error.
func autoTrustPlatformCA(ctx context.Context, apiURL, stateDir string, pins [][]byte, out io.Writer) {
	u, err := url.Parse(apiURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return
	}
	file := filepath.Join(stateDir, platformCAFile)
	base := basePool()
	if ok, unknown := probeTrust(ctx, u, base); ok || !unknown {
		return
	}
	// A bundle kept earlier: use it while its certificate still matches a pin.
	if data, err := os.ReadFile(file); err == nil { // #nosec G304 -- the sensor's own state file
		pool := base.Clone()
		n := 0
		for _, c := range parseCertPEM(data) {
			if matchesPin(c, pins) {
				pool.AddCert(c)
				n++
			}
		}
		if n > 0 {
			if ok, unknown := probeTrust(ctx, u, pool); ok || !unknown {
				setPlatformRoots(pool)
				return
			}
		}
	}
	bundle, presented, err := fetchPlatformCA(ctx, u)
	if err != nil {
		_, _ = fmt.Fprintf(out, "Warning: could not fetch the platform's CA (%s=...): %v\n", EnvCASHA256, err)
		return
	}
	pinned, err := verifyPinnedBundle(bundle, presented, u.Hostname(), pins)
	if err != nil {
		_, _ = fmt.Fprintf(out, "Warning: %v. Check %s against the fingerprint the console shows, or something is intercepting TLS.\n", err, EnvCASHA256)
		return
	}
	var buf []byte
	pool := base.Clone()
	for _, c := range pinned {
		pool.AddCert(c)
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := writeFileAtomic(file, buf); err != nil {
		_, _ = fmt.Fprintf(out, "Warning: trusting the platform CA for this run only; could not save %s: %v\n", file, err)
	}
	for _, c := range pinned {
		_, _ = fmt.Fprintf(out, "Trusting the platform's CA %s, pinned by %s.\n", describeCert(c), EnvCASHA256)
	}
	setPlatformRoots(pool)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".platform-ca-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil { // #nosec G302 -- public certificate
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
