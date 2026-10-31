// Package tlsprobe reads what a host shows in a TLS handshake, whether or
// not it then answers HTTP: the leaf certificate (as core.TLSLeaf) and, on
// request, whether one HTTP request gets an answer.
//
// Scanners never verify certificates (they must see a host whose
// certificate expired or names another site), so a host that completes the
// handshake and then resets every request looks to them like a host that
// does not answer. The probe tells the cases apart and keeps the
// certificate facts that an HTTP prober loses when the request fails:
//
//	answered    the HTTP request got a response
//	http_reset  the handshake completed (or the plain connection opened),
//	            then the request was reset, closed or left unanswered
//	tls_failed  the connection opened, the TLS handshake failed
//	reset       the connection was reset before it opened
//	refused     the connection was refused (the port is closed)
//	no_answer   nothing answered (filtered, down, or no path)
//	""          the attempt says nothing about the host (a proxy refused
//	            it, the probe was canceled)
//
// The probe dials only the host and port it is given, through the DialFunc
// the caller supplies (the task's egress proxy in a confined run; see
// Dialer), so the caller's scope and rate controls apply. It sends at most
// one HTTP request (HEAD /, Connection: close) and reads at most a response
// head. Every value read from the certificate is the server's choice; the
// CTIS converter bounds it.
//
// Stability: Beta (docs/STABILITY.md).
package tlsprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// Outcomes of a probe (Result.Outcome). The values are the matching
// adapt.GapCause values so a coverage gap can carry them as they are.
const (
	OutcomeAnswered  = adapt.GapCauseAnswered
	OutcomeHTTPReset = adapt.GapCauseHTTPReset
	OutcomeTLSFailed = adapt.GapCauseTLSFailed
	OutcomeRefused   = adapt.GapCauseRefused
	OutcomeNoAnswer  = adapt.GapCauseNoAnswer
	// OutcomeReset: the connection was reset before it opened.
	OutcomeReset = adapt.GapCauseReset
	// OutcomeTLSOK: the handshake completed and no HTTP request was asked
	// (Options.HTTP false).
	OutcomeTLSOK = "tls_ok"
	// OutcomeUnknown: the attempt says nothing about the host.
	OutcomeUnknown = ""
)

// Bounds.
const (
	// DefaultTimeout bounds each step (connect, handshake, response head).
	DefaultTimeout = 8 * time.Second
	// MaxTimeout caps Options.Timeout.
	MaxTimeout = 30 * time.Second
	// maxHeadBytes bounds the response head read.
	maxHeadBytes = 16 << 10
	// maxErrLen bounds Result.Err.
	maxErrLen = 160
)

// insecureSkipTargetVerify: the probe does not verify the target's
// certificate. It exists to read a certificate a browser would refuse
// (expired, another site's names, self-signed); the leaf is recorded and
// judged (CertProblem), nothing it says is trusted, and no credential or
// data is sent over the connection (one HEAD request at most).
const insecureSkipTargetVerify = true

// DialFunc opens a connection (net.Dialer.DialContext's signature).
type DialFunc = reach.DialFunc

// Options tune a probe.
type Options struct {
	// Timeout bounds each step; 0 is DefaultTimeout, at most MaxTimeout.
	Timeout time.Duration
	// HTTP sends one HEAD request after the handshake and reports whether
	// it was answered.
	HTTP bool
	// Plain skips TLS: the HTTP request goes over the plain connection.
	Plain bool
	// UserAgent of the HTTP request ("" is a generic one).
	UserAgent string
	// Now is the clock for the certificate's validity (nil: time.Now).
	Now func() time.Time
}

// Result is what a probe saw.
type Result struct {
	// Outcome is one of the Outcome constants.
	Outcome string
	// Leaf is the certificate the host presented (nil without a
	// completed handshake).
	Leaf *core.TLSLeaf
	// TLSVersion of the handshake ("TLS1.2", "TLS1.3"), "" without one.
	TLSVersion string
	// RemoteAddr is the address the connection reached ("" through a
	// proxy, which hides it, or without a connection).
	RemoteAddr string
	// Status is the HTTP status of an answered request.
	Status int
	// Err is a short reason for an outcome other than answered or tls_ok.
	Err string
}

// CertProblem is the strongest problem of the leaf for a browser, as an
// adapt.GapCert value: expired, not yet valid, a name that does not cover
// the host, self-signed; "" when none (or no leaf).
func (r Result) CertProblem(now time.Time) string { return CertProblem(r.Leaf, now) }

// CertProblem is the strongest problem of leaf (see Result.CertProblem).
func CertProblem(leaf *core.TLSLeaf, now time.Time) string {
	if leaf == nil {
		return ""
	}
	switch {
	case leaf.Expired || (!leaf.NotAfter.IsZero() && now.After(leaf.NotAfter)):
		return adapt.GapCertExpired
	case !leaf.NotBefore.IsZero() && now.Before(leaf.NotBefore):
		return adapt.GapCertNotYetValid
	case leaf.Mismatched:
		return adapt.GapCertNameMismatch
	case leaf.SelfSigned:
		return adapt.GapCertSelfSigned
	}
	return ""
}

// Probe connects to host:port with dial, completes a TLS handshake without
// verifying the certificate (unless o.Plain) and, with o.HTTP, sends one
// HTTP request. host is a name or an address; a name is also the server
// name (SNI) and the name the certificate is checked against.
func Probe(ctx context.Context, dial DialFunc, host string, port int, o Options) Result {
	host = strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), ".")
	if host == "" || port < 1 || port > 65535 || dial == nil {
		return Result{Err: "no host, port or dialer"}
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	timeout = min(timeout, MaxTimeout)
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}

	dctx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dial(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	cancel()
	if err != nil {
		return Result{Outcome: dialOutcome(ctx, err), Err: shortErr(err)}
	}
	defer conn.Close() //nolint:errcheck // probe connection

	res := Result{RemoteAddr: remoteAddr(conn)}
	stream := conn
	if !o.Plain {
		cfg := &tls.Config{
			InsecureSkipVerify: insecureSkipTargetVerify, //nolint:gosec // G402 security-review: allow GO-TLS-NOVERIFY see insecureSkipTargetVerify
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}
		if net.ParseIP(host) == nil {
			cfg.ServerName = host
		}
		tc := tls.Client(conn, cfg)
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			if ctx.Err() != nil {
				return Result{Err: shortErr(err)}
			}
			res.Outcome, res.Err = OutcomeTLSFailed, shortErr(err)
			return res
		}
		st := tc.ConnectionState()
		res.TLSVersion = tlsVersion(st.Version)
		if len(st.PeerCertificates) > 0 {
			res.Leaf = Leaf(st.PeerCertificates[0], host, now())
		}
		stream = tc
	}
	if !o.HTTP {
		res.Outcome = OutcomeTLSOK
		return res
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	status, err := headRequest(stream, host, port, o.Plain, o.UserAgent)
	switch {
	case err == nil:
		res.Outcome, res.Status = OutcomeAnswered, status
	case ctx.Err() != nil:
		res.Outcome, res.Err = OutcomeUnknown, shortErr(err)
	default:
		// The connection opened (and the handshake completed): a reset, a
		// close or silence on the request is the host refusing HTTP.
		res.Outcome, res.Err = OutcomeHTTPReset, shortErr(err)
	}
	return res
}

// dialOutcome maps a failed connect to an outcome. Through a proxy the
// relay's refusal text carries the upstream error ("connection refused",
// "i/o timeout"), which classifies the same way; a refusal that names
// none (the proxy's rules, a backed-off host) says nothing.
func dialOutcome(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return OutcomeUnknown
	}
	var pe *ProxyError
	if errors.As(err, &pe) && (pe.Status == http.StatusServiceUnavailable || pe.Status == http.StatusForbidden) {
		return OutcomeUnknown
	}
	switch reach.Classify(err) {
	case reach.PortClosed:
		return OutcomeRefused
	case reach.Timeout, reach.NoRoute, reach.DNSFailure, reach.FirewallRefused:
		return OutcomeNoAnswer
	case reach.Reached:
		// A connect that failed with a reset: something answered.
		return OutcomeReset
	}
	return OutcomeUnknown
}

// headRequest sends HEAD / and reads the response head.
func headRequest(c net.Conn, host string, port int, plain bool, ua string) (int, error) {
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; openctem-tlsprobe/1)"
	}
	hostHdr := host
	if strings.Contains(host, ":") {
		hostHdr = "[" + host + "]"
	}
	if (plain && port != 80) || (!plain && port != 443) {
		hostHdr += ":" + strconv.Itoa(port)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", hostHdr, sanitizeHeader(ua))
	if _, err := c.Write(b.Bytes()); err != nil {
		return 0, err
	}
	req, _ := http.NewRequest(http.MethodHead, "/", nil)
	resp, err := http.ReadResponse(bufio.NewReaderSize(&limitedReader{r: c, n: maxHeadBytes}, 4096), req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

type limitedReader struct {
	r net.Conn
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("tlsprobe: response head too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// Leaf converts a certificate the host presented for host (a name or an
// address) to core.TLSLeaf: Mismatched when its names do not cover host,
// Expired when now is past NotAfter, SelfSigned when it is signed by its
// own key.
func Leaf(cert *x509.Certificate, host string, now time.Time) *core.TLSLeaf {
	if cert == nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	l := &core.TLSLeaf{
		SubjectCN:         cert.Subject.CommonName,
		SANs:              append([]string(nil), cert.DNSNames...),
		IssuerCN:          cert.Issuer.CommonName,
		SerialNumber:      serialHex(cert),
		NotBefore:         cert.NotBefore.UTC(),
		NotAfter:          cert.NotAfter.UTC(),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		Expired:           now.After(cert.NotAfter),
	}
	for _, ip := range cert.IPAddresses {
		l.SANs = append(l.SANs, ip.String())
	}
	if len(cert.Issuer.Organization) > 0 {
		l.IssuerOrg = cert.Issuer.Organization[0]
	}
	// Signed by its own key (CheckSignatureFrom would also demand a CA).
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
		l.SelfSigned = true
	}
	for _, n := range cert.DNSNames {
		if strings.HasPrefix(n, "*.") {
			l.Wildcard = true
			break
		}
	}
	if host != "" && cert.VerifyHostname(host) != nil {
		l.Mismatched = true
	}
	return l
}

func serialHex(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	return strings.ToUpper(c.SerialNumber.Text(16))
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return ""
}

func remoteAddr(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	if _, ok := c.(*proxiedConn); ok {
		return ""
	}
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	return ""
}

// shortErr is the last colon-separated part of err's text, bounded: the
// reason without addresses or URLs.
func shortErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.LastIndexByte(msg, ':'); i >= 0 && i < len(msg)-1 {
		msg = msg[i+1:]
	}
	msg = strings.TrimSpace(sanitizeHeader(msg))
	if len(msg) > maxErrLen {
		msg = msg[:maxErrLen]
	}
	return msg
}
