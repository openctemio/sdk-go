package tlsprobe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// certFor makes a self-signed certificate for names, valid in [from, to).
func certFor(t *testing.T, cn string, names []string, from, to time.Time) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    from,
		NotAfter:     to,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type serverMode int

const (
	modeReset   serverMode = iota // handshake, then reset on the request
	modeAnswer                    // handshake, then an HTTP answer
	modeNoTLS                     // close at once (handshake fails)
	modePlainOK                   // plain HTTP answer
)

// serve runs a listener in mode and returns its port.
func serve(t *testing.T, mode serverMode, cert tls.Certificate) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				switch mode {
				case modeNoTLS:
					return
				case modePlainOK:
					_, _ = bufio.NewReader(c).ReadString('\n')
					_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
					return
				}
				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				br := bufio.NewReader(tc)
				if _, err := br.ReadString('\n'); err != nil {
					return
				}
				if mode == modeReset {
					_ = c.(*net.TCPConn).SetLinger(0)
					return
				}
				_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

var direct = (&net.Dialer{Timeout: 2 * time.Second}).DialContext

func TestProbeClassifiesEachCase(t *testing.T) {
	now := time.Now()
	expiredForeign := certFor(t, "ssl.default.pagebuilder.test", []string{"ssl.default.pagebuilder.test"},
		now.Add(-800*24*time.Hour), now.Add(-400*24*time.Hour))
	valid := certFor(t, "localhost", []string{"localhost"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	cases := []struct {
		name     string
		mode     serverMode
		cert     tls.Certificate
		plain    bool
		outcome  string
		problem  string
		wantLeaf bool
	}{
		{"handshake ok, request reset, foreign expired certificate", modeReset, expiredForeign, false, OutcomeHTTPReset, adapt.GapCertExpired, true},
		{"handshake ok, answered, self-signed certificate", modeAnswer, valid, false, OutcomeAnswered, adapt.GapCertSelfSigned, true},
		{"connection opens, handshake fails", modeNoTLS, valid, false, OutcomeTLSFailed, "", false},
		{"plain http answered", modePlainOK, valid, true, OutcomeAnswered, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := serve(t, tc.mode, tc.cert)
			r := Probe(context.Background(), direct, "localhost", port, Options{HTTP: true, Plain: tc.plain, Timeout: 3 * time.Second})
			if r.Outcome != tc.outcome {
				t.Fatalf("outcome %q (err %q), want %q", r.Outcome, r.Err, tc.outcome)
			}
			if (r.Leaf != nil) != tc.wantLeaf {
				t.Fatalf("leaf %+v, want leaf %v", r.Leaf, tc.wantLeaf)
			}
			if got := r.CertProblem(now); got != tc.problem {
				t.Fatalf("cert problem %q, want %q", got, tc.problem)
			}
		})
	}
}

func TestProbeKeepsTheCertificateFactsWhenHTTPFails(t *testing.T) {
	now := time.Now()
	port := serve(t, modeReset, certFor(t, "ssl.default.pagebuilder.test", []string{"ssl.default.pagebuilder.test"},
		now.Add(-800*24*time.Hour), now.Add(-400*24*time.Hour)))
	r := Probe(context.Background(), direct, "localhost", port, Options{HTTP: true, Timeout: 3 * time.Second})
	l := r.Leaf
	if l == nil {
		t.Fatal("no leaf")
	}
	if !l.Expired || !l.Mismatched || !l.SelfSigned || l.SubjectCN != "ssl.default.pagebuilder.test" {
		t.Fatalf("leaf facts: %+v", l)
	}
	if len(l.FingerprintSHA256) != 64 || l.SerialNumber != "1092" || r.TLSVersion == "" {
		t.Fatalf("leaf identity: fp %q serial %q version %q", l.FingerprintSHA256, l.SerialNumber, r.TLSVersion)
	}
	if r.RemoteAddr != "127.0.0.1" {
		t.Fatalf("remote addr %q", r.RemoteAddr)
	}
}

func TestProbeWithoutHTTPStopsAfterTheHandshake(t *testing.T) {
	port := serve(t, modeReset, certFor(t, "localhost", []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	r := Probe(context.Background(), direct, "localhost", port, Options{Timeout: 3 * time.Second})
	if r.Outcome != OutcomeTLSOK || r.Leaf == nil || r.Leaf.Mismatched {
		t.Fatalf("got %+v", r)
	}
}

func TestProbeConnectFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listens: refused

	if r := Probe(context.Background(), direct, "127.0.0.1", port, Options{HTTP: true}); r.Outcome != OutcomeRefused {
		t.Fatalf("closed port: %+v", r)
	}
	timeout := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}
	if r := Probe(context.Background(), timeout, "192.0.2.1", 443, Options{HTTP: true}); r.Outcome != OutcomeNoAnswer {
		t.Fatalf("timeout: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := func(ctx context.Context, _, _ string) (net.Conn, error) { return nil, ctx.Err() }
	if r := Probe(ctx, canceled, "192.0.2.1", 443, Options{HTTP: true}); r.Outcome != OutcomeUnknown {
		t.Fatalf("canceled: %+v", r)
	}
	if r := Probe(context.Background(), direct, "", 443, Options{}); r.Outcome != OutcomeUnknown {
		t.Fatalf("no host: %+v", r)
	}
}

// connectProxy is a minimal CONNECT proxy: it tunnels to the asked address,
// or answers refuse (status and body) when set.
func connectProxy(t *testing.T, refuse int, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if refuse != 0 {
					_, _ = io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(refuse)+" No\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestProbeThroughTheTaskProxy(t *testing.T) {
	now := time.Now()
	port := serve(t, modeReset, certFor(t, "localhost", []string{"localhost"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour)))
	dial, err := Dialer(connectProxy(t, 0, ""))
	if err != nil {
		t.Fatal(err)
	}
	r := Probe(context.Background(), dial, "localhost", port, Options{HTTP: true, Timeout: 3 * time.Second})
	if r.Outcome != OutcomeHTTPReset || r.CertProblem(now) != adapt.GapCertExpired {
		t.Fatalf("through the proxy: %+v", r)
	}
	if r.RemoteAddr != "" {
		t.Fatalf("a proxied probe does not know the address, got %q", r.RemoteAddr)
	}

	refusals := []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusBadGateway, "dial tcp 192.0.2.7:443: connect: connection refused", OutcomeRefused},
		{http.StatusBadGateway, "dial tcp 192.0.2.7:443: i/o timeout", OutcomeNoAnswer},
		{http.StatusForbidden, "refused by the local policy", OutcomeUnknown},
		{http.StatusServiceUnavailable, "adapt: host is backed off", OutcomeUnknown},
	}
	for _, rf := range refusals {
		dial, err := Dialer(connectProxy(t, rf.status, rf.body))
		if err != nil {
			t.Fatal(err)
		}
		r := Probe(context.Background(), dial, "localhost", 443, Options{HTTP: true, Timeout: 3 * time.Second})
		if r.Outcome != rf.want {
			t.Fatalf("%d %q: outcome %q, want %q", rf.status, rf.body, r.Outcome, rf.want)
		}
		var pe *ProxyError
		_, err = dial(context.Background(), "tcp", "localhost:443")
		if !errors.As(err, &pe) || pe.Status != rf.status {
			t.Fatalf("proxy error: %v", err)
		}
	}
}

func TestDialerRefusesUnknownSchemes(t *testing.T) {
	for _, p := range []string{"ftp://127.0.0.1:21", "://", "https://127.0.0.1:3128"} {
		if _, err := Dialer(p); err == nil {
			t.Fatalf("%q accepted", p)
		}
	}
	for _, p := range []string{"", "http://127.0.0.1:1080", "socks5://127.0.0.1:1080", "socks5h://u:p@127.0.0.1:1080"} {
		if _, err := Dialer(p); err != nil {
			t.Fatalf("%q: %v", p, err)
		}
	}
}

func TestLeafAndCertProblem(t *testing.T) {
	now := time.Now()
	parse := func(c tls.Certificate) *x509.Certificate {
		x, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	wild := parse(certFor(t, "example.test", []string{"*.example.test", "example.test"}, now.Add(-time.Hour), now.Add(10*24*time.Hour)))
	l := Leaf(wild, "www.example.test", now)
	if !l.Wildcard || l.Mismatched || l.Expired || !l.SelfSigned {
		t.Fatalf("wildcard leaf: %+v", l)
	}
	if got := CertProblem(l, now); got != adapt.GapCertSelfSigned {
		t.Fatalf("self-signed problem %q", got)
	}
	if !Leaf(wild, "other.test", now).Mismatched {
		t.Fatal("a name the certificate does not cover is a mismatch")
	}
	future := parse(certFor(t, "example.test", []string{"example.test"}, now.Add(time.Hour), now.Add(48*time.Hour)))
	if got := CertProblem(Leaf(future, "example.test", now), now); got != adapt.GapCertNotYetValid {
		t.Fatalf("not yet valid: %q", got)
	}
	l = Leaf(wild, "www.example.test", now)
	l.SelfSigned = false
	if got := CertProblem(l, now); got != "" {
		t.Fatalf("a good leaf has no problem, got %q", got)
	}
	if CertProblem(nil, now) != "" || Leaf(nil, "x", now) != nil {
		t.Fatal("nil leaf")
	}
	expired := Leaf(wild, "other.test", now.Add(30*24*time.Hour))
	if got := CertProblem(expired, now.Add(30*24*time.Hour)); got != adapt.GapCertExpired {
		t.Fatalf("expired wins over a mismatch, got %q", got)
	}
}
