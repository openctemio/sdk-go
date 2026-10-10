package egress

// Scope limits (scopelimit, from the job's signed statement): a limited
// host is reached only on its allowed ports, and on a port whose limits
// name path prefixes every HTTP request is read and checked before it goes
// upstream. TLS to such a port is terminated here with a per-forwarder
// certificate authority and opened again to the target, so the check sees
// the request a server sees; anything that is not HTTP/1.x fails there.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
)

// ProtocolHTTPPath is the Record protocol of an HTTP request the path
// guard read (allowed requests are not recorded one by one; refusals are).
const ProtocolHTTPPath = "http-path"

// maxLeafCerts bounds the per-host certificates a forwarder keeps.
const maxLeafCerts = 256

// limitHosts are the limited hosts whose limits apply to a connection to
// host (a name, or an address): the name itself, or for an address every
// limited name pinned to it and the address when it is limited itself.
// nil: the destination is not limited. An address that carries limits is
// limited whatever else resolves to it (the narrower reading).
func (f *Forwarder) limitHosts(host string) []string {
	if f.scopeLimits.Empty() {
		return nil
	}
	h := normName(strings.Trim(host, "[]"))
	if a, err := netip.ParseAddr(h); err == nil {
		return f.addrLimits[a.Unmap()]
	}
	if f.scopeLimits.Limited(h) {
		return []string{h}
	}
	return nil
}

// limitPortAllowed reports whether a connection to host:port is within the
// limits.
func (f *Forwarder) limitPortAllowed(host string, port int) bool {
	hosts := f.limitHosts(host)
	return len(hosts) == 0 || slices.ContainsFunc(hosts, func(h string) bool { return f.scopeLimits.AllowsPort(h, port) })
}

// indexLimits maps every limited name's pinned addresses, and every
// limited address, to the limited hosts they serve.
func (f *Forwarder) indexLimits() {
	f.addrLimits = map[netip.Addr][]string{}
	for _, h := range f.scopeLimits.Hosts() {
		if a, err := netip.ParseAddr(h); err == nil {
			f.addrLimits[a.Unmap()] = append(f.addrLimits[a.Unmap()], h)
			continue
		}
		for _, a := range f.names[h] {
			f.addrLimits[a.Unmap()] = append(f.addrLimits[a.Unmap()], h)
		}
	}
}

// guard is the path check of one connection to a limited port.
type guard struct {
	f    *Forwarder
	host string // as dialed (a name, or an address)
	port int
	// hosts are the limited hosts behind the destination (limitHosts).
	hosts []string
}

// guardFor returns the path guard of a connection to host:port, or nil
// when no limit of the destination names a path for that port.
func (f *Forwarder) guardFor(host string, port int) *guard {
	hosts := f.limitHosts(host)
	for _, h := range hosts {
		if _, guarded := f.scopeLimits.PathPrefixes(h, port); guarded {
			return &guard{f: f, host: normName(strings.Trim(host, "[]")), port: port, hosts: hosts}
		}
	}
	return nil
}

// allowsName reports whether a request (its Host, or a TLS server name)
// may name name on this connection: the host dialed, or a limited host
// behind the dialed address.
func (g *guard) allowsName(name string) bool {
	name = normName(strings.Trim(name, "[]"))
	return name != "" && (name == g.host || slices.Contains(g.hosts, name))
}

// check decides one request: its Host must name the destination, and its
// path must be under the prefixes that host's limits give this port.
func (g *guard) check(req *http.Request) error {
	if req.URL == nil || req.URL.Opaque != "" || req.Method == http.MethodConnect {
		return fmt.Errorf("%w: not an origin-form request", scopelimit.ErrOutside)
	}
	if req.Header.Get("Upgrade") != "" {
		return fmt.Errorf("%w: protocol upgrade", scopelimit.ErrOutside)
	}
	host := req.Host
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err != nil || n != g.port {
			return fmt.Errorf("%w: Host names port %s, the connection is to %d", scopelimit.ErrOutside, p, g.port)
		}
		host = h
	}
	if !g.allowsName(host) {
		return fmt.Errorf("%w: Host %q is not the destination", scopelimit.ErrOutside, clipString(host, 128))
	}
	name := normName(strings.Trim(host, "[]"))
	if !g.f.scopeLimits.Limited(name) {
		// A request by address to a name's address: only the address's
		// own limits could allow it, and it has none.
		return fmt.Errorf("%w: requests to %s must name the limited host", scopelimit.ErrOutside, clipString(name, 128))
	}
	prefixes, guarded := g.f.scopeLimits.PathPrefixes(name, g.port)
	if !guarded {
		if !g.f.scopeLimits.AllowsPort(name, g.port) {
			return fmt.Errorf("%w: port %d of %s", scopelimit.ErrOutside, g.port, name)
		}
		return nil
	}
	return scopelimit.PathAllowed(req.URL.EscapedPath(), prefixes)
}

// refuse records a refused request.
func (g *guard) refuse(host string, err error) {
	g.f.record(Record{Time: time.Now().UTC(), Protocol: ProtocolHTTPPath, Host: clipString(host, 256), Port: g.port,
		Verdict: Refused, Reason: err.Error()})
}

// bufConn reads what a bufio.Reader already buffered before the conn.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveGuarded serves the tunnel client<->up of a guarded connection: TLS
// is terminated when the client starts it, then every request is checked.
func (f *Forwarder) serveGuarded(ctx context.Context, c net.Conn, br *bufio.Reader, up net.Conn, g *guard, rec *Record) {
	var out, in int64
	// The forwarder stopping ends the connection, as does a client idle
	// between requests for longer than the handshake timeout.
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); _ = up.Close() })
	defer stop()
	defer func() {
		_ = up.Close()
		rec.BytesOut, rec.BytesIn = out, in
		f.record(*rec)
	}()
	_ = c.SetReadDeadline(time.Now().Add(f.limits.HandshakeTimeout))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	client, upstream := net.Conn(&bufConn{Conn: c, r: br}), up
	if first[0] == 0x16 { // a TLS handshake record
		var sni string
		srv := tls.Server(client, &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni = hello.ServerName
				if sni != "" && !g.allowsName(sni) {
					return nil, fmt.Errorf("server name %q is not the destination", clipString(sni, 128))
				}
				name := sni
				if name == "" {
					name = g.host
				}
				return f.leafCert(name)
			},
		})
		if err := srv.Handshake(); err != nil {
			g.refuse(g.host, fmt.Errorf("%w: TLS: %v", scopelimit.ErrOutside, err))
			return
		}
		serverName := sni
		if serverName == "" {
			if _, err := netip.ParseAddr(g.host); err != nil {
				serverName = g.host
			}
		}
		// The tool chose not to verify the target (scanners do not); the
		// target's certificate is not checked here either.
		upTLS := tls.Client(up, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, //nolint:gosec // scanner semantics, see above
			NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS10})
		if err := upTLS.Handshake(); err != nil {
			return
		}
		client, upstream = srv, upTLS
	}
	_ = c.SetReadDeadline(time.Time{})
	lr := &io.LimitedReader{R: client, N: maxHeaderBytes}
	cbr := bufio.NewReader(lr)
	ubr := bufio.NewReader(upstream)
	cw, uw := &countWriter{w: client}, &countWriter{w: upstream}
	defer func() { out, in = uw.n.Load(), cw.n.Load() }()
	for {
		lr.N = maxHeaderBytes
		_ = c.SetReadDeadline(time.Now().Add(f.limits.HandshakeTimeout))
		req, err := http.ReadRequest(cbr)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		lr.N = math.MaxInt64
		if err := g.check(req); err != nil {
			g.refuse(req.Host, err)
			writeRefusal(cw, err)
			return
		}
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		if err := req.Write(uw); err != nil {
			return
		}
		resp, err := http.ReadResponse(ubr, req)
		for err == nil && resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			if werr := resp.Write(cw); werr != nil {
				return
			}
			resp, err = http.ReadResponse(ubr, req)
		}
		if err != nil {
			return
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			_ = resp.Body.Close()
			return
		}
		werr := resp.Write(cw)
		_ = resp.Body.Close()
		if werr != nil || resp.Close || req.Close {
			return
		}
	}
}

// writeRefusal answers a refused request (the connection then closes).
func writeRefusal(w io.Writer, err error) {
	msg := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	msg = clipString(msg, 256)
	_, _ = fmt.Fprintf(w, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Openctem-Egress: refused\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
		len(msg), msg)
}

// tlsAuthority is a forwarder's own certificate authority: created on the
// first terminated connection, valid for a day, never written to disk.
type tlsAuthority struct {
	once  sync.Once
	err   error
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	pem   []byte
	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func (a *tlsAuthority) init() error {
	a.once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			a.err = err
			return
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: "openctem task egress (ephemeral)"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			a.err = err
			return
		}
		a.cert, _ = x509.ParseCertificate(der)
		a.key = key
		a.pem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		a.leafs = map[string]*tls.Certificate{}
	})
	return a.err
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

// leafCert is the certificate the forwarder presents for name.
func (f *Forwarder) leafCert(name string) (*tls.Certificate, error) {
	a := &f.authority
	if err := a.init(); err != nil {
		return nil, err
	}
	name = normName(name)
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leafs[name]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: a.cert.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		tmpl.IPAddresses = []net.IP{ip.AsSlice()}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key}
	if len(a.leafs) < maxLeafCerts {
		a.leafs[name] = c
	}
	return c, nil
}

// AuthorityPEM is the forwarder's certificate authority (PEM), the issuer
// of the certificates it presents on terminated connections, for a tool
// that verifies TLS; nil before the first terminated connection or on an
// error. Always non-nil after CreateAuthority.
func (f *Forwarder) AuthorityPEM() []byte {
	if f.authority.pem == nil {
		return nil
	}
	return append([]byte(nil), f.authority.pem...)
}

// CreateAuthority creates the forwarder's certificate authority now (it is
// otherwise created on the first terminated connection), so AuthorityPEM
// can be handed to a tool before it starts. A forwarder without path
// limits does not need one.
func (f *Forwarder) CreateAuthority() error { return f.authority.init() }

func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
