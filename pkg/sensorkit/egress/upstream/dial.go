package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// maxReplyHeader bounds an HTTP CONNECT reply's status line and headers.
const maxReplyHeader = 8 << 10

// attemptError is the outcome of one tunnel attempt through one endpoint.
type attemptError struct {
	class string
	err   error
	// replyTimeout: the proxy took the request and sent no CONNECT reply
	// in time. The pool decides whether that is the target or the proxy
	// (Pool.observe).
	replyTimeout bool
}

func (e *attemptError) Error() string { return e.class + ": " + e.err.Error() }
func (e *attemptError) Unwrap() error { return e.err }

func failed(class string, format string, args ...any) *attemptError {
	return &attemptError{class: class, err: fmt.Errorf(format, args...)}
}

// replyTimedOut is the error of a CONNECT that got no reply in time: about
// the target at first (a proxy that is up waits on a target that does not
// answer), about the proxy once it never carried a tunnel in the job
// (Pool.observe).
func replyTimedOut(e *Endpoint, err error) *attemptError {
	return &attemptError{class: egress.ClassTargetUnreachable, replyTimeout: true,
		err: fmt.Errorf("%s: no CONNECT reply in time: %w", e, err)}
}

// tunnel opens a tunnel to target through e. Every error is an
// *attemptError. The handshake is bounded by ctx: its deadline is the
// connection's deadline until the tunnel is up, and the end of ctx ends it.
func (p *Pool) tunnel(ctx context.Context, e *Endpoint, target netip.AddrPort) (net.Conn, error) {
	raw, err := p.dialEndpoint(ctx, e)
	if err != nil {
		return nil, err
	}
	stop := bindDeadline(ctx, raw)
	conn, err := p.handshake(ctx, raw, e, target)
	live := stop()
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if !live {
		// ctx ended as the handshake finished: the deadline was moved to
		// the past, so the tunnel is unusable.
		_ = raw.Close()
		return nil, failed(egress.ClassProxyDown, "%s: %w", e, context.Cause(ctx))
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// bindDeadline makes ctx's deadline the connection's and cancels the
// connection's I/O when ctx ends. stop undoes the binding and reports
// whether ctx was still live.
func bindDeadline(ctx context.Context, c net.Conn) (stop func() bool) {
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	after := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	return after
}

// dialEndpoint opens TCP (and TLS for an https endpoint) to the endpoint.
// A host name is resolved now; every address it resolves to must pass
// Denied, and the dial goes to the addresses checked (never resolved again).
func (p *Pool) dialEndpoint(ctx context.Context, e *Endpoint) (net.Conn, error) {
	addrs, err := p.endpointAddrs(ctx, e)
	if err != nil {
		return nil, err
	}
	var lastErr error
	var c net.Conn
	for _, a := range addrs {
		c, err = p.opts.dialer(ctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(e.Port)))
		if err == nil {
			break
		}
		lastErr = err
	}
	if c == nil {
		return nil, failed(egress.ClassProxyDown, "%s: %w", e, lastErr)
	}
	if e.Scheme != SchemeHTTPS {
		return c, nil
	}
	tc := tls.Client(c, &tls.Config{
		ServerName: e.Host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    p.opts.RootCAs, // nil: the system roots
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, failed(egress.ClassProxyDown, "%s: tls: %w", e, err)
	}
	return tc, nil
}

func (p *Pool) endpointAddrs(ctx context.Context, e *Endpoint) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(e.Host); err == nil {
		if Denied(a) {
			return nil, failed(egress.ClassProxyDown, "%s: address not allowed", e)
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := p.opts.lookup(ctx, e.Host)
	if err != nil {
		return nil, failed(egress.ClassProxyDown, "%s: resolve: %w", e, err)
	}
	if len(addrs) == 0 {
		return nil, failed(egress.ClassProxyDown, "%s: resolves to no address", e)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if Denied(a) {
			return nil, failed(egress.ClassProxyDown, "%s: resolves to %s, an address not allowed for a proxy", e, a.Unmap())
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

func (p *Pool) handshake(ctx context.Context, c net.Conn, e *Endpoint, target netip.AddrPort) (net.Conn, error) {
	switch e.Scheme {
	case SchemeHTTP, SchemeHTTPS:
		return httpConnect(c, e, target)
	default:
		return socks5Connect(c, e, target)
	}
}

// httpConnect sends CONNECT ip:port and reads the reply. Bytes the proxy
// sent after the reply stay buffered in the returned connection.
func httpConnect(c net.Conn, e *Endpoint, target netip.AddrPort) (net.Conn, error) {
	hp := target.String()
	var req bytes.Buffer
	req.WriteString("CONNECT " + hp + " HTTP/1.1\r\nHost: " + hp + "\r\n")
	if e.Username != "" || e.Password != "" {
		req.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(e.Username+":"+e.Password)) + "\r\n")
	}
	req.WriteString("\r\n")
	if _, err := c.Write(req.Bytes()); err != nil {
		return nil, failed(egress.ClassProxyDown, "%s: write CONNECT: %w", e, err)
	}
	br := bufio.NewReaderSize(c, 4096)
	code, err := readConnectReply(br)
	if err != nil {
		if isTimeout(err) {
			// The proxy accepted the connection and the request: it is
			// waiting on the target, or it hangs.
			return nil, replyTimedOut(e, err)
		}
		return nil, failed(egress.ClassProxyDown, "%s: %w", e, err)
	}
	switch {
	case code >= 200 && code < 300:
		return wrap(c, br, e.ID), nil
	case code == 407:
		return nil, failed(egress.ClassProxyAuth, "%s: proxy answered 407", e)
	case code == 502 || code == 503 || code == 504:
		return nil, failed(egress.ClassTargetUnreachable, "%s: proxy answered %d to CONNECT %s", e, code, hp)
	case code >= 400 && code < 500:
		return nil, failed(egress.ClassTargetRefused, "%s: proxy answered %d to CONNECT %s", e, code, hp)
	default:
		return nil, failed(egress.ClassProxyDown, "%s: proxy answered %d to CONNECT", e, code)
	}
}

var errBadReply = errors.New("malformed proxy reply")

// readConnectReply reads an HTTP CONNECT reply's status line and headers
// (at most maxReplyHeader bytes) and returns the status code.
func readConnectReply(br *bufio.Reader) (int, error) {
	total := 0
	code := 0
	for first := true; ; first = false {
		line, err := readLine(br, maxReplyHeader-total)
		if err != nil {
			return 0, err
		}
		total += len(line)
		if first {
			// HTTP/1.x SP 3DIGIT [SP reason]
			if len(line) < 12 || !bytes.HasPrefix(line, []byte("HTTP/1.")) || line[8] != ' ' {
				return 0, errBadReply
			}
			n, err := strconv.Atoi(string(line[9:12]))
			if err != nil || n < 100 || n > 599 || (len(line) > 12 && line[12] != ' ' && line[12] != '\r' && line[12] != '\n') {
				return 0, errBadReply
			}
			code = n
			continue
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			return code, nil
		}
	}
}

// readLine reads one line ending in \n, of at most limit bytes.
func readLine(br *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		if limit <= 0 {
			return nil, fmt.Errorf("%w: header over %d bytes", errBadReply, maxReplyHeader)
		}
		b, err := br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%w: connection closed", errBadReply)
			}
			return nil, err
		}
		line = append(line, b)
		limit--
		if b == '\n' {
			return line, nil
		}
	}
}

// SOCKS5 (RFC 1928, RFC 1929).
const (
	socksVer         = 0x05
	socksNoAuth      = 0x00
	socksUserPass    = 0x02
	socksNoMethod    = 0xff
	socksCmdConnect  = 0x01
	socksAtypIPv4    = 0x01
	socksAtypName    = 0x03
	socksAtypIPv6    = 0x04
	socksAuthVersion = 0x01
)

func socks5Connect(c net.Conn, e *Endpoint, target netip.AddrPort) (net.Conn, error) {
	creds := e.Username != "" || e.Password != ""
	greet := []byte{socksVer, 1, socksNoAuth}
	if creds {
		greet = []byte{socksVer, 1, socksUserPass}
	}
	if _, err := c.Write(greet); err != nil {
		return nil, failed(egress.ClassProxyDown, "%s: write greeting: %w", e, err)
	}
	br := bufio.NewReaderSize(c, 512)
	var sel [2]byte
	if _, err := io.ReadFull(br, sel[:]); err != nil {
		return nil, failed(egress.ClassProxyDown, "%s: read method: %w", e, err)
	}
	switch {
	case sel[0] != socksVer:
		return nil, failed(egress.ClassProxyDown, "%s: not a SOCKS5 proxy", e)
	case sel[1] == socksNoMethod:
		return nil, failed(egress.ClassProxyAuth, "%s: proxy accepts none of our authentication methods", e)
	case sel[1] == socksUserPass && creds:
		ul, pl := len(e.Username), len(e.Password)
		if ul > maxCredential || pl > maxCredential {
			return nil, failed(egress.ClassProxyAuth, "%s: credentials too long for SOCKS5", e)
		}
		auth := make([]byte, 0, 3+ul+pl)
		auth = append(auth, socksAuthVersion, uint8(ul&0xff)) //nolint:gosec // bounded to 255 above
		auth = append(auth, e.Username...)
		auth = append(auth, uint8(pl&0xff)) //nolint:gosec // bounded to 255 above
		auth = append(auth, e.Password...)
		if _, err := c.Write(auth); err != nil {
			return nil, failed(egress.ClassProxyDown, "%s: write authentication: %w", e, err)
		}
		var st [2]byte
		if _, err := io.ReadFull(br, st[:]); err != nil {
			return nil, failed(egress.ClassProxyDown, "%s: read authentication status: %w", e, err)
		}
		if st[0] != socksAuthVersion {
			return nil, failed(egress.ClassProxyDown, "%s: malformed authentication status", e)
		}
		if st[1] != 0x00 {
			return nil, failed(egress.ClassProxyAuth, "%s: proxy refused the credentials", e)
		}
	case sel[1] == socksNoAuth && !creds:
	default:
		return nil, failed(egress.ClassProxyDown, "%s: proxy chose a method we did not offer", e)
	}
	req := []byte{socksVer, socksCmdConnect, 0x00}
	a := target.Addr().Unmap()
	if a.Is4() {
		b := a.As4()
		req = append(append(req, socksAtypIPv4), b[:]...)
	} else {
		b := a.As16()
		req = append(append(req, socksAtypIPv6), b[:]...)
	}
	req = binary.BigEndian.AppendUint16(req, target.Port())
	if _, err := c.Write(req); err != nil {
		return nil, failed(egress.ClassProxyDown, "%s: write CONNECT: %w", e, err)
	}
	rep, err := readSOCKSReply(br)
	if err != nil {
		if isTimeout(err) {
			return nil, replyTimedOut(e, err)
		}
		return nil, failed(egress.ClassProxyDown, "%s: %w", e, err)
	}
	switch rep {
	case 0x00:
		return wrap(c, br, e.ID), nil
	case 0x02:
		return nil, failed(egress.ClassTargetRefused, "%s: proxy ruleset refused CONNECT %s", e, target)
	case 0x01, 0x03, 0x04, 0x05, 0x06:
		// 0x01 (general failure) is what many proxies answer when the
		// target does not answer: about the target, not the proxy.
		return nil, failed(egress.ClassTargetUnreachable, "%s: proxy reply %d to CONNECT %s", e, rep, target)
	default:
		return nil, failed(egress.ClassProxyDown, "%s: proxy reply %d to CONNECT", e, rep)
	}
}

// readSOCKSReply reads a SOCKS5 CONNECT reply to its end (the bound
// address included) and returns the reply code.
func readSOCKSReply(br *bufio.Reader) (byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return 0, fmt.Errorf("read CONNECT reply: %w", err)
	}
	if h[0] != socksVer {
		return 0, errBadReply
	}
	var n int
	switch h[3] {
	case socksAtypIPv4:
		n = 4
	case socksAtypIPv6:
		n = 16
	case socksAtypName:
		l, err := br.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("read CONNECT reply: %w", err)
		}
		n = int(l)
	default:
		return 0, errBadReply
	}
	if _, err := io.CopyN(io.Discard, br, int64(n)+2); err != nil {
		return 0, fmt.Errorf("read CONNECT reply: %w", err)
	}
	return h[1], nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// conn is a tunnel through an endpoint: reads drain what the handshake
// buffered first.
type conn struct {
	net.Conn
	r        io.Reader
	endpoint string
}

func wrap(c net.Conn, br *bufio.Reader, endpoint string) net.Conn {
	w := &conn{Conn: c, r: c, endpoint: endpoint}
	if n := br.Buffered(); n > 0 {
		buf, _ := br.Peek(n)
		w.r = io.MultiReader(bytes.NewReader(bytes.Clone(buf)), c)
	}
	return w
}

func (c *conn) Read(b []byte) (int, error) { return c.r.Read(b) }

// UpstreamEndpoint is the endpoint id (egress.EndpointConn).
func (c *conn) UpstreamEndpoint() string { return c.endpoint }

// CloseWrite half-closes a TCP tunnel. Over TLS to the proxy it does
// nothing: a close_notify would end the whole tunnel at most proxies.
func (c *conn) CloseWrite() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

var _ egress.EndpointConn = (*conn)(nil)
