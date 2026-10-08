package egress

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxHeaderBytes bounds an HTTP proxy request's header.
const maxHeaderBytes = 64 << 10

// Serve accepts connections on ln until ctx ends or ln is closed, and
// forwards each one. It returns nil when ctx ended.
func (f *Forwarder) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case f.conns <- struct{}{}:
		default:
			_ = c.Close() // over MaxConns
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-f.conns }()
			f.ServeConn(ctx, c)
		}()
	}
}

// ServeConn forwards one client connection: SOCKS5 when its first byte is
// 5, else an HTTP proxy request. It closes c.
func (f *Forwarder) ServeConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(f.limits.HandshakeTimeout))
	// The handshake (a SOCKS5 greeting and request, or an HTTP request
	// header) is bounded; lift() removes the bound once it is read.
	lr := &io.LimitedReader{R: c, N: maxHeaderBytes}
	br := bufio.NewReaderSize(lr, 4096)
	lift := func() {
		lr.N = math.MaxInt64
		_ = c.SetReadDeadline(time.Time{})
	}
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		f.serveSOCKS5(ctx, c, br, lift)
		return
	}
	f.serveHTTP(ctx, c, br, lift)
}

func (f *Forwarder) serveHTTP(ctx context.Context, c net.Conn, br *bufio.Reader, lift func()) {
	req, err := http.ReadRequest(br)
	if err != nil {
		writeHTTPError(c, http.StatusBadRequest, "malformed proxy request")
		return
	}
	if req.Method == http.MethodConnect {
		host, portStr, err := net.SplitHostPort(req.Host)
		port, perr := strconv.Atoi(portStr)
		if err != nil || perr != nil {
			writeHTTPError(c, http.StatusBadRequest, "CONNECT needs host:port")
			return
		}
		up, rec, err := f.dial(ctx, "connect", host, port)
		if err != nil {
			writeHTTPError(c, statusOf(err), err.Error())
			return
		}
		lift()
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			_ = up.Close()
			f.record(*rec)
			return
		}
		f.pipe(c, br, up, rec)
		return
	}
	if req.URL == nil || req.URL.Host == "" || !strings.EqualFold(req.URL.Scheme, "http") {
		writeHTTPError(c, http.StatusBadRequest, "only CONNECT and absolute http:// requests are proxied")
		return
	}
	port := 80
	if p := req.URL.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			writeHTTPError(c, http.StatusBadRequest, "bad port")
			return
		}
	}
	host := req.URL.Hostname()
	up, rec, err := f.dial(ctx, "http", host, port)
	if err != nil {
		writeHTTPError(c, statusOf(err), err.Error())
		return
	}
	lift()
	// One request per proxied connection: the next one may name another
	// host and must be checked again.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Close = true
	out := &countWriter{w: up}
	if err := req.Write(out); err != nil {
		_ = up.Close()
		rec.BytesOut = out.n.Load()
		f.record(*rec)
		writeHTTPError(c, http.StatusBadGateway, "upstream write failed")
		return
	}
	in, _ := io.Copy(c, up)
	_ = up.Close()
	rec.BytesOut, rec.BytesIn = out.n.Load(), in
	f.record(*rec)
}

func statusOf(err error) int {
	if errors.Is(err, ErrRefused) {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

func writeHTTPError(c net.Conn, status int, msg string) {
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > 256 {
		msg = msg[:256]
	}
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
		status, http.StatusText(status), len(msg), msg)
}

// SOCKS5 (RFC 1928), CONNECT only, no authentication.
const (
	socksVersion   = 0x05
	socksConnect   = 0x01
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04
	repSucceeded   = 0x00
	repNotAllowed  = 0x02
	repUnreachable = 0x04
	repCmdUnsupp   = 0x07
	repAtypUnsupp  = 0x08
)

func (f *Forwarder) serveSOCKS5(ctx context.Context, c net.Conn, br *bufio.Reader, lift func()) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != socksVersion || hdr[1] == 0 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if !containsByte(methods, 0x00) {
		_, _ = c.Write([]byte{socksVersion, 0xff})
		return
	}
	if _, err := c.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != socksVersion {
		return
	}
	var host string
	switch req[3] {
	case atypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case atypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case atypDomain:
		n, err := br.ReadByte()
		if err != nil || n == 0 {
			return
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	default:
		socksReply(c, repAtypUnsupp)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb[:]))
	if req[1] != socksConnect {
		socksReply(c, repCmdUnsupp)
		return
	}
	up, rec, err := f.dial(ctx, "socks5", host, port)
	if err != nil {
		if errors.Is(err, ErrRefused) {
			socksReply(c, repNotAllowed)
		} else {
			socksReply(c, repUnreachable)
		}
		return
	}
	lift()
	socksReply(c, repSucceeded)
	f.pipe(c, br, up, rec)
}

func socksReply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// pipe copies both ways until either side ends, then records the bytes.
// br holds what the client sent after its request.
func (f *Forwarder) pipe(c net.Conn, br *bufio.Reader, up net.Conn, rec *Record) {
	var out, in int64
	done := make(chan struct{})
	go func() {
		out, _ = io.Copy(up, br)
		closeWrite(up)
		close(done)
	}()
	in, _ = io.Copy(c, up)
	closeWrite(c)
	<-done
	_ = up.Close()
	rec.BytesOut, rec.BytesIn = out, in
	f.record(*rec)
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

type countWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}
