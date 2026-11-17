package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
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
	// The forwarder stopping ends every connection it serves, at once: a
	// handler blocked on either side returns, so Serve's wait (and the
	// task waiting on the forwarder) ends.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
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
		if g := f.guardFor(host, port); g != nil {
			f.serveGuarded(ctx, c, br, up, g, rec)
			return
		}
		f.pipe(ctx, c, br, up, rec)
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
	if f.isOOB(host, port) {
		// The task's interaction server: its own checks, never the web
		// scope or the target limits (oob.go).
		f.serveOOB(ctx, c, req, lift)
		return
	}
	if g := f.guardFor(host, port); g != nil {
		if err := g.check(req); err != nil {
			g.refuse(req.Host, err)
			writeRefusal(c, err, false) // one request per proxied connection
			return
		}
	}
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
	f.scope.Identity.apply(req, req.URL.Host)
	req.Close = true
	out := &countWriter{w: up}
	pr := peerOfRecord(rec)
	if err := req.Write(out); err != nil {
		f.observeErr(pr, err)
		_ = up.Close()
		rec.BytesOut = out.n.Load()
		f.record(*rec)
		writeHTTPError(c, http.StatusBadGateway, "upstream write failed")
		return
	}
	// The response's status (429, 503, Retry-After, 403) paces the host;
	// the response itself goes to the client as it came.
	// It is parsed from a copy: every byte read from the host is passed
	// on unchanged, in order.
	// The head is read within the head window: a host that drips it does
	// not hold the connection for as long as each byte beats the idle
	// bound. On that timeout the connection ends (the deadline stays).
	ur := &errReader{r: up}
	var head bytes.Buffer
	_ = up.SetReadDeadline(time.Now().Add(f.responseHeadTimeout()))
	hr := bufio.NewReader(io.TeeReader(io.LimitReader(ur, maxHeaderBytes), &head))
	if resp, err := http.ReadResponse(hr, req); err == nil {
		// What the reader already buffered is in head too, so it reaches
		// the client unchanged. The body start is read from that buffer
		// only: the bounded head read above is the sole read of the host.
		f.observeResponse(pr, resp, bufferedBody(hr, resp))
		_ = up.SetReadDeadline(time.Time{})
	} else {
		f.observeErr(pr, err)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			_ = up.SetReadDeadline(time.Time{})
		}
	}
	n, _ := c.Write(head.Bytes())
	rest, _ := io.Copy(c, ur)
	in := int64(n) + rest
	_ = up.Close()
	rec.BytesOut, rec.BytesIn = out.n.Load(), in
	f.record(*rec)
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, ErrRefused):
		return http.StatusForbidden
	case errors.Is(err, adapt.ErrHostUnavailable):
		return http.StatusServiceUnavailable
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
	if g := f.guardFor(host, port); g != nil {
		f.serveGuarded(ctx, c, br, up, g, rec)
		return
	}
	f.pipe(ctx, c, br, up, rec)
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
// br holds what the client sent after its request. What the client sends
// goes through the tunnel's meter (tunnel.go): each further request it can
// tell apart waits for the host's rate, and a request the rate refuses (the
// host is backed off) or one past the tunnel's lifetime ends the tunnel.
func (f *Forwarder) pipe(ctx context.Context, c net.Conn, br *bufio.Reader, up net.Conn, rec *Record) {
	var out, in int64
	pr := peerOfRecord(rec)
	// The tunnel holds its connection slots while it is open. It is idle
	// while it is quiet after the host's answer, and busy again with the
	// next bytes of the client; while idle, another connection to the host
	// may close it for its slots (hostbudget.go).
	sl, act := slotsOf(up), &tunnelActivity{}
	sl.attach(c)
	act.touch(false)
	meter := newTunnelMeter(up, func(answered bool) error {
		if answered {
			// Bytes came back since the request before: the host is alive
			// and answered it (what it answered is not known).
			f.report(pr, adapt.Event{Signal: adapt.Answered, Opaque: true})
		}
		return f.acquire(ctx, pr)
	})
	if sl != nil && f.limits.PerHostConns > 0 && f.limits.SlotIdle > 0 {
		stopIdle := make(chan struct{})
		defer close(stopIdle)
		go sl.watchIdle(act, f.limits.SlotIdle/2, func() time.Duration { return f.slotIdleFor(meter) }, stopIdle)
	}
	done := make(chan struct{})
	var meterErr error
	go func() {
		defer close(done)
		out, meterErr = io.Copy(meter, slotReader{r: br, act: act, resume: sl.resume})
		if meterErr == nil {
			meterErr = meter.Flush()
		}
		if errors.Is(meterErr, errTunnelLifetime) || errors.Is(meterErr, errSlotEvicted) || errors.Is(meterErr, adapt.ErrHostUnavailable) || errors.Is(meterErr, context.Canceled) || errors.Is(meterErr, context.DeadlineExceeded) {
			// The tunnel carries no further request: both sides end, before
			// a byte of that request reached the host.
			_ = c.Close()
			_ = up.Close()
			return
		}
		meterErr = nil
		closeWrite(up)
	}()
	ur := &errReader{r: up}
	in, _ = io.Copy(c, spokeReader{r: ur, m: meter, act: act})
	if ur.err != nil {
		// The host side broke (reset, or cut on the idle bound): nothing
		// the client sends can reach it any more, so the client side is
		// closed too, which also ends the copy toward the host.
		_ = c.Close()
	} else {
		closeWrite(c)
	}
	<-done
	_ = up.Close()
	rec.BytesOut, rec.BytesIn = out, in
	if meterErr == nil && sl.wasEvicted() {
		// The forwarder closed the idle tunnel for another connection to
		// the host: how it ended says nothing about the host.
		meterErr = errSlotEvicted
	}
	if meterErr != nil {
		// The forwarder ended the tunnel itself: that says nothing about
		// the host.
		if in > 0 {
			f.report(pr, adapt.Event{Signal: adapt.Answered, Opaque: true})
		}
		rec.Reason = "tunnel ended: " + meterErr.Error()
		f.record(*rec)
		return
	}
	// An opaque tunnel shows only how it ended: reset by the host, or
	// closed after the host sent data. A tunnel cut on the idle bound after
	// the host answered is not a host failure.
	// A tunnel the tool opened and never sent a byte on (a connection its
	// pool dialed ahead and did not use) says nothing about the host when it
	// is cut on the idle bound: the host had nothing to answer. Read as a
	// timeout, such tunnels opened the breakers of live hosts two minutes
	// into a scan, and the tool then dropped the host on the refusals.
	unused := out == 0 && idledConn(up)
	if ur.err != nil && (in == 0 || !idledConn(up)) && !unused {
		f.observeErr(pr, ur.err)
	} else if in > 0 {
		// Bytes came back on a tunnel the forwarder did not read: the host
		// is alive, what it answered is not known (Opaque).
		f.report(pr, adapt.Event{Signal: adapt.Answered, Opaque: true})
	}
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
