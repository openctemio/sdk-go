package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultUpstreamIdle is how long an upstream connection may stay silent
// (no byte read from the host) before the forwarder closes it, when
// Limits.UpstreamIdle is 0.
//
// Every forwarded connection is bounded twice, so no connection outlives
// its task and none blocks the forwarder's stop: the forwarder's context
// ending closes it at once, and a host that accepted the connection but
// sends nothing (a silent or tarpitting host, or one that keeps a
// half-closed connection open after the tool went away) is cut after this
// window. Without these bounds a single silent host kept a finished task
// waiting on its forwarder indefinitely.
const DefaultUpstreamIdle = 2 * time.Minute

// boundedConn is an upstream connection with a read idle bound and closed
// when its context ends.
type boundedConn struct {
	net.Conn
	idle time.Duration
	stop func() bool
	once sync.Once
	// idled is set when a read ended on the idle bound (not a host error).
	idled atomic.Bool
	// deadline is a read deadline the caller set (unix nanoseconds, 0:
	// none); a read waits until the earlier of it and the idle bound.
	deadline atomic.Int64
}

// bound wraps c (an upstream connection the forwarder dialed): reads wait
// at most idle for the host, and ctx ending closes it.
func bound(ctx context.Context, c net.Conn, idle time.Duration) *boundedConn {
	b := &boundedConn{Conn: c, idle: idle}
	b.stop = context.AfterFunc(ctx, func() { _ = c.Close() })
	return b
}

func (b *boundedConn) Read(p []byte) (int, error) {
	var d time.Time
	if b.idle > 0 {
		d = time.Now().Add(b.idle)
	}
	explicit := false
	if ns := b.deadline.Load(); ns != 0 && (d.IsZero() || ns < d.UnixNano()) {
		d, explicit = time.Unix(0, ns), true
	}
	_ = b.Conn.SetReadDeadline(d)
	n, err := b.Conn.Read(p)
	if err != nil && !explicit && b.idle > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
		b.idled.Store(true)
	}
	return n, err
}

// SetReadDeadline records a caller's read deadline; the next read waits
// until the earlier of it and the idle bound.
func (b *boundedConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		b.deadline.Store(0)
	} else {
		b.deadline.Store(t.UnixNano())
	}
	return b.Conn.SetReadDeadline(t)
}

// SetDeadline sets both deadlines (the read one as SetReadDeadline).
func (b *boundedConn) SetDeadline(t time.Time) error {
	_ = b.SetReadDeadline(t)
	return b.SetWriteDeadline(t)
}

func (b *boundedConn) Close() error {
	var err error
	b.once.Do(func() {
		b.stop()
		err = b.Conn.Close()
	})
	return err
}

// CloseWrite half-closes the connection when the underlying one can.
func (b *boundedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Close()
}

// UpstreamEndpoint is the underlying connection's endpoint (EndpointConn).
func (b *boundedConn) UpstreamEndpoint() string {
	if ec, ok := b.Conn.(EndpointConn); ok {
		return ec.UpstreamEndpoint()
	}
	return ""
}

// Idled reports whether a read ended on the idle bound.
func (b *boundedConn) Idled() bool { return b.idled.Load() }

// idledConn reports whether c is a bounded connection that was cut on its
// idle bound: an idle cut after the host answered is not a host failure.
func idledConn(c net.Conn) bool {
	b, ok := c.(*boundedConn)
	return ok && b.Idled()
}
