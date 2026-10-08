package tool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// EnvEgressProxy is set by the sensor's sandbox, for a task whose network
// it confines, to the task's forwarder (api RFC-060): the task has no other
// way out. Its value is a proxy URL ("http://127.0.0.1:1080") that takes
// HTTP CONNECT, absolute-form HTTP and SOCKS5.
const EnvEgressProxy = "OPENCTEM_EGRESS_PROXY"

// ErrEgressRefused is the error of a connection the task's forwarder
// refused: the destination is not one the task may reach.
var ErrEgressRefused = errors.New("egress refused")

// EgressProxy is the task's forwarder, or nil when the task's network is
// not confined.
func EgressProxy() *url.URL {
	v := strings.TrimSpace(os.Getenv(EnvEgressProxy))
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

// Dial opens a connection for a tool that speaks TCP itself (a port
// scanner, a TLS checker, a protocol probe). On a sensor that confines the
// task's network it goes through the task's forwarder with HTTP CONNECT:
// a direct connection has no route there, and a destination that is not a
// target fails with ErrEgressRefused. Elsewhere it is a direct connection.
// network must be "tcp", "tcp4" or "tcp6".
func Dial(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("tool.Dial: network %q is not supported", network)
	}
	var d net.Dialer
	p := EgressProxy()
	if p == nil {
		return d.DialContext(ctx, network, address)
	}
	c, err := d.DialContext(ctx, "tcp", p.Host)
	if err != nil {
		return nil, fmt.Errorf("tool.Dial: egress proxy: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("tool.Dial: egress proxy: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		if resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("%w: %s", ErrEgressRefused, address)
		}
		return nil, fmt.Errorf("tool.Dial: egress proxy answered %s for %s", resp.Status, address)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufferedConn is a connection whose first bytes were read with its
// CONNECT answer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
