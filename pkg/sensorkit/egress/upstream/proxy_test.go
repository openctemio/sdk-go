package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Test proxies: real in-process HTTP CONNECT and SOCKS5 servers on
// loopback. Endpoints name private addresses (loopback is denied for a
// proxy); the test dialer maps them to the loopback listeners.

type testProxy struct {
	ln    net.Listener
	conns atomic.Int64 // accepted connections
	mu    sync.Mutex
	auth  []string // Proxy-Authorization values or "user:pass" seen
	dials []string // CONNECT targets
	// names is a SOCKS proxy's own resolver for CONNECT by name.
	names map[string]string
}

func (tp *testProxy) resolve(name, real string) {
	tp.mu.Lock()
	if tp.names == nil {
		tp.names = map[string]string{}
	}
	tp.names[name] = real
	tp.mu.Unlock()
}

func (tp *testProxy) addr() string { return tp.ln.Addr().String() }

func (tp *testProxy) seen() (auth, dials []string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([]string(nil), tp.auth...), append([]string(nil), tp.dials...)
}

// httpProxy answers CONNECT with code; on 2xx it dials the target and
// pipes, sending early (bytes right after the reply) first. user/pass,
// when set, are required (407 otherwise).
func httpProxy(t *testing.T, code int, user, pass string, early string) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tp := &testProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tp.conns.Add(1)
			go tp.serveHTTP(c, code, user, pass, early)
		}
	}()
	return tp
}

func (tp *testProxy) serveHTTP(c net.Conn, code int, user, pass, early string) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	tp.mu.Lock()
	tp.auth = append(tp.auth, req.Header.Get("Proxy-Authorization"))
	tp.dials = append(tp.dials, req.Host)
	tp.mu.Unlock()
	if user != "" && req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
		return
	}
	if code < 200 || code > 299 {
		_, _ = io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(code)+" No\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\nX-Test: 1\r\n\r\n"+early)
	pipe(c, br, up)
}

func pipe(c net.Conn, br io.Reader, up net.Conn) {
	done := make(chan struct{})
	go func() { _, _ = io.Copy(up, br); close(done) }()
	_, _ = io.Copy(c, up)
	_ = c.Close()
	<-done
}

// socksProxy is a SOCKS5 server; rep is its CONNECT reply (0 dials the
// target). user/pass, when set, are required.
func socksProxy(t *testing.T, rep byte, user, pass string) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tp := &testProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tp.conns.Add(1)
			go tp.serveSOCKS(c, rep, user, pass)
		}
	}()
	return tp
}

func (tp *testProxy) serveSOCKS(c net.Conn, rep byte, user, pass string) {
	defer c.Close()
	br := bufio.NewReader(c)
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	want := byte(0)
	if user != "" {
		want = 2
	}
	if !containsB(methods, want) {
		_, _ = c.Write([]byte{5, 0xff})
		return
	}
	_, _ = c.Write([]byte{5, want})
	if want == 2 {
		var v [2]byte
		if _, err := io.ReadFull(br, v[:]); err != nil {
			return
		}
		u := make([]byte, v[1])
		_, _ = io.ReadFull(br, u)
		pl, _ := br.ReadByte()
		pw := make([]byte, pl)
		_, _ = io.ReadFull(br, pw)
		tp.mu.Lock()
		tp.auth = append(tp.auth, string(u)+":"+string(pw))
		tp.mu.Unlock()
		if string(u) != user || string(pw) != pass {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	var a netip.Addr
	switch req[3] {
	case 1:
		var b [4]byte
		_, _ = io.ReadFull(br, b[:])
		a = netip.AddrFrom4(b)
	case 4:
		var b [16]byte
		_, _ = io.ReadFull(br, b[:])
		a = netip.AddrFrom16(b)
	case 3:
		// By name (socks5h): the proxy resolves it with its own table.
		l, _ := br.ReadByte()
		name := make([]byte, l)
		_, _ = io.ReadFull(br, name)
		var pb [2]byte
		_, _ = io.ReadFull(br, pb[:])
		tp.mu.Lock()
		tp.dials = append(tp.dials, string(name)+":"+strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))
		real, ok := tp.names[string(name)]
		tp.mu.Unlock()
		if !ok {
			_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		up, err := net.Dial("tcp", real)
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		pipe(c, br, up)
		return
	default:
		return
	}
	var pb [2]byte
	_, _ = io.ReadFull(br, pb[:])
	target := netip.AddrPortFrom(a, binary.BigEndian.Uint16(pb[:])).String()
	tp.mu.Lock()
	tp.dials = append(tp.dials, target)
	tp.mu.Unlock()
	if rep != 0 {
		_, _ = c.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	// A domain-name bound address, to check the client reads it all.
	_, _ = c.Write([]byte{5, 0, 0, 3, 4, 'h', 'o', 's', 't', 0x04, 0x38})
	pipe(c, br, up)
}

func containsB(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// echoServer echoes one line per connection, prefixed with "echo:".
func echoServer(t *testing.T) netip.AddrPort {
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
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				_, _ = io.WriteString(c, "echo:"+line)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// netmap maps endpoint addresses (private IPs) to loopback listeners and
// counts dials per endpoint address; an unmapped address is refused.
type netmap struct {
	mu    sync.Mutex
	m     map[string]string
	dials map[string]int
}

func newNetmap() *netmap { return &netmap{m: map[string]string{}, dials: map[string]int{}} }

func (n *netmap) add(endpoint, real string) {
	n.mu.Lock()
	n.m[endpoint] = real
	n.mu.Unlock()
}

func (n *netmap) remove(endpoint string) {
	n.mu.Lock()
	delete(n.m, endpoint)
	n.mu.Unlock()
}

func (n *netmap) count(endpoint string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dials[endpoint]
}

func (n *netmap) total() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := 0
	for _, v := range n.dials {
		t += v
	}
	return t
}

func (n *netmap) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dials[addr]++
	real, ok := n.m[addr]
	n.mu.Unlock()
	if !ok {
		// Direct dials of test targets (loopback) pass through.
		if ap, err := netip.ParseAddrPort(addr); err == nil && ap.Addr().IsLoopback() {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}

func newTestPool(t *testing.T, cfg Config, n *netmap, mod ...func(*Options)) *Pool {
	t.Helper()
	opts := Options{Key: "job-1", dialer: n.dial, lookup: func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no lookup in this test")
	}}
	for _, m := range mod {
		m(&opts)
	}
	p, err := New(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func roundTrip(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "ping\n"); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
