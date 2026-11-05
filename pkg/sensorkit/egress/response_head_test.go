package egress

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

// hostileHost accepts connections on loopback, reads what the client sends
// first, and then runs answer on the connection. written counts the bytes
// answer wrote.
func hostileHost(t *testing.T, answer func(c net.Conn, written *atomic.Int64)) (int, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	written := &atomic.Int64{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				_, _ = c.Read(make([]byte, 4096))
				_ = c.SetReadDeadline(time.Time{})
				answer(c, written)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, written
}

// endlessHeader answers with a status line and one header line that never
// ends.
func endlessHeader(c net.Conn, written *atomic.Int64) {
	n, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nX-A: ")
	written.Add(int64(n))
	chunk := []byte(strings.Repeat("a", 32<<10))
	for err == nil && written.Load() < 1<<30 {
		n, err = c.Write(chunk)
		written.Add(int64(n))
	}
}

// slowHeader answers with a status line, then one header byte every 50ms:
// every read beats the idle bound, the head never completes.
func slowHeader(c net.Conn, written *atomic.Int64) {
	n, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nX-A: ")
	written.Add(int64(n))
	for err == nil {
		time.Sleep(50 * time.Millisecond)
		n, err = c.Write([]byte("a"))
		written.Add(int64(n))
	}
}

// slowHandshake answers a TLS client hello with the header of a 16 KiB
// handshake record, then one byte of it every 50ms.
func slowHandshake(c net.Conn, written *atomic.Int64) {
	n, err := c.Write([]byte{0x16, 0x03, 0x03, 0x40, 0x00})
	written.Add(int64(n))
	for err == nil {
		time.Sleep(50 * time.Millisecond)
		n, err = c.Write([]byte{0x02})
		written.Add(int64(n))
	}
}

// headForwarder guards every connection (a web scope) with an idle bound
// of idle, so a dripping host beats the idle bound on every byte.
func headForwarder(t *testing.T, idle time.Duration) string {
	t.Helper()
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}},
		Web: &webscope.Scope{DenyPaths: []string{"/admin"}}, WebTargets: []string{"app.test"}}, Limits{UpstreamIdle: idle})
	return serve(t, f)
}

// within fails when do takes longer than d.
func within(t *testing.T, d time.Duration, do func()) time.Duration {
	t.Helper()
	start := time.Now()
	done := make(chan struct{})
	go func() { do(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("still reading after %s", d)
	}
	return time.Since(start)
}

// readUntilClosed reads the response of the request on c; the forwarder
// must close the connection without a response.
func readUntilClosed(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if resp, err := http.ReadResponse(br, nil); err == nil {
		_ = resp.Body.Close()
		t.Errorf("got a response %d, want the connection closed", resp.StatusCode)
	}
}

// openTunnel opens a CONNECT tunnel to app.test:port through the forwarder.
func openTunnel(t *testing.T, pa string, port int) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT app.test:%d HTTP/1.1\r\nHost: app.test\r\n\r\n", port)
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, br
}

func getRequest(port int) string {
	return "GET /public HTTP/1.1\r\nHost: app.test:" + strconv.Itoa(port) + "\r\n\r\n"
}

// A host that sends an endless header line is cut after maxHeaderBytes on
// a guarded tunnel: before, the forwarder read it all (256 MiB in under two
// seconds) and the sensor ran out of memory.
func TestGuardedResponseEndlessHeader(t *testing.T) {
	port, written := hostileHost(t, endlessHeader)
	pa := headForwarder(t, time.Minute)
	c, br := openTunnel(t, pa, port)
	_, _ = io.WriteString(c, getRequest(port))
	within(t, 20*time.Second, func() { readUntilClosed(t, c, br) })
	time.Sleep(200 * time.Millisecond)
	// What the host wrote: the head bound plus what the socket buffers
	// took before the forwarder closed the connection.
	if n := written.Load(); n > 32<<20 {
		t.Errorf("the host wrote %d bytes before the forwarder closed the connection", n)
	}
}

// The same over SOCKS5.
func TestGuardedResponseEndlessHeaderSOCKS5(t *testing.T) {
	port, written := hostileHost(t, endlessHeader)
	pa := headForwarder(t, time.Minute)
	d, err := proxy.SOCKS5("tcp", pa, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", "app.test:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, getRequest(port))
	within(t, 20*time.Second, func() { readUntilClosed(t, c, bufio.NewReader(c)) })
	time.Sleep(200 * time.Millisecond)
	if n := written.Load(); n > 32<<20 {
		t.Errorf("the host wrote %d bytes before the forwarder closed the connection", n)
	}
}

// A host that drips its head, each byte inside the idle bound, holds the
// connection only for the head window (the idle bound), not forever.
func TestGuardedResponseSlowHeader(t *testing.T) {
	port, _ := hostileHost(t, slowHeader)
	pa := headForwarder(t, time.Second)
	c, br := openTunnel(t, pa, port)
	_, _ = io.WriteString(c, getRequest(port))
	if d := within(t, 10*time.Second, func() { readUntilClosed(t, c, br) }); d < 900*time.Millisecond {
		t.Errorf("closed after %s, before the head window", d)
	}
}

// The same on a plain proxied request (absolute form): its head was
// already bounded in size, and is now bounded in time too.
func TestPlainResponseSlowHeader(t *testing.T) {
	port, _ := hostileHost(t, slowHeader)
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}}}, Limits{UpstreamIdle: time.Second})
	pa := serve(t, f)
	c, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET http://app.test:%d/public HTTP/1.1\r\nHost: app.test:%d\r\n\r\n", port, port)
	within(t, 10*time.Second, func() {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	})
}

// A plain proxied request to a host with an endless header passes at most
// the head bound to the client before the stream continues unparsed; the
// forwarder never buffers more than the bound.
func TestPlainResponseEndlessHeaderIsStreamed(t *testing.T) {
	port, _ := hostileHost(t, endlessHeader)
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}}}, Limits{UpstreamIdle: time.Second})
	pa := serve(t, f)
	c, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET http://app.test:%d/public HTTP/1.1\r\nHost: app.test:%d\r\n\r\n", port, port)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _ := io.CopyN(io.Discard, c, 4<<20)
	if n != 4<<20 {
		t.Errorf("read %d bytes of the passed-on stream", n)
	}
}

// A target that drips its TLS handshake holds a terminated connection only
// for the head window.
func TestGuardedSlowUpstreamHandshake(t *testing.T) {
	port, _ := hostileHost(t, slowHandshake)
	pa := headForwarder(t, time.Second)
	c, _ := openTunnel(t, pa, port)
	tc := tls.Client(c, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // the forwarder's own test authority
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake with the forwarder: %v", err)
	}
	_, _ = io.WriteString(tc, getRequest(port))
	if d := within(t, 10*time.Second, func() {
		_ = tc.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.Copy(io.Discard, tc)
	}); d < 900*time.Millisecond {
		t.Errorf("closed after %s, before the head window", d)
	}
}
