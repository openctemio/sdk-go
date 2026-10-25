package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// silentServer accepts connections and never answers or closes them (a
// host that accepted the TCP connection but whose service hangs): the
// incident host. It returns its port.
func silentServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() { _, _ = io.Copy(io.Discard, c) }() // reads, never answers
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// startServe runs f and returns its address, its cancel and a channel
// closed when Serve returned.
func startServe(t *testing.T, f *Forwarder) (string, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), cancel, done
}

// requests are the ways a tool reaches a silent host through the
// forwarder: a plain HTTP request (absolute form) and a CONNECT tunnel.
var requests = map[string]func(c net.Conn, port int){
	"http": func(c net.Conn, port int) {
		_, _ = fmt.Fprintf(c, "GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
	},
	"connect": func(c net.Conn, port int) {
		_, _ = fmt.Fprintf(c, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
		_, _ = bufio.NewReader(c).ReadString('\n') // 200 Connection established
		_, _ = io.WriteString(c, "\x16\x03\x01")   // a TLS hello the host never answers
	},
}

// The incident (2026-10-25): a tool gave up on a silent host and exited,
// and the forwarder's handler stayed blocked reading that host, so the
// forwarder's stop (and the task, and its command) waited forever. The
// forwarder stopping must end every connection at once.
func TestStopEndsConnectionsToASilentHost(t *testing.T) {
	for name, send := range requests {
		t.Run(name, func(t *testing.T) {
			port := silentServer(t)
			f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{UpstreamIdle: -1})
			addr, cancel, done := startServe(t, f)
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			send(c, port)
			time.Sleep(200 * time.Millisecond)
			_ = c.Close() // the tool gave up on the host and went away
			time.Sleep(100 * time.Millisecond)
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return: a connection to a silent host outlived the forwarder")
			}
		})
	}
}

// A silent host is cut after the idle bound even while the forwarder runs:
// a connection the tool abandoned does not stay open until the task ends.
func TestSilentHostIsCutAfterTheIdleBound(t *testing.T) {
	for name, send := range requests {
		t.Run(name, func(t *testing.T) {
			port := silentServer(t)
			f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{UpstreamIdle: 300 * time.Millisecond})
			addr, _, _ := startServe(t, f)
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			send(c, port)
			// The forwarder closes the client side once it cut the host.
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			start := time.Now()
			_, err = io.Copy(io.Discard, c)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the connection to a silent host was not cut")
			}
			if waited := time.Since(start); waited > 4*time.Second {
				t.Fatalf("cut after %s", waited)
			}
			// The connection is recorded once it ended.
			if recs := waitRecords(t, f, 1); recs[0].Verdict != Allowed {
				t.Fatalf("record %+v", recs[0])
			}
		})
	}
}

// The idle bound counts silence only: a host that keeps sending is never
// cut, however long the transfer lasts.
func TestIdleBoundIsSilenceOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = bufio.NewReader(c).ReadString('\n')
		for range 8 {
			_, _ = io.WriteString(c, "x")
			time.Sleep(100 * time.Millisecond)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{UpstreamIdle: 250 * time.Millisecond})
	addr, _, _ := startServe(t, f)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = fmt.Fprintf(c, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n", port)
	br := bufio.NewReader(c)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	_, _ = br.ReadString('\n') // the blank line
	_, _ = io.WriteString(c, "go\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(br)
	if string(got) != "xxxxxxxx" {
		t.Fatalf("a host that kept sending was cut: got %q", got)
	}
}

// A caller's own read deadline still applies to a bounded connection, and
// a read cut by it is not counted as idle.
func TestBoundedConnKeepsCallerDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	bc := bound(ctx, a, time.Hour)
	_ = bc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	if _, err := bc.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("read %v after %s", err, time.Since(start))
	}
	if bc.Idled() {
		t.Fatal("a caller's deadline counted as idle")
	}
	_ = bc.SetReadDeadline(time.Time{})
	// The context ending closes it.
	cancel()
	if _, err := bc.Read(make([]byte, 1)); err == nil {
		t.Fatal("read after the context ended")
	}
	if err := bc.Close(); err != nil {
		t.Fatalf("close after the context closed it: %v", err)
	}
}
