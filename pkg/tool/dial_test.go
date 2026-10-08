package tool_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func greeter(t *testing.T) string {
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
			_, _ = c.Write([]byte("hello\n"))
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func readLine(t *testing.T, c net.Conn) string {
	t.Helper()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	l, _ := bufio.NewReader(c).ReadString('\n')
	return l
}

func TestDialDirect(t *testing.T) {
	t.Setenv(tool.EnvEgressProxy, "")
	c, err := tool.Dial(context.Background(), "tcp", greeter(t))
	if err != nil {
		t.Fatal(err)
	}
	if l := readLine(t, c); l != "hello\n" {
		t.Fatalf("%q", l)
	}
	if _, err := tool.Dial(context.Background(), "udp", "127.0.0.1:53"); err == nil {
		t.Fatal("udp accepted")
	}
}

// SECURITY (api RFC-060): on a confined sensor Dial goes through the task's
// forwarder; a destination that is not a target is ErrEgressRefused.
func TestDialThroughTheForwarder(t *testing.T) {
	target := greeter(t)
	fw := egress.New(egress.Scope{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, egress.Limits{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fw.Serve(ctx, ln) }()
	t.Setenv(tool.EnvEgressProxy, "http://"+ln.Addr().String())

	c, err := tool.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	if l := readLine(t, c); l != "hello\n" {
		t.Fatalf("through the forwarder: %q", l)
	}
	if _, err := tool.Dial(context.Background(), "tcp", "outside.example:443"); !errors.Is(err, tool.ErrEgressRefused) {
		t.Fatalf("outside: %v", err)
	}
}
