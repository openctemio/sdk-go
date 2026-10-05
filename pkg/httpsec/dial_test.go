package httpsec

import (
	"context"
	"net"
	"testing"
)

// The first resolved address is unreachable (nothing listens on that port on
// ::1); the dial falls through to the next validated address.
func TestDialValidatedFallsThroughToTheNextAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := &net.Dialer{}
	conn, err := dialValidated(context.Background(), d.DialContext, "tcp", []string{"::1", "127.0.0.1"}, port)
	if err != nil {
		t.Fatalf("expected a connection through 127.0.0.1: %v", err)
	}
	_ = conn.Close()
}

func TestDialValidatedReturnsTheFirstError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close() // nothing listens any more
	d := &net.Dialer{}
	if _, err := dialValidated(context.Background(), d.DialContext, "tcp", []string{"127.0.0.1"}, port); err == nil {
		t.Fatal("expected an error when no address answers")
	}
}
