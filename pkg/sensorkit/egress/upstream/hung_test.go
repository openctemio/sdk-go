package upstream

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// hungProxy accepts connections, reads what it is sent and never answers
// the CONNECT (a SOCKS5 one answers the greeting with "no authentication"
// first).
func hungProxy(t *testing.T, scheme string) string {
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
				if scheme == SchemeSOCKS5 {
					var greet [3]byte
					if _, err := io.ReadFull(c, greet[:]); err != nil {
						return
					}
					_, _ = c.Write([]byte{socksVer, socksNoAuth})
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// A proxy that takes the connection and the CONNECT and never replies is
// hung, not every target unreachable: after replyTimeoutLimit timeouts with
// no tunnel through it in the job, it is proxy_down, the connection fails
// over and its breaker opens.
func TestHungProxyIsProxyDownAfterRepeatedReplyTimeouts(t *testing.T) {
	for _, scheme := range []string{SchemeHTTP, SchemeSOCKS5} {
		t.Run(scheme, func(t *testing.T) {
			target := echoServer(t)
			good := httpProxy(t, 200, "", "", "")
			n := newNetmap()
			n.add("10.0.0.1:1", hungProxy(t, scheme))
			n.add("10.0.0.2:2", good.addr())
			p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Strategy: StrategyPriority,
				Endpoints: []Endpoint{ep("hung", scheme, "10.0.0.1", 1), ep("good", SchemeHTTP, "10.0.0.2", 2)}}, n,
				func(o *Options) { o.AttemptTimeout = 50 * time.Millisecond })
			dial := func() (net.Conn, error) {
				return p.Dial(egress.WithTargetHost(context.Background(), "example.com"), "tcp", target.String())
			}
			// Below the limit: about the target, no failover.
			for i := 1; i < replyTimeoutLimit; i++ {
				_, err := dial()
				if ue := upErr(t, err); ue.Class != egress.ClassTargetUnreachable || ue.Endpoint != "hung" {
					t.Fatalf("timeout %d: %s via %s, want target_unreachable via hung", i, ue.Class, ue.Endpoint)
				}
			}
			if n.count("10.0.0.2:2") != 0 {
				t.Fatal("failed over on a target answer")
			}
			// At the limit: proxy_down, the connection fails over.
			c, err := dial()
			if err != nil {
				t.Fatalf("no failover to the good endpoint: %v", err)
			}
			if ec, ok := c.(egress.EndpointConn); !ok || ec.UpstreamEndpoint() != "good" {
				t.Fatal("tunnel not through the good endpoint")
			}
			_ = c.Close()
			// The breaker is open: the hung endpoint is not tried again.
			before := n.count("10.0.0.1:1")
			c, err = dial()
			if err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			if n.count("10.0.0.1:1") != before {
				t.Fatal("hung endpoint tried with its breaker open")
			}
			for _, e := range p.Report().Endpoints {
				if e.EndpointID == "hung" && (e.ProxyDown != 1 || e.TargetUnreachable != int64(replyTimeoutLimit-1)) {
					t.Fatalf("hung endpoint report %+v", e)
				}
			}
		})
	}
}

// An endpoint that has carried a tunnel in the job is up: a CONNECT reply
// that never comes afterwards is the target's, and never opens its breaker.
func TestReplyTimeoutAfterATunnelStaysTargetUnreachable(t *testing.T) {
	target := echoServer(t)
	good := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", good.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, n,
		func(o *Options) { o.AttemptTimeout = 50 * time.Millisecond })
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	n.add("10.0.0.1:1", hungProxy(t, SchemeHTTP)) // now it never answers
	for i := range 2 * replyTimeoutLimit {
		_, err := p.Dial(context.Background(), "tcp", target.String())
		if ue := upErr(t, err); ue.Class != egress.ClassTargetUnreachable {
			t.Fatalf("timeout %d: %s, want target_unreachable: %v", i, ue.Class, err)
		}
	}
	if got := n.count("10.0.0.1:1"); got != 1+2*replyTimeoutLimit {
		t.Fatalf("%d dials: the breaker opened on target timeouts", got)
	}
}
