package absname

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestOf(t *testing.T) {
	for in, want := range map[string]string{
		"app.example.com":  "app.example.com.",
		"app.example.com.": "app.example.com.",
		"host":             "host.",
		"10.0.0.1":         "10.0.0.1",
		"[2001:db8::1]":    "[2001:db8::1]",
		"2001:db8::1":      "2001:db8::1",
		"":                 "",
	} {
		if got := Of(in); got != want {
			t.Errorf("Of(%q) = %q, want %q", in, got, want)
		}
	}
}

// nxServer answers every query NXDOMAIN and records the names asked.
type nxServer struct {
	mu    sync.Mutex
	asked []string
}

func (s *nxServer) serve(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.asked = append(s.asked, q.Name.String())
			s.mu.Unlock()
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeNameError},
				Questions: []dnsmessage.Question{q}}
			b, _ := resp.Pack()
			_, _ = pc.WriteTo(b, from)
		}
	}()
	return pc.LocalAddr().String()
}

// An unresolvable target looked up through Of never produces a query with
// a search domain appended, whatever the host's resolv.conf says (the Go
// resolver reads its search list from it); the relative name does, on a
// host with a search list.
func TestAbsoluteLookupNeverAppendsASearchDomain(t *testing.T) {
	s := &nxServer{}
	addr := s.serve(t)
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const name = "unresolvable-target.example"
	if _, err := r.LookupNetIP(ctx, "ip4", Of(name)); err == nil {
		t.Fatal("the fake server answers NXDOMAIN")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.asked) == 0 {
		t.Fatal("no query reached the server")
	}
	for _, q := range s.asked {
		if !strings.EqualFold(q, name+".") {
			t.Fatalf("the resolver asked %q: a search domain was appended to %q", q, name)
		}
	}
}
