package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

// echoServer accepts connections on loopback and echoes one line back.
func echoServer(t *testing.T) (string, int) {
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
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = io.WriteString(c, "echo:"+line)
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// serve runs f on a loopback listener and returns its address.
func serve(t *testing.T, f *Forwarder) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = f.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

func TestResolveScope(t *testing.T) {
	f := New(Scope{
		Names:    map[string][]netip.Addr{"App.Example.": {addr("192.0.2.10")}, "meta.example": {addr("169.254.169.254")}},
		Prefixes: []netip.Prefix{pfx("10.0.0.0/8"), pfx("0.0.0.0/0")},
		Vendor:   []string{"api.vendor.example", "evil.vendor.example"},
	}, Limits{})
	f.LookupVendor = func(_ context.Context, h string) ([]netip.Addr, error) {
		if h == "evil.vendor.example" {
			return []netip.Addr{addr("10.1.2.3"), addr("127.0.0.1")}, nil
		}
		return []netip.Addr{addr("203.0.113.5")}, nil
	}
	ctx := context.Background()
	ok := map[string]string{
		"app.example":        "192.0.2.10",
		"10.9.9.9":           "10.9.9.9",
		"api.vendor.example": "203.0.113.5",
		"[::ffff:10.1.1.1]":  "10.1.1.1",
	}
	for h, want := range ok {
		got, err := f.Resolve(ctx, h, 443)
		if err != nil || len(got) == 0 || got[0].String() != want {
			t.Errorf("%s: %v %v, want %s", h, got, err, want)
		}
	}
	// SECURITY: metadata and link-local never, whatever the scope admits;
	// a vendor host never reaches private addresses; unknown names never.
	for _, h := range []string{"169.254.169.254", "fe80::1", "meta.example", "evil.vendor.example", "other.example", "0.0.0.0", "224.0.0.1"} {
		if _, err := f.Resolve(ctx, h, 443); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v, want refused", h, err)
		}
	}
	g := New(Scope{Prefixes: []netip.Prefix{pfx("192.0.2.0/24")}, Ports: []int{443}}, Limits{})
	if _, err := g.Resolve(ctx, "192.0.2.1", 22); !errors.Is(err, ErrRefused) {
		t.Errorf("port outside the list: %v", err)
	}
	if _, err := g.Resolve(ctx, "198.51.100.1", 443); !errors.Is(err, ErrRefused) {
		t.Errorf("address outside the prefixes: %v", err)
	}
}

// SECURITY: an admitted name is dialed at its pinned address; it is never
// looked up again, so a rebound DNS answer cannot move it.
func TestAdmittedNameIsPinned(t *testing.T) {
	host, port := echoServer(t)
	f := New(Scope{Names: map[string][]netip.Addr{"target.test": {addr(host)}}}, Limits{})
	f.LookupVendor = func(context.Context, string) ([]netip.Addr, error) {
		t.Error("an admitted name was resolved again")
		return nil, errors.New("no")
	}
	resp := connect(t, serve(t, f), fmt.Sprintf("target.test:%d", port))
	if resp != "echo:hi\n" {
		t.Fatalf("tunnel: %q", resp)
	}
	recs := waitRecords(t, f, 1)
	if len(recs) != 1 || recs[0].Verdict != Allowed || recs[0].Addr != host || recs[0].BytesIn == 0 {
		t.Fatalf("record %+v", recs)
	}
}

// waitRecords waits until the forwarder recorded n destinations (a tunnel
// is recorded when it closes).
func waitRecords(t *testing.T, f *Forwarder, n int) []Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		recs, _ := f.Records()
		if len(recs) >= n || time.Now().After(deadline) {
			return recs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// connect opens a CONNECT tunnel through the proxy, sends "hi\n" and
// returns what came back (or the proxy's status line).
func connect(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.Status
	}
	_, _ = io.WriteString(c, "hi\n")
	line, _ := br.ReadString('\n')
	return line
}

func TestConnectRefusesOutOfScope(t *testing.T) {
	_, port := echoServer(t)
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{})
	p := serve(t, f)
	if got := connect(t, p, fmt.Sprintf("127.0.0.1:%d", port)); got != "echo:hi\n" {
		t.Fatalf("admitted: %q", got)
	}
	for _, target := range []string{"127.0.0.2:22", "example.org:80", "169.254.169.254:80"} {
		if got := connect(t, p, target); !strings.HasPrefix(got, "403") {
			t.Errorf("%s: %q, want 403", target, got)
		}
	}
	if n := len(f.Refusals()); n != 3 {
		t.Fatalf("%d refusals recorded, want 3", n)
	}
}

func TestHTTPAbsoluteForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached the target")
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.Path, body)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{})
	pu, _ := url.Parse("http://" + serve(t, f))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 10 * time.Second}
	resp, err := client.Post(srv.URL+"/x", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "POST /x payload" {
		t.Fatalf("body %q", b)
	}
	resp, err = client.Get("http://not-a-target.example:" + u.Port() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unadmitted host: %d", resp.StatusCode)
	}
}

func TestSOCKS5(t *testing.T) {
	host, port := echoServer(t)
	f := New(Scope{Names: map[string][]netip.Addr{"target.test": {addr(host)}}}, Limits{})
	d, err := proxy.SOCKS5("tcp", serve(t, f), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", fmt.Sprintf("target.test:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "hi\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if line != "echo:hi\n" {
		t.Fatalf("socks tunnel: %q", line)
	}
	if _, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port)); err == nil {
		t.Fatal("an address that is not admitted was reached over SOCKS5")
	}
}

func TestDNS(t *testing.T) {
	f := New(Scope{Names: map[string][]netip.Addr{"target.test": {addr("192.0.2.7"), addr("2001:db8::7")}}}, Limits{})
	ask := func(name string, typ dnsmessage.Type) *dnsmessage.Message {
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
		b, _ := q.Pack()
		out, err := f.AnswerDNS(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatal(err)
		}
		return &m
	}
	m := ask("target.test.", dnsmessage.TypeA)
	if m.ID != 7 || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 7} {
		t.Fatalf("A: %+v", m)
	}
	if m := ask("target.test.", dnsmessage.TypeAAAA); len(m.Answers) != 1 {
		t.Fatalf("AAAA: %+v", m)
	}
	// SECURITY: any other name is NXDOMAIN (no lookup carries data out).
	if m := ask("c2VjcmV0.exfil.example.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
		t.Fatalf("unadmitted name: %+v", m.Header)
	}
	if n := len(f.Refusals()); n != 1 || f.Refusals()[0].Protocol != "dns" {
		t.Fatalf("refusals %+v", f.Refusals())
	}
}

func TestRateLimit(t *testing.T) {
	f := New(Scope{Prefixes: []netip.Prefix{pfx("192.0.2.0/24")}}, Limits{Rate: 20})
	start := time.Now()
	for range 30 {
		if err := f.allowRate(context.Background(), "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	// A burst of 20, then 10 more at 20/s: at least ~0.5s.
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Fatalf("30 connections at 20/s took %v", d)
	}
}

func TestMalformedRequests(t *testing.T) {
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{HandshakeTimeout: time.Second})
	p := serve(t, f)
	for _, raw := range []string{
		"GET https://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", // TLS origination is not offered
		"CONNECT nohostport HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n", // origin-form: not a proxy request
		"GET http://127.0.0.1/ HTTP/1.1\r\nX: " + strings.Repeat("a", maxHeaderBytes) + "\r\n\r\n",
	} {
		c, err := net.Dial("tcp", p)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, raw)
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if !strings.Contains(line, "400") {
			t.Errorf("%.40q: %q, want 400", raw, line)
		}
	}
}

func FuzzServeConn(f *testing.F) {
	f.Add([]byte("CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n"))
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 4, 't', 'e', 's', 't', 0, 80})
	f.Add([]byte("GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		fw := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}, Names: map[string][]netip.Addr{"test": {addr("127.0.0.1")}}},
			Limits{HandshakeTimeout: 200 * time.Millisecond, DialTimeout: 100 * time.Millisecond})
		fw.Dial = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no network in the fuzzer")
		}
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() { fw.ServeConn(context.Background(), server); close(done) }()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		go func() { _, _ = client.Write(in); _, _ = io.Copy(io.Discard, client) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("ServeConn did not return")
		}
		_ = client.Close()
	})
}

func FuzzAnswerDNS(f *testing.F) {
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		fw := New(Scope{Names: map[string][]netip.Addr{"test": {addr("192.0.2.1")}}}, Limits{})
		_, _ = fw.AnswerDNS(context.Background(), in)
	})
}

// SECURITY: AnyPublic reaches the internet, never private, loopback or
// metadata addresses, whatever a name resolves to.
func TestAnyPublic(t *testing.T) {
	f := New(Scope{AnyPublic: true}, Limits{})
	f.LookupVendor = func(_ context.Context, h string) ([]netip.Addr, error) {
		switch h {
		case "public.example":
			return []netip.Addr{addr("203.0.113.9")}, nil
		case "rebind.example":
			return []netip.Addr{addr("10.0.0.5"), addr("169.254.169.254")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	ctx := context.Background()
	if got, err := f.Resolve(ctx, "public.example", 443); err != nil || got[0] != addr("203.0.113.9") {
		t.Fatalf("public: %v %v", got, err)
	}
	if _, err := f.Resolve(ctx, "8.8.8.8", 53); err != nil {
		t.Fatalf("public address: %v", err)
	}
	for _, h := range []string{"rebind.example", "10.1.1.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "168.63.129.16", "100.100.100.200", "fd00:ec2::254"} {
		if _, err := f.Resolve(ctx, h, 443); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v, want refused", h, err)
		}
	}
}

// The relay of a confined task asks over a stream (RFC 1035 framing).
func TestServeDNSStream(t *testing.T) {
	f := New(Scope{Names: map[string][]netip.Addr{"target.test": {addr("192.0.2.7")}}}, Limits{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.ServeDNSStream(ctx, ln) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, name := range []string{"target.test.", "other.test."} {
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 9}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		b, _ := q.Pack()
		if _, err := c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
			t.Fatal(err)
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "target.test.":
			if len(m.Answers) != 1 {
				t.Fatalf("admitted name: %+v", m)
			}
		default:
			if m.RCode != dnsmessage.RCodeNameError {
				t.Fatalf("other name: %+v", m.Header)
			}
		}
	}
}

// A DNS tool gets the other record types of an admitted name from the
// upstream resolver; an unadmitted name never reaches it, and an answer
// to another question is not passed on.
func TestDNSUpstreamForAdmittedNames(t *testing.T) {
	f := New(Scope{Names: map[string][]netip.Addr{"target.test": {addr("192.0.2.7")}}}, Limits{})
	asked := 0
	mx := func(q []byte, id uint16, name string) []byte {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET}},
			Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET},
				Body: &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName("mail.target.test.")}}}}
		b, _ := m.Pack()
		return b
	}
	var reply func(q []byte) []byte
	f.Upstream = func(_ context.Context, q []byte) ([]byte, error) { asked++; return reply(q), nil }
	ask := func(name string, id uint16) *dnsmessage.Message {
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: id}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET}}}
		b, _ := q.Pack()
		out, err := f.AnswerDNS(context.Background(), b)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatal(err)
		}
		return &m
	}
	reply = func(q []byte) []byte { return mx(q, 5, "target.test.") }
	if m := ask("target.test.", 5); len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.MXResource).Pref != 10 {
		t.Fatalf("MX of an admitted name: %+v", m)
	}
	// SECURITY: an upstream answer to another question is dropped.
	reply = func(q []byte) []byte { return mx(q, 99, "evil.test.") }
	if m := ask("target.test.", 6); len(m.Answers) != 0 {
		t.Fatalf("a mismatched upstream answer was passed on: %+v", m)
	}
	before := asked
	if m := ask("exfil.example.", 7); m.RCode != dnsmessage.RCodeNameError || asked != before {
		t.Fatalf("an unadmitted name reached upstream (asked %d->%d) or answered %+v", before, asked, m.Header)
	}
}
