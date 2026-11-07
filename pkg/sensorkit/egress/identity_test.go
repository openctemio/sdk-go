package egress

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// identSite records what each request carried.
type identSite struct {
	mu   sync.Mutex
	seen []string
}

func (s *identSite) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		s.mu.Lock()
		s.seen = append(s.seen, fmt.Sprintf("%s|%s|%s|%s|%s", host, r.UserAgent(), r.Header.Get("X-Pentest-Id"), r.URL.Query().Get("pentest_id"), r.URL.Query().Get("q")))
		s.mu.Unlock()
		fmt.Fprint(w, "ok")
	})
}

func (s *identSite) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func identForwarder(t *testing.T) (*Forwarder, string) {
	t.Helper()
	ua := map[string]string{"app.test": "UA-app", "other.test": "UA-other"}
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}, "other.test": {addr("127.0.0.1")}},
		Identity: &Identity{Headers: map[string]string{"X-Pentest-Id": "pt-1"}, QueryName: "pentest_id", QueryValue: "pt-1",
			UserAgent: func(host string) string {
				h, _, err := net.SplitHostPort(host)
				if err != nil {
					h = host
				}
				return ua[strings.ToLower(h)]
			}}}, Limits{})
	return f, serve(t, f)
}

// SECURITY: the forwarder puts the identification on every request of a
// tool that sends none (or a forged one): plain HTTP, HTTPS through a
// tunnel (TLS terminated with the forwarder's authority), each host with
// its own User-Agent, the tool's own values replaced.
func TestForwarderAddsTheIdentification(t *testing.T) {
	s := &identSite{}
	plain := httptest.NewServer(s.handler())
	defer plain.Close()
	secure := httptest.NewTLSServer(s.handler())
	defer secure.Close()
	f, pa := identForwarder(t)
	if err := f.CreateAuthority(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.AuthorityPEM())
	c := proxiedClient(t, pa, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	for _, base := range []string{"http://app.test:" + strconv.Itoa(portOf(t, plain.URL)), "https://app.test:" + strconv.Itoa(portOf(t, secure.URL)),
		"https://other.test:" + strconv.Itoa(portOf(t, secure.URL))} {
		for _, path := range []string{"/a", "/b?q=1", "/c?pentest_id=forged&q=2"} {
			req, _ := http.NewRequest(http.MethodGet, base+path, nil)
			req.Header.Set("User-Agent", "tool-own/1")
			req.Header.Set("x-pentest-id", "forged")
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("%s%s: %v", base, path, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("%s%s: %d", base, path, resp.StatusCode)
			}
		}
	}
	got := s.requests()
	if len(got) != 9 {
		t.Fatalf("the servers saw %d requests: %q", len(got), got)
	}
	for i, r := range got {
		host := "app.test"
		if i >= 6 {
			host = "other.test"
		}
		want := map[string]string{"app.test": "UA-app", "other.test": "UA-other"}[host]
		q := []string{"", "1", "2"}[i%3]
		if r != fmt.Sprintf("%s|%s|pt-1|pt-1|%s", host, want, q) {
			t.Errorf("request %d carried %q", i, r)
		}
	}
}

// SECURITY: with the identification at the forwarder, nothing that is
// not an HTTP/1.x request reaches the target: raw bytes, HTTP/2 and a
// protocol upgrade are refused, so no request leaves without it.
func TestForwarderIdentityRefusesWhatItCannotMark(t *testing.T) {
	var mu sync.Mutex
	var got [][]byte
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				b := make([]byte, 512)
				n, _ := c.Read(b)
				if n > 0 {
					mu.Lock()
					got = append(got, b[:n])
					mu.Unlock()
				}
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	_, pa := identForwarder(t)
	for _, payload := range []string{
		"\x00\x01\x02\x03",                 // raw bytes
		"SSH-2.0-OpenSSH_9.6\r\n",          // another protocol
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", // HTTP/2
		"GET / HTTP/1.1\r\nHost: app.test:" + strconv.Itoa(port) + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
	} {
		c, err := net.Dial("tcp", pa)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "CONNECT app.test:%d HTTP/1.1\r\nHost: app.test\r\n\r\n%s", port, payload)
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Read(buf)
		_ = c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("the target received %d unmarked payload(s): %q", len(got), got)
	}
}
