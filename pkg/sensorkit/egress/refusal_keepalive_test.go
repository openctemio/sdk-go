package egress

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tunnelConn opens a CONNECT tunnel to app.test:port through the forwarder,
// optionally TLS inside it (the forwarder terminates it).
func tunnelConn(t *testing.T, pa string, port int, useTLS bool) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT app.test:%d HTTP/1.1\r\nHost: app.test\r\n\r\n", port)
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	if !useTLS {
		return c, br
	}
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: "app.test", InsecureSkipVerify: true}) //nolint:gosec // test: a scanner's client
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc, bufio.NewReader(tc)
}

// roundTrip sends one raw request on c and reads its answer (nil: the
// connection closed or no answer came).
func roundTrip(t *testing.T, c net.Conn, br *bufio.Reader, raw string) *http.Response {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		return nil
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

// SECURITY: a refused request gets a complete 403 marked as the
// forwarder's, its body is discarded (never sent upstream), and the
// connection stays open: the next allowed request on the SAME connection is
// served, in clear and on the TLS-terminated path. A tool's per-host error
// budget therefore never counts a refusal as a broken host.
func TestRefusalKeepsTheConnection(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "tls"}[useTLS], func(t *testing.T) {
			s := &webSite{}
			var srv *httptest.Server
			if useTLS {
				srv = httptest.NewTLSServer(s.handler())
			} else {
				srv = httptest.NewServer(s.handler())
			}
			defer srv.Close()
			port := portOf(t, srv.URL)
			f, pa := webForwarder(t, testWebScope)
			if useTLS {
				if err := f.CreateAuthority(); err != nil {
					t.Fatal(err)
				}
			}
			c, br := tunnelConn(t, pa, port, useTLS)
			h := "app.test:" + strconv.Itoa(port)
			steps := []struct {
				raw  string
				want int
			}{
				{"GET /public/a HTTP/1.1\r\nHost: " + h + "\r\n\r\n", 200},
				{"GET /admin/x HTTP/1.1\r\nHost: " + h + "\r\n\r\n", 403},
				{"POST /admin/x HTTP/1.1\r\nHost: " + h + "\r\nContent-Length: 11\r\n\r\nuser=secret", 403},
				{"POST /admin/y HTTP/1.1\r\nHost: " + h + "\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 403},
				{"GET /public/b HTTP/1.1\r\nHost: " + h + "\r\n\r\n", 200},
			}
			for i, st := range steps {
				resp := roundTrip(t, c, br, st.raw)
				if resp == nil {
					t.Fatalf("step %d: no answer: the connection closed", i)
				}
				if resp.StatusCode != st.want {
					t.Fatalf("step %d: %d, want %d", i, resp.StatusCode, st.want)
				}
				if st.want == 403 && (resp.Header.Get("X-Openctem-Egress") != "refused" || resp.Close || resp.ContentLength <= 0) {
					t.Fatalf("step %d: refusal %+v, want a complete keep-alive 403 marked refused", i, resp.Header)
				}
			}
			s.assertNoDenied(t)
			if got := strings.Join(s.served(), ","); got != "GET /public/a,GET /public/b" {
				t.Fatalf("the server saw %s", got)
			}
		})
	}
}

// After a refusal the connection closes when keeping it would mean reading
// an unbounded body, waiting for a body the client holds back, or ignoring
// the client's own close: the request behind it is not answered.
func TestRefusalClosesWhenItMust(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	_, pa := webForwarder(t, testWebScope)
	h := "app.test:" + strconv.Itoa(port)
	big := strings.Repeat("a", maxRefusedBody+10)
	for name, raw := range map[string]string{
		"large body":   "POST /admin HTTP/1.1\r\nHost: " + h + "\r\nContent-Length: " + strconv.Itoa(len(big)) + "\r\n\r\n" + big,
		"expect":       "POST /admin HTTP/1.1\r\nHost: " + h + "\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
		"client close": "GET /admin HTTP/1.1\r\nHost: " + h + "\r\nConnection: close\r\n\r\n",
		"other host":   "GET /public/a HTTP/1.1\r\nHost: evil.test:" + strconv.Itoa(port) + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, br := tunnelConn(t, pa, port, false)
			resp := roundTrip(t, c, br, raw)
			if resp == nil || resp.StatusCode != 403 || !resp.Close {
				t.Fatalf("want a 403 that closes the connection, got %+v", resp)
			}
			if again := roundTrip(t, c, br, "GET /public/a HTTP/1.1\r\nHost: "+h+"\r\n\r\n"); again != nil {
				t.Fatalf("the connection stayed open: %d", again.StatusCode)
			}
		})
	}
	s.assertNoDenied(t)
}
