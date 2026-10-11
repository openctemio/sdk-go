package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// A target answering 429 with Retry-After slows the host down and holds
// the next connection until the Retry-After has passed; the response
// reaches the tool unchanged.
func TestForwarderBacksOffOn429(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "slow down")
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{Rate: 40})
	var changes []adapt.Change
	f.TargetRate().OnChange = func(c adapt.Change) { changes = append(changes, c) }
	pu, _ := url.Parse("http://" + serve(t, f))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}, Timeout: 10 * time.Second}

	resp, err := client.Get(srv.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || string(body) != "slow down" || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("429 not passed on unchanged: %d %q %q", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
	start := time.Now()
	resp, err = client.Get(srv.URL + "/b")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("second answer %q", body)
	}
	if el := time.Since(start); el < 800*time.Millisecond {
		t.Fatalf("next connection after Retry-After: 1 went out after %v", el)
	}
	s := f.TargetRate().Summary()
	if s.Throttled != 1 || s.Ceiling != 40 || s.Min != 5 {
		t.Fatalf("summary %+v, want the host throttled from 10 to 5 under a ceiling of 40", s)
	}
	if len(changes) == 0 || changes[0].Reason != adapt.ReasonHTTP429 {
		t.Fatalf("changes %+v, want a http_429 decrease", changes)
	}
}

// resetServer accepts the first connection normally (the port answers),
// then resets every further one.
func resetServer(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if n.Add(1) == 1 {
				go func() {
					defer c.Close()
					line, _ := bufio.NewReader(c).ReadString('\n')
					_, _ = io.WriteString(c, "echo:"+line)
				}()
				continue
			}
			_ = c.(*net.TCPConn).SetLinger(0)
			_ = c.Close()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// A host that resets connection after connection trips its breaker: the
// forwarder then refuses connections to it (503) instead of hammering it,
// and the host is a coverage gap of the task.
func TestForwarderBreakerOnResets(t *testing.T) {
	host, port := resetServer(t)
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{})
	proxyAddr := serve(t, f)
	target := fmt.Sprintf("%s:%d", host, port)
	if got := connect(t, proxyAddr, target); got != "echo:hi\n" {
		t.Fatalf("first connection: %q", got)
	}
	var refused string
	for range 3 * adapt.TargetRate.BreakerFailures {
		got := connect(t, proxyAddr, target)
		if strings.HasPrefix(got, "503") {
			refused = got
			break
		}
	}
	if refused == "" {
		t.Fatalf("the breaker never opened: %+v", f.TargetRate().Summary())
	}
	gaps, total := f.TargetRate().Gaps()
	if total != 1 || gaps[0].Host != host || gaps[0].Reason != adapt.GapBreakerOpen {
		t.Fatalf("gaps %+v (%d), want %s breaker_open", gaps, total, host)
	}
}

// A port that never answered (closed) does not slow the host: a port scan
// meets thousands of them.
func TestForwarderClosedPortsAreNotPushBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // now closed: connections are refused
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{})
	proxyAddr := serve(t, f)
	for range 2 * adapt.TargetRate.BreakerFailures {
		if got := connect(t, proxyAddr, fmt.Sprintf("127.0.0.1:%d", port)); !strings.HasPrefix(got, "502") {
			t.Fatalf("closed port: %q, want 502", got)
		}
	}
	if s := f.TargetRate().Summary(); s.Throttled != 0 || s.GapsTotal != 0 {
		t.Fatalf("closed port throttled the host: %+v", s)
	}
}
