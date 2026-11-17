package adapt

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/useragent"
)

func TestCanaryTargets(t *testing.T) {
	list, unwatched := CanaryTargets([]string{
		"https://a.example.com/login?x=1", "https://a.example.com:8443/other", "http://b.example.com:8080/x",
		"c.example.com", "c.example.com:443", "ftp://d.example.com/", "192.0.2.9", "https://[2001:db8::1]:8443/p", "",
	})
	want := []CanaryTarget{
		{Host: "a.example.com", URL: "https://a.example.com/"},
		{Host: "b.example.com", URL: "http://b.example.com:8080/"},
		{Host: "2001:db8::1", URL: "https://[2001:db8::1]:8443/"},
	}
	if !reflect.DeepEqual(list, want) {
		t.Fatalf("targets %+v\nwant %+v", list, want)
	}
	// c.example.com, d.example.com and 192.0.2.9 name no http(s) origin.
	if unwatched != 3 {
		t.Fatalf("unwatched = %d, want 3", unwatched)
	}
	var many []string
	for i := range CanaryPace.MaxHosts + 10 {
		many = append(many, "https://h"+strings.Repeat("x", i)+".example.com/")
	}
	if list, unwatched := CanaryTargets(many); len(list) != CanaryPace.MaxHosts || unwatched != 10 {
		t.Fatalf("bounded list: %d watched, %d unwatched", len(list), unwatched)
	}
}

// fastCanary shortens the canary's intervals and the controller's windows
// for a test and restores them after.
func fastCanary(t *testing.T) {
	t.Helper()
	oldC, oldR := CanaryPace, TargetRate
	CanaryPace.Interval, CanaryPace.FailInterval, CanaryPace.Timeout = 20*time.Millisecond, 10*time.Millisecond, time.Second
	TargetRate.Window, TargetRate.ThrottleSpacing = 20*time.Millisecond, 5*time.Millisecond
	TargetRate.BreakerOpen, TargetRate.BreakerOpenMax = 150*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { CanaryPace, TargetRate = oldC, oldR })
}

type canaryAnswer struct {
	status int
	header map[string]string
	body   string
	err    error
}

// scripted answers the canary's requests from a script (the last entry
// repeats) and records what was asked.
type scripted struct {
	mu      sync.Mutex
	answers []canaryAnswer
	n       int
	reqs    []*http.Request
}

func (s *scripted) do(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	a := s.answers[min(s.n, len(s.answers)-1)]
	s.n++
	s.reqs = append(s.reqs, req)
	s.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	h := http.Header{}
	for k, v := range a.header {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: a.status, Header: h, Body: io.NopCloser(strings.NewReader(a.body))}, nil
}

func (s *scripted) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func runCanary(t *testing.T, rate *HostRate, s *scripted, until func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewCanary(rate, s.do).Run(ctx, []CanaryTarget{{Host: "a.example.com", URL: "https://a.example.com/", Addrs: []string{"192.0.2.10"}}}, 0)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !until() {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("the canary did not get there: %+v", rate.Summary())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// SECURITY: the canary's 429 answers lower the host's rate and never open
// its breaker, however many there are: a host that recognizes the canary
// cannot end its own scan through it. The tool's connections keep going
// out, and the push-back reaches the address the host is reached at too.
func TestCanaryPushbackSlowsAndNeverOpensTheBreaker(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200}, {status: 429, header: map[string]string{"Retry-After": "300"}}}}
	runCanary(t, rate, s, func() bool { return s.count() >= 1+6*TargetRate.ThrottleRun })
	sum := rate.Summary()
	if sum.CircuitOpens != 0 || sum.GapsTotal != 0 {
		t.Fatalf("the canary alone opened the breaker or made a gap: %+v", sum)
	}
	if sum.Backoffs == 0 || sum.Min >= 50 {
		t.Fatalf("the rate was not lowered: %+v", sum)
	}
	if sum.Canary == nil || sum.Canary.Hosts != 1 || sum.Canary.Pushback < 6*TargetRate.ThrottleRun-1 || sum.Canary.Probes < sum.Canary.Pushback {
		t.Fatalf("canary summary %+v", sum.Canary)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := rate.Acquire(ctx, "a.example.com"); err != nil {
		t.Fatalf("a tool connection was refused or held for the canary's Retry-After: %v", err)
	}
	// The address the host is reached at was slowed too.
	if got := rate.Rate("192.0.2.10"); got >= 50 {
		t.Fatalf("the address's rate is %.3g", got)
	}
	if err := rate.AcquireAddr(ctx, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
}

// The canary's request is the same for every job: GET of the origin's
// root, no query, no body, and no header besides the sensor's own
// User-Agent. Nothing a job or a platform setting says is on it.
func TestCanaryRequestIsFixed(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// The origin a target named carries a path, a query and user info:
		// none of them reaches the request.
		NewCanary(rate, s.do).Run(ctx, []CanaryTarget{{Host: "a.example.com", URL: "https://user:pw@a.example.com:8443/admin?scan=job-1#x"}}, 0)
		close(done)
	}()
	for s.count() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reqs {
		if r.Method != http.MethodGet || r.URL.String() != "https://a.example.com:8443/" || r.Body != nil {
			t.Fatalf("canary request %s %s", r.Method, r.URL)
		}
		if len(r.Header) != 1 || r.Header.Get("User-Agent") != useragent.String() {
			t.Fatalf("canary headers %v", r.Header)
		}
	}
}

// What reaches the wire: the request line, Host and the User-Agent, and
// nothing else (the transport adds no header of its own).
func TestCanaryRequestOnTheWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			head.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		got <- head.String()
	}()
	do, release := CanaryDo(func(ctx context.Context, _ string, _ int) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}, nil)
	defer release()
	req, err := canaryRequest(t.Context(), "http://a.example.com/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	want := "GET / HTTP/1.1\r\nHost: a.example.com\r\nUser-Agent: " + useragent.String() + "\r\n\r\n"
	if head := <-got; head != want {
		t.Fatalf("on the wire:\n%q\nwant\n%q", head, want)
	}
}

// While the host's breaker is open (opened by the tool's own traffic) the
// canary sends nothing and does not move the breaker; it goes on when the
// breaker closed again.
func TestCanaryWaitsWhileTheBreakerIsOpen(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200}}}
	for range TargetRate.ThrottleRun {
		rate.ReportHTTP("a.example.com", 503, "")
		time.Sleep(TargetRate.ThrottleSpacing)
	}
	if rate.Summary().CircuitOpens != 1 {
		t.Fatalf("setup: %+v", rate.Summary())
	}
	began := time.Now()
	runCanary(t, rate, s, func() bool { return time.Since(began) > 80*time.Millisecond })
	sum := rate.Summary()
	if s.count() != 0 || sum.Canary.Held == 0 || sum.CircuitOpens != 1 {
		t.Fatalf("the canary sent %d request(s) to a host whose breaker is open: %+v", s.count(), sum.Canary)
	}
}

// Resets and timeouts of the canary's request, from a host that served it
// before, lower the rate and open nothing.
func TestCanaryResetsAndTimeouts(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200}, {err: syscall.ECONNRESET}, {err: context.DeadlineExceeded}}}
	runCanary(t, rate, s, func() bool { return s.count() >= 2+2*TargetRate.BreakerFailures })
	sum := rate.Summary()
	if sum.CircuitOpens != 0 || sum.GapsTotal != 0 || sum.Backoffs == 0 {
		t.Fatalf("summary %+v", sum)
	}
	var host HostStat
	for _, hs := range sum.HostStats {
		if hs.Host == "a.example.com" {
			host = hs
		}
	}
	if host.Resets != 1 || host.Timeouts < 3 || sum.Canary.Failed < TargetRate.BreakerFailures {
		t.Fatalf("host stats %+v canary %+v", sum.HostStats, sum.Canary)
	}
}

// A root that is forbidden from the first request on says nothing; one that
// was served and is forbidden later, and a vendor's block page, lower the
// rate. Neither blocks the host by itself.
func TestCanaryForbidden(t *testing.T) {
	fastCanary(t)
	t.Run("forbidden from the start is an answer", func(t *testing.T) {
		rate := NewHostRate(200)
		s := &scripted{answers: []canaryAnswer{{status: 403}}}
		runCanary(t, rate, s, func() bool { return s.count() >= 3*TargetRate.ThrottleRun })
		if sum := rate.Summary(); sum.CircuitOpens != 0 || len(sum.Gaps) != 0 || sum.Backoffs != 0 {
			t.Fatalf("summary %+v", sum)
		}
	})
	t.Run("forbidden after it was served slows", func(t *testing.T) {
		rate := NewHostRate(200)
		s := &scripted{answers: []canaryAnswer{{status: 200}, {status: 403}}}
		runCanary(t, rate, s, func() bool { return s.count() >= 1+3*TargetRate.ThrottleRun })
		if sum := rate.Summary(); sum.CircuitOpens != 0 || sum.GapsTotal != 0 || sum.Backoffs == 0 || sum.Canary.Pushback == 0 {
			t.Fatalf("summary %+v canary %+v", sum, sum.Canary)
		}
	})
	t.Run("with the tool's connections failing it is a block", func(t *testing.T) {
		rate := NewHostRate(200)
		rate.Report("a.example.com", Event{Signal: Connected})
		for range TargetRate.CorroborateFailures {
			rate.Report("a.example.com", Event{Signal: Failed, Reason: ReasonReset})
		}
		s := &scripted{answers: []canaryAnswer{{status: 200}, {status: 403}}}
		runCanary(t, rate, s, func() bool { return rate.Summary().CircuitOpens > 0 })
		sum := rate.Summary()
		var opened string
		for _, hs := range sum.HostStats {
			if hs.Host == "a.example.com" {
				opened = hs.OpenedBy
			}
		}
		if len(sum.Gaps) != 1 || sum.Gaps[0].Reason != GapBlocked || opened != EvidenceCanaryAndConnection {
			t.Fatalf("summary %+v", sum)
		}
	})
}

// A healthy host: nothing is lowered, and the canary sends about one
// request per interval, each counted against the host's rate.
func TestCanaryHealthyHostIsLeftAlone(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200, body: "<html>ok</html>"}}}
	began := time.Now()
	runCanary(t, rate, s, func() bool { return s.count() >= 10 })
	if el := time.Since(began); el < 9*CanaryPace.Interval {
		t.Fatalf("10 requests in %v: faster than one per interval", el)
	}
	if sum := rate.Summary(); sum.Backoffs != 0 || sum.CircuitOpens != 0 || len(sum.Gaps) != 0 || sum.Canary.Pushback != 0 {
		t.Fatalf("summary %+v", sum)
	}
}
