package adapt

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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

func runCanary(t *testing.T, rate *HostRate, s *scripted, header http.Header, until func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewCanary(rate, s.do, header).Run(ctx, []CanaryTarget{{Host: "a.example.com", URL: "https://a.example.com/"}}, 0)
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

// The canary's 429 answers lower the host's rate, and a run of them opens
// its breaker: the host is a throttled gap with the counts. The requests
// are plain GETs of the origin with the job's identification.
func TestCanaryPushbackLowersTheRateAndOpensTheBreaker(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200}, {status: 429, header: map[string]string{"Retry-After": "0"}}}}
	hdr := http.Header{"X-Scan-Id": {"job-1"}}
	runCanary(t, rate, s, hdr, func() bool { return rate.Summary().CircuitOpens > 0 })
	sum := rate.Summary()
	if len(sum.Gaps) != 1 || sum.Gaps[0].Reason != GapThrottled || !strings.Contains(sum.Gaps[0].Detail, "429=") {
		t.Fatalf("gaps %+v", sum.Gaps)
	}
	if sum.Backoffs == 0 || sum.Min >= 50 {
		t.Fatalf("the rate was not lowered: %+v", sum)
	}
	if sum.Canary == nil || sum.Canary.Hosts != 1 || sum.Canary.Pushback < TargetRate.ThrottleRun || sum.Canary.Probes < sum.Canary.Pushback {
		t.Fatalf("canary summary %+v", sum.Canary)
	}
	for _, r := range s.reqs {
		if r.Method != http.MethodGet || r.URL.String() != "https://a.example.com/" || r.Header.Get("X-Scan-Id") != "job-1" || r.Body != nil {
			t.Fatalf("canary request %s %s %v", r.Method, r.URL, r.Header)
		}
	}
}

// 503 with Retry-After and resets count too; while the breaker is open the
// canary sends nothing, and it is the probe that closes it again when the
// host answers normally.
func TestCanaryRespectsTheBreakerAndRecovers(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	answers := []canaryAnswer{{status: 200}}
	for range TargetRate.ThrottleRun {
		answers = append(answers, canaryAnswer{status: 503})
	}
	answers = append(answers, canaryAnswer{status: 200})
	s := &scripted{answers: answers}
	var held int
	runCanary(t, rate, s, nil, func() bool {
		sum := rate.Summary()
		if sum.CircuitOpens > 0 && held == 0 {
			held = s.count()
		}
		// Recovered: the breaker opened, then a probe got an ordinary
		// answer and several more went out.
		return sum.CircuitOpens > 0 && s.count() >= held+3
	})
	if held != 1+TargetRate.ThrottleRun {
		t.Fatalf("%d requests went out before the breaker opened, want %d", held, 1+TargetRate.ThrottleRun)
	}
	sum := rate.Summary()
	if sum.CircuitOpens != 1 || sum.Canary.Held == 0 {
		t.Fatalf("summary %+v canary %+v", sum, sum.Canary)
	}
	if err := rate.Acquire(t.Context(), "a.example.com"); err != nil {
		t.Fatalf("the breaker did not close after an ordinary answer: %v", err)
	}
}

func TestCanaryResetsAndTimeouts(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200}, {err: syscall.ECONNRESET}, {err: context.DeadlineExceeded}}}
	runCanary(t, rate, s, nil, func() bool { return rate.Summary().CircuitOpens > 0 })
	sum := rate.Summary()
	if len(sum.Gaps) != 1 || sum.Gaps[0].Reason != GapThrottled || sum.HostStats[0].Resets != 1 || sum.HostStats[0].Timeouts < 3 {
		t.Fatalf("summary %+v", sum)
	}
	if sum.Canary.Failed < TargetRate.BreakerFailures {
		t.Fatalf("canary %+v", sum.Canary)
	}
}

// A root that is forbidden from the first request on says nothing; one that
// was served and is forbidden later is a block. A vendor's block page is a
// block from the first answer.
func TestCanaryForbidden(t *testing.T) {
	fastCanary(t)
	t.Run("forbidden from the start is an answer", func(t *testing.T) {
		rate := NewHostRate(200)
		s := &scripted{answers: []canaryAnswer{{status: 403}}}
		runCanary(t, rate, s, nil, func() bool { return s.count() >= 3*TargetRate.ThrottleRun })
		if sum := rate.Summary(); sum.CircuitOpens != 0 || len(sum.Gaps) != 0 || sum.Backoffs != 0 {
			t.Fatalf("summary %+v", sum)
		}
	})
	t.Run("forbidden after it was served is a block", func(t *testing.T) {
		rate := NewHostRate(200)
		s := &scripted{answers: []canaryAnswer{{status: 200}, {status: 403}}}
		runCanary(t, rate, s, nil, func() bool { return rate.Summary().CircuitOpens > 0 })
		if sum := rate.Summary(); len(sum.Gaps) != 1 || sum.Gaps[0].Reason != GapBlocked {
			t.Fatalf("gaps %+v", sum.Gaps)
		}
	})
}

// A healthy host: nothing is lowered, and the canary sends about one
// request per interval, each counted against the host's rate.
func TestCanaryHealthyHostIsLeftAlone(t *testing.T) {
	fastCanary(t)
	rate := NewHostRate(200)
	s := &scripted{answers: []canaryAnswer{{status: 200, body: "<html>ok</html>"}}}
	start := time.Now()
	runCanary(t, rate, s, nil, func() bool { return s.count() >= 10 })
	if el := time.Since(start); el < 9*CanaryPace.Interval {
		t.Fatalf("10 requests in %v: faster than one per interval", el)
	}
	if sum := rate.Summary(); sum.Backoffs != 0 || sum.CircuitOpens != 0 || len(sum.Gaps) != 0 || sum.Canary.Pushback != 0 {
		t.Fatalf("summary %+v", sum)
	}
}
