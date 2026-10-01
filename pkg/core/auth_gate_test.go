package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// statusErr mimics *client.HTTPError.
type statusErr struct{ code int }

func (e *statusErr) Error() string       { return fmt.Sprintf("http %d", e.code) }
func (e *statusErr) HTTPStatusCode() int { return e.code }

func newTestGate(t *testing.T) (*AuthGate, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	g := NewAuthGate(&AuthGateConfig{Logger: log.New(buf, "", 0)})
	g.jitter = func(d time.Duration) time.Duration { return d }
	return g, buf
}

func lines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestAuthFailureStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{errors.New("dial tcp: connection refused"), 0},
		{&statusErr{401}, 401},
		{&statusErr{403}, 403},
		{&statusErr{404}, 0},
		{&statusErr{500}, 0},
		{fmt.Errorf("request failed after 3 retries: %w", &statusErr{401}), 401},
	}
	for _, c := range cases {
		if got := AuthFailureStatus(c.err); got != c.want {
			t.Errorf("AuthFailureStatus(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestAPIKeyHint(t *testing.T) {
	key := "rda_5d221b75e7c2c415af4ef576b6ecc6993539ae83aba2c94d12074a3060c49c70"
	if got := APIKeyHint(key); got != "rda_5d22…" {
		t.Errorf("hint %q", got)
	}
	// Never more than half of a short key.
	if got := APIKeyHint("rda_bogus"); got != "rda_…" {
		t.Errorf("short key hint %q", got)
	}
	if got := APIKeyHint(""); got != "(none)" {
		t.Errorf("empty key hint %q", got)
	}
}

func TestAuthGate_RejectedBacksOffAndRecovers(t *testing.T) {
	g, buf := newTestGate(t)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		if got := g.Observe(&statusErr{401}, "rda_ab12…"); got != w {
			t.Fatalf("rejection %d: backoff %v, want %v", i+1, got, w)
		}
		if !g.Rejected() {
			t.Fatal("gate must report rejected")
		}
	}
	logged := lines(buf.String())
	if len(logged) != len(want) {
		t.Fatalf("want one log line per backoff step (%d), got %d:\n%s", len(want), len(logged), buf.String())
	}
	first := logged[0]
	for _, part := range []string{"HTTP 401", "rda_ab12…", "Settings → Sensors", "API_KEY", "next check in 30s", "attempt 1"} {
		if !strings.Contains(first, part) {
			t.Errorf("log line lacks %q: %s", part, first)
		}
	}

	if got := g.Observe(nil, "rda_ab12…"); got != 0 {
		t.Fatalf("accepted heartbeat must not override the interval, got %v", got)
	}
	if g.Rejected() {
		t.Fatal("accepted heartbeat must lift the rejection")
	}
	if !strings.Contains(buf.String(), "accepted the API key again") {
		t.Errorf("recovery not logged:\n%s", buf.String())
	}
	// The backoff starts over after a recovery.
	if got := g.Observe(&statusErr{403}, "k"); got != 30*time.Second {
		t.Errorf("backoff after recovery %v, want 30s", got)
	}
}

func TestAuthGate_JitterStaysWithinCap(t *testing.T) {
	g := NewAuthGate(&AuthGateConfig{Logger: log.New(&syncBuffer{}, "", 0)})
	for range 50 {
		d := g.Observe(&statusErr{401}, "k")
		if d <= 0 || d > DefaultAuthBackoffMax {
			t.Fatalf("backoff %v outside (0, %v]", d, DefaultAuthBackoffMax)
		}
	}
}

func TestAuthGate_UnreachableLogsSparselyAndKeepsInterval(t *testing.T) {
	g, buf := newTestGate(t)
	for range 9 {
		if d := g.Observe(errors.New("connection refused"), "k"); d != 0 {
			t.Fatalf("network failure must keep the normal interval, got %v", d)
		}
	}
	if g.Rejected() {
		t.Fatal("a network failure is not an auth rejection")
	}
	// Logged at failures 1, 2, 4 and 8 only.
	if n := len(lines(buf.String())); n != 4 {
		t.Fatalf("want 4 log lines for 9 failures, got %d:\n%s", n, buf.String())
	}
	g.Observe(nil, "k")
	if !strings.Contains(buf.String(), "reachable again after 9") {
		t.Errorf("recovery not logged:\n%s", buf.String())
	}
}

func TestAuthGate_MarkRejectedLogsOnce(t *testing.T) {
	g, buf := newTestGate(t)
	g.MarkRejected(errors.New("timeout"), "k")
	if g.Rejected() {
		t.Fatal("non-auth poll errors must not mark rejected")
	}
	for range 3 {
		g.MarkRejected(&statusErr{401}, "k")
	}
	if !g.Rejected() {
		t.Fatal("401 poll must mark rejected")
	}
	if n := len(lines(buf.String())); n != 1 {
		t.Fatalf("want 1 log line, got %d:\n%s", n, buf.String())
	}
}

// --- base sensor + poller ----------------------------------------------------

// authPusher answers heartbeats with err() (nil: accepted with hints).
type authPusher struct {
	mu    sync.Mutex
	err   error
	beats atomic.Int32
}

func (p *authPusher) setErr(err error) { p.mu.Lock(); p.err = err; p.mu.Unlock() }
func (p *authPusher) SendHeartbeatWithHints(context.Context, *SensorStatus) (*HeartbeatHints, error) {
	p.beats.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	return &HeartbeatHints{Present: true, NextHeartbeat: 30 * time.Second}, nil
}
func (p *authPusher) SendHeartbeat(ctx context.Context, s *SensorStatus) error {
	_, err := p.SendHeartbeatWithHints(ctx, s)
	return err
}
func (p *authPusher) PushFindings(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *authPusher) PushAssets(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *authPusher) TestConnection(context.Context) error { return nil }
func (p *authPusher) APIKeyHint() string                   { return "rda_ab12…" }

func TestBaseSensor_RejectedHeartbeatBacksOffAndStopsPolling(t *testing.T) {
	for _, withDoorbell := range []bool{true, false} {
		t.Run(fmt.Sprintf("doorbell=%v", withDoorbell), func(t *testing.T) {
			p := &authPusher{}
			s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Minute}, p)
			gate, buf := newTestGate(t)
			s.SetAuthGate(gate)

			cc := &countingCommandClient{cmds: make(chan *Command, 1)}
			poller := NewCommandPoller(cc, &recordingExecutor{ran: make(chan string, 1)}, nil)
			if withDoorbell {
				d, _ := newTestDoorbell(t, nil)
				s.SetDoorbell(d)
				poller.SetDoorbell(d) // gets the gate through the doorbell
			} else {
				poller.SetAuthGate(s.AuthGate())
			}
			ctx := context.Background()

			// Accepted: normal (advised or configured) interval, polling on.
			next := s.sendHeartbeat(ctx)
			if next != 30*time.Second && next != time.Minute {
				t.Fatalf("accepted heartbeat: next %v", next)
			}
			poller.pollAndExecute(ctx)
			if cc.polls.Load() != 1 {
				t.Fatalf("polls %d, want 1", cc.polls.Load())
			}

			// Revoked: backoff replaces the interval, polling stops.
			p.setErr(fmt.Errorf("request failed: %w", &statusErr{401}))
			if next := s.sendHeartbeat(ctx); next != 30*time.Second {
				t.Fatalf("first rejection: next %v, want 30s backoff", next)
			}
			if next := s.sendHeartbeat(ctx); next != time.Minute {
				t.Fatalf("second rejection: next %v, want 1m backoff", next)
			}
			for range 3 {
				poller.pollAndExecute(ctx)
			}
			if cc.polls.Load() != 1 {
				t.Fatalf("poller polled with a rejected key: %d polls", cc.polls.Load())
			}
			if !strings.Contains(buf.String(), "HTTP 401, key rda_ab12…") {
				t.Errorf("rejection not logged with the key hint:\n%s", buf.String())
			}

			// Re-activated: polling resumes with the first accepted heartbeat.
			p.setErr(nil)
			s.sendHeartbeat(ctx)
			poller.pollAndExecute(ctx)
			if cc.polls.Load() != 2 {
				t.Fatalf("polling did not resume: %d polls", cc.polls.Load())
			}
		})
	}
}

// rejectingCommandClient rejects every poll with 401.
type rejectingCommandClient struct{ countingCommandClient }

func (c *rejectingCommandClient) GetCommands(context.Context) (*GetCommandsResponse, error) {
	c.polls.Add(1)
	return nil, &statusErr{401}
}

func TestCommandPoller_StandaloneBacksOffOnRejection(t *testing.T) {
	cc := &rejectingCommandClient{}
	p := NewCommandPoller(cc, &recordingExecutor{ran: make(chan string, 1)}, nil)
	buf := &syncBuffer{}
	p.ownGate = NewAuthGate(&AuthGateConfig{Logger: log.New(buf, "", 0)})
	ctx := context.Background()
	for range 5 {
		p.pollAndExecute(ctx)
	}
	if n := cc.polls.Load(); n != 1 {
		t.Fatalf("a poller without a heartbeat gate must back off after a 401: %d polls", n)
	}
	if n := len(lines(buf.String())); n != 1 {
		t.Fatalf("want 1 log line, got %d:\n%s", n, buf.String())
	}
	if !p.ownNext.After(time.Now().Add(20 * time.Second)) {
		t.Errorf("next poll at %v, want >= ~24s ahead", p.ownNext)
	}
}

func TestBaseSensor_StopSkipsFinalHeartbeatWhenRejected(t *testing.T) {
	p := &authPusher{}
	p.setErr(&statusErr{401})
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	gate, _ := newTestGate(t)
	s.SetAuthGate(gate)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for p.beats.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for !gate.Rejected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = s.Stop(context.Background())
	if n := p.beats.Load(); n != 1 {
		t.Fatalf("heartbeats %d, want 1 (no final heartbeat with a rejected key)", n)
	}
}

func TestBaseSensor_FirstHeartbeatIsNotRepeatedByStart(t *testing.T) {
	p := &authPusher{}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	d, _ := newTestDoorbell(t, nil)
	s.SetDoorbell(d)
	next, err := s.FirstHeartbeat(context.Background())
	if err != nil || next != 30*time.Second {
		t.Fatalf("FirstHeartbeat = %v, %v; want the advised 30s, nil", next, err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_ = s.Stop(context.Background())
	// FirstHeartbeat + the final heartbeat on Stop; Start sent none.
	if n := p.beats.Load(); n != 2 {
		t.Fatalf("heartbeats %d, want 2 (first + final), Start must not send one at once", n)
	}

	// A rejected first heartbeat returns the backoff and the error.
	p2 := &authPusher{}
	p2.setErr(&statusErr{401})
	s2 := NewBaseSensor(&BaseSensorConfig{Name: "t2"}, p2)
	gate, _ := newTestGate(t)
	s2.SetAuthGate(gate)
	next, err = s2.FirstHeartbeat(context.Background())
	if AuthFailureStatus(err) != 401 || next != 30*time.Second {
		t.Fatalf("rejected FirstHeartbeat = %v, %v", next, err)
	}
}

func TestAuthFailureAdvice(t *testing.T) {
	rejected := AuthFailureAdvice(&statusErr{401}, "rda_ab12…")
	for _, part := range []string{"rejected the API key", "HTTP 401", "rda_ab12…", "Settings → Sensors", "API_KEY"} {
		if !strings.Contains(rejected, part) {
			t.Errorf("advice lacks %q: %s", part, rejected)
		}
	}
	// The key never reached the API (web UI origin, header-stripping proxy).
	stripped := AuthFailureAdvice(fmt.Errorf("request failed: %w", &bodyStatusErr{401, `{"code":"UNAUTHORIZED","message":"API key required"}`}), "rda_ab12…")
	for _, part := range []string{"never reached the API", "web UI", "Authorization header", "API_URL", "rda_ab12…"} {
		if !strings.Contains(stripped, part) {
			t.Errorf("stripped-key advice lacks %q: %s", part, stripped)
		}
	}
	if strings.Contains(stripped, "regenerate") {
		t.Errorf("a key that never arrived must not be blamed: %s", stripped)
	}
}

// bodyStatusErr mimics *client.HTTPError, whose message includes the body.
type bodyStatusErr struct {
	code int
	body string
}

func (e *bodyStatusErr) Error() string       { return fmt.Sprintf("http %d: %s", e.code, e.body) }
func (e *bodyStatusErr) HTTPStatusCode() int { return e.code }
