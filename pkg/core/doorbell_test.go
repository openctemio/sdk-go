package core

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestParseHeartbeatHints(t *testing.T) {
	cases := []struct {
		name string
		body string
		want HeartbeatHints
	}{
		{"v1 server", `{"agent_id":"a","status":"ok","tenant_id":"t"}`, HeartbeatHints{}},
		{"empty", ``, HeartbeatHints{}},
		{"not json", `<html>`, HeartbeatHints{}},
		{"idle aware", `{"status":"ok","next_heartbeat_seconds":30,"config_version":"0123456789abcdef"}`,
			HeartbeatHints{Present: true, NextHeartbeat: 30 * time.Second, ConfigVersion: "0123456789abcdef"}},
		{"work waiting", `{"pending_jobs":3,"next_heartbeat_seconds":5}`,
			HeartbeatHints{Present: true, PendingJobs: 3, NextHeartbeat: 5 * time.Second}},
		{"pending capped", `{"pending_jobs":100000}`, HeartbeatHints{Present: true, PendingJobs: MaxDoorbellPendingJobs}},
		{"negative pending dropped", `{"pending_jobs":-4}`, HeartbeatHints{Present: true}},
		{"interval below floor", `{"next_heartbeat_seconds":1}`, HeartbeatHints{Present: true, NextHeartbeat: MinDoorbellHeartbeatInterval}},
		{"interval above ceiling", `{"next_heartbeat_seconds":999999999}`, HeartbeatHints{Present: true, NextHeartbeat: MaxDoorbellHeartbeatInterval}},
		{"zero interval ignored", `{"next_heartbeat_seconds":0}`, HeartbeatHints{Present: true}},
		{"malformed config version dropped", `{"config_version":"rm -rf /"}`, HeartbeatHints{Present: true}},
		{"actions", `{"actions":["pause","rotate_key","bogus"]}`,
			HeartbeatHints{Present: true, Actions: []HeartbeatAction{"pause", "rotate_key", "bogus"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseHeartbeatHints([]byte(tc.body))
			if got.Present != tc.want.Present || got.PendingJobs != tc.want.PendingJobs ||
				got.NextHeartbeat != tc.want.NextHeartbeat || got.ConfigVersion != tc.want.ConfigVersion ||
				strings.Join(actionStrings(got.Actions), ",") != strings.Join(actionStrings(tc.want.Actions), ",") {
				t.Errorf("got %+v, want %+v", *got, tc.want)
			}
		})
	}
}

func newTestDoorbell(t *testing.T, onRotate func()) (*Doorbell, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	return NewDoorbell(&DoorbellConfig{OnRotateKey: onRotate, Logger: log.New(buf, "", 0)}), buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func woke(d *Doorbell) bool {
	select {
	case <-d.Wake():
		return true
	default:
		return false
	}
}

func TestDoorbell_PendingJobsWakesPoller(t *testing.T) {
	d, _ := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true, NextHeartbeat: 30 * time.Second})
	if woke(d) {
		t.Fatal("idle heartbeat must not wake the poller")
	}
	if !d.HintsActive() {
		t.Fatal("hints present: doorbell should be active")
	}
	d.Handle(&HeartbeatHints{Present: true, PendingJobs: 2})
	d.Handle(&HeartbeatHints{Present: true, PendingJobs: 2}) // collapses into one wake
	if !woke(d) {
		t.Fatal("pending_jobs > 0 must wake the poller")
	}
	if woke(d) {
		t.Fatal("wakes must collapse into one")
	}
}

func TestDoorbell_PauseResume(t *testing.T) {
	d, logs := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionPause}, PendingJobs: 3})
	if !d.Paused() || d.State() != "paused by platform" {
		t.Fatalf("want paused, state %q", d.State())
	}
	if woke(d) {
		t.Fatal("a paused sensor must not be woken to claim work")
	}
	// Still paused while the platform keeps saying so.
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionPause}})
	if !d.Paused() {
		t.Fatal("pause must hold while sent")
	}
	// pause wins over resume in the same answer.
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionResume, HeartbeatActionPause}})
	if !d.Paused() {
		t.Fatal("pause must win over resume")
	}
	// First answer without pause lifts it.
	d.Handle(&HeartbeatHints{Present: true, NextHeartbeat: 30 * time.Second})
	if d.Paused() || d.State() != "running" {
		t.Fatal("first heartbeat without pause must resume")
	}
	// Explicit resume.
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionPause}})
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionResume}})
	if d.Paused() {
		t.Fatal("resume must lift the pause")
	}
	if n := strings.Count(logs.String(), "paused by platform"); n != 2 {
		t.Errorf("pause transitions logged %d times, want 2:\n%s", n, logs)
	}
	// A failed heartbeat keeps the pause.
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionPause}})
	d.HeartbeatFailed()
	if !d.Paused() {
		t.Fatal("a failed heartbeat must not lift the pause")
	}
}

func TestDoorbell_DrainIsFinal(t *testing.T) {
	d, _ := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionDrain}})
	for _, h := range []*HeartbeatHints{
		{Present: true},
		{Present: true, Actions: []HeartbeatAction{HeartbeatActionResume}},
		nil,
	} {
		d.Handle(h)
		if !d.Paused() || !d.Draining() || d.State() != "draining by platform" {
			t.Fatalf("drain must be final, state %q", d.State())
		}
	}
	d.Handle(&HeartbeatHints{Present: true, PendingJobs: 5})
	if woke(d) {
		t.Fatal("a drained sensor must not be woken")
	}
}

func TestDoorbell_RotateKeyCallsRenewal(t *testing.T) {
	var calls atomic.Int32
	done := make(chan struct{}, 4)
	d, _ := newTestDoorbell(t, func() { calls.Add(1); done <- struct{}{} })
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionRotateKey}})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rotate_key did not trigger the renewal")
	}
	if calls.Load() != 1 {
		t.Fatalf("renewal called %d times", calls.Load())
	}

	// Without a renewer, rotate_key is only logged.
	d2, logs := newTestDoorbell(t, nil)
	d2.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionRotateKey}})
	if !strings.Contains(logs.String(), "key renewal is not enabled") {
		t.Errorf("missing log: %s", logs)
	}
}

func TestDoorbell_UnknownAndUpdateOnlyLogged(t *testing.T) {
	d, logs := newTestDoorbell(t, nil)
	for i := 0; i < 3; i++ {
		d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{"reboot\nnow", HeartbeatActionUpdate}})
	}
	out := logs.String()
	if n := strings.Count(out, "ignoring unknown heartbeat action"); n != 1 {
		t.Errorf("unknown action logged %d times, want once:\n%s", n, out)
	}
	if strings.Contains(out, "reboot\nnow") {
		t.Error("server-supplied value must be logged escaped, not raw")
	}
	if n := strings.Count(out, "update is available"); n != 1 {
		t.Errorf("update logged %d times, want once:\n%s", n, out)
	}
	if d.Paused() {
		t.Error("unknown/update actions must not change job intake")
	}
	// Bounded memory for unknown actions.
	for i := 0; i < 1000; i++ {
		d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatAction(strings.Repeat("x", i%200+1) + "y")}})
	}
	d.mu.Lock()
	n := len(d.unknownLogged)
	d.mu.Unlock()
	if n > maxUnknownActionsLogged {
		t.Errorf("unknown action memory unbounded: %d", n)
	}
}

func TestDoorbell_ConfigVersionAndFallback(t *testing.T) {
	d, logs := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true, ConfigVersion: "aaaaaaaaaaaaaaaa"})
	d.Handle(&HeartbeatHints{Present: true, ConfigVersion: "aaaaaaaaaaaaaaaa"})
	d.Handle(&HeartbeatHints{Present: true, ConfigVersion: "bbbbbbbbbbbbbbbb"})
	if d.ConfigVersion() != "bbbbbbbbbbbbbbbb" {
		t.Fatalf("config version %q", d.ConfigVersion())
	}
	if n := strings.Count(logs.String(), "config version changed"); n != 1 {
		t.Errorf("change logged %d times:\n%s", n, logs)
	}
	// An older server: no hints, fixed polling.
	d.Handle(&HeartbeatHints{})
	if d.HintsActive() {
		t.Fatal("no hints: doorbell must be inactive")
	}
	d.Handle(&HeartbeatHints{Present: true})
	d.HeartbeatFailed()
	if d.HintsActive() {
		t.Fatal("failed heartbeat: fall back to fixed polling")
	}
}

// --- poller -----------------------------------------------------------------

type countingCommandClient struct {
	polls atomic.Int32
	cmds  chan *Command
}

func (c *countingCommandClient) GetCommands(context.Context) (*GetCommandsResponse, error) {
	c.polls.Add(1)
	select {
	case cmd := <-c.cmds:
		return &GetCommandsResponse{Commands: []*Command{cmd}}, nil
	default:
		return &GetCommandsResponse{}, nil
	}
}
func (c *countingCommandClient) AcknowledgeCommand(context.Context, string) error { return nil }
func (c *countingCommandClient) StartCommand(context.Context, string) error       { return nil }
func (c *countingCommandClient) ReportCommandResult(context.Context, string, *CommandResult) error {
	return nil
}
func (c *countingCommandClient) ReportCommandProgress(context.Context, string, int, string) error {
	return nil
}

type recordingExecutor struct{ ran chan string }

func (e *recordingExecutor) Execute(_ context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.ran <- cmd.ID
	return &CommandExecutionResult{}, nil
}

func startPoller(t *testing.T, d *Doorbell, interval, safety time.Duration) (*countingCommandClient, *recordingExecutor) {
	t.Helper()
	cc := &countingCommandClient{cmds: make(chan *Command, 4)}
	ex := &recordingExecutor{ran: make(chan string, 4)}
	p := NewCommandPoller(cc, ex, &CommandPollerConfig{PollInterval: interval, DoorbellSafetyPoll: safety})
	if d != nil {
		p.SetDoorbell(d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cc, ex
}

func TestCommandPoller_DoorbellReplacesFixedPoll(t *testing.T) {
	d, _ := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true, NextHeartbeat: 30 * time.Second})
	cc, ex := startPoller(t, d, 10*time.Millisecond, time.Hour)

	time.Sleep(200 * time.Millisecond)
	if n := cc.polls.Load(); n != 1 {
		t.Fatalf("with hints active only the start-up poll should run, got %d polls", n)
	}

	// The doorbell rings: the poller polls at once and runs the job.
	cc.cmds <- &Command{ID: "c1", Type: "scan"}
	start := time.Now()
	d.Handle(&HeartbeatHints{Present: true, PendingJobs: 1})
	select {
	case id := <-ex.ran:
		if id != "c1" {
			t.Fatalf("ran %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("doorbell did not trigger a poll")
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("doorbell-to-run took %v", el)
	}
}

func TestCommandPoller_SafetyPoll(t *testing.T) {
	d, _ := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true})
	cc, _ := startPoller(t, d, 10*time.Millisecond, 100*time.Millisecond)
	time.Sleep(450 * time.Millisecond)
	if n := cc.polls.Load(); n < 3 || n > 7 {
		t.Fatalf("safety poll every ~100ms over 450ms: got %d polls", n)
	}
}

func TestCommandPoller_NoHintsKeepsFixedPoll(t *testing.T) {
	d, _ := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{}) // older server
	cc, _ := startPoller(t, d, 20*time.Millisecond, time.Hour)
	time.Sleep(250 * time.Millisecond)
	if n := cc.polls.Load(); n < 6 {
		t.Fatalf("without hints the fixed poll must continue, got %d polls", n)
	}

	// No doorbell at all: unchanged behavior.
	cc2, _ := startPoller(t, nil, 20*time.Millisecond, time.Hour)
	time.Sleep(250 * time.Millisecond)
	if n := cc2.polls.Load(); n < 6 {
		t.Fatalf("poller without doorbell must poll on its interval, got %d polls", n)
	}
}

func TestCommandPoller_PausedClaimsNothing(t *testing.T) {
	d, _ := newTestDoorbell(t, nil)
	d.Handle(&HeartbeatHints{Present: true, Actions: []HeartbeatAction{HeartbeatActionPause}})
	d.HeartbeatFailed() // even with fixed polling, a pause holds
	cc, ex := startPoller(t, d, 10*time.Millisecond, time.Hour)
	cc.cmds <- &Command{ID: "c1", Type: "scan"}
	time.Sleep(150 * time.Millisecond)
	if n := cc.polls.Load(); n != 0 {
		t.Fatalf("paused sensor polled %d times", n)
	}

	d.Handle(&HeartbeatHints{Present: true, PendingJobs: 1}) // resumed, work waiting
	select {
	case <-ex.ran:
	case <-time.After(2 * time.Second):
		t.Fatal("did not resume taking jobs")
	}
}

// --- base sensor heartbeat ----------------------------------------------------

type doorbellPusher struct {
	mu       sync.Mutex
	times    []time.Time
	messages []string
	answer   func(n int) *HeartbeatHints
	plain    atomic.Int32
}

func (p *doorbellPusher) SendHeartbeatWithHints(_ context.Context, s *SensorStatus) (*HeartbeatHints, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.times = append(p.times, time.Now())
	p.messages = append(p.messages, s.Message)
	return p.answer(len(p.times)), nil
}
func (p *doorbellPusher) SendHeartbeat(context.Context, *SensorStatus) error {
	p.plain.Add(1)
	return nil
}
func (p *doorbellPusher) PushFindings(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *doorbellPusher) PushAssets(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *doorbellPusher) TestConnection(context.Context) error { return nil }

func TestBaseSensor_HeartbeatFollowsAdvice(t *testing.T) {
	p := &doorbellPusher{answer: func(n int) *HeartbeatHints {
		if n == 1 {
			return &HeartbeatHints{Present: true, NextHeartbeat: MinDoorbellHeartbeatInterval, Actions: []HeartbeatAction{HeartbeatActionPause}}
		}
		return &HeartbeatHints{Present: true, NextHeartbeat: MinDoorbellHeartbeatInterval}
	}}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	d, _ := newTestDoorbell(t, nil)
	s.SetDoorbell(d)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		p.mu.Lock()
		n := len(p.times)
		p.mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = s.Stop(context.Background())

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.times) < 3 {
		t.Fatalf("advised 5s interval not followed (configured 1h): %d heartbeats", len(p.times))
	}
	gap := p.times[1].Sub(p.times[0])
	if gap < 4*time.Second || gap > 7*time.Second {
		t.Errorf("gap %v, want ~5s", gap)
	}
	if p.messages[1] != "paused by platform" {
		t.Errorf("heartbeat while paused should say so, got %q", p.messages[1])
	}
	if p.messages[2] != "" {
		t.Errorf("after resume message %q", p.messages[2])
	}
}

func TestBaseSensor_NoDoorbellSendsPlainHeartbeat(t *testing.T) {
	p := &doorbellPusher{answer: func(int) *HeartbeatHints { return &HeartbeatHints{} }}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_ = s.Stop(context.Background())
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.times) != 0 || p.plain.Load() < 1 {
		t.Fatalf("without a doorbell the heartbeat must stay plain: hints=%d plain=%d", len(p.times), p.plain.Load())
	}
}
