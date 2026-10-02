package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// controlPusher records the heartbeats it is sent and fails while err is set.
type controlPusher struct {
	mu     sync.Mutex
	err    error
	delay  time.Duration
	status []*SensorStatus
}

func (p *controlPusher) SendHeartbeat(_ context.Context, s *SensorStatus) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	time.Sleep(p.delay)
	cp := *s
	p.status = append(p.status, &cp)
	return p.err
}
func (p *controlPusher) PushFindings(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *controlPusher) PushAssets(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *controlPusher) TestConnection(context.Context) error { return nil }

func (p *controlPusher) last() *SensorStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status[len(p.status)-1]
}

// Every heartbeat carries the control channel's stats: the interval it
// follows, the gap since the previous delivered one, the round trip of that
// one and the failures since.
func TestHeartbeat_ControlStats(t *testing.T) {
	p := &controlPusher{delay: 20 * time.Millisecond}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Minute}, p)
	ctx := context.Background()

	next, err := s.heartbeatOnce(ctx, s.Status())
	if err != nil || next != time.Minute {
		t.Fatalf("first: next %s, err %v", next, err)
	}
	c := p.last().Control
	if c == nil || c.IntervalSeconds != 60 || c.GapSeconds != 0 || c.RTTMs != 0 || c.Failures != 0 {
		t.Fatalf("first heartbeat control = %+v", c)
	}

	time.Sleep(30 * time.Millisecond)
	if _, err := s.heartbeatOnce(ctx, s.Status()); err != nil {
		t.Fatal(err)
	}
	c = p.last().Control
	if c.GapSeconds < 0.04 || c.RTTMs < 20 {
		t.Fatalf("second heartbeat control = %+v, want the gap and the first one's round trip", c)
	}

	// Two failures: the next delivered heartbeat says so, and a failed one
	// is followed after about HeartbeatRetryDelay, not the interval.
	p.mu.Lock()
	p.err = errors.New("connection refused")
	p.mu.Unlock()
	for range 2 {
		next, err := s.heartbeatOnce(ctx, s.Status())
		if err == nil {
			t.Fatal("want the error")
		}
		if lo, hi := HeartbeatRetryDelay*8/10, HeartbeatRetryDelay*12/10; next < lo || next > hi {
			t.Fatalf("after a failure next = %s, want about %s", next, HeartbeatRetryDelay)
		}
	}
	p.mu.Lock()
	p.err = nil
	p.mu.Unlock()
	if _, err := s.heartbeatOnce(ctx, s.Status()); err != nil {
		t.Fatal(err)
	}
	if c = p.last().Control; c.Failures != 2 {
		t.Fatalf("after two failures control = %+v", c)
	}
	if _, err := s.heartbeatOnce(ctx, s.Status()); err != nil {
		t.Fatal(err)
	}
	if c = p.last().Control; c.Failures != 0 {
		t.Fatalf("failures not reset after a delivered heartbeat: %+v", c)
	}
}

// A heartbeat whose interval is shorter than the retry delay keeps it.
func TestRetryDelay_NeverAboveTheInterval(t *testing.T) {
	if d := retryDelay(3 * time.Second); d != 3*time.Second {
		t.Fatalf("retryDelay(3s) = %s", d)
	}
}

// The loop records how late its timer fired: the time the sensor waited for
// a CPU before it could even build the heartbeat.
func TestControlTracker_Lag(t *testing.T) {
	var c controlTracker
	due := time.Unix(100, 0)
	c.fired(due, due.Add(1500*time.Millisecond))
	if s := c.stats(due.Add(2*time.Second), 200*time.Millisecond, time.Minute); s.LagMs != 1500 || s.BuildMs != 200 {
		t.Fatalf("stats = %+v", s)
	}
	c.delivered(due.Add(2*time.Second), 10*time.Millisecond, 30*time.Second)
	if s := c.stats(due.Add(32*time.Second), 0, time.Minute); s.LagMs != 0 || s.IntervalSeconds != 30 || s.GapSeconds != 30 || s.RTTMs != 10 {
		t.Fatalf("after delivery = %+v", s)
	}
}
