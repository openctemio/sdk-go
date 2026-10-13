package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// churnClient plays a platform with claim-N: a poll claims what it returns,
// and a release puts the command back and rings the sensor's doorbell at
// once (the platform wakes sensors when a command becomes claimable).
type churnClient struct {
	*queueClient
	bell     *Doorbell
	polls    atomic.Int32
	releases atomic.Int32
}

func (c *churnClient) GetCommandsLimit(ctx context.Context, limit int) (*GetCommandsResponse, error) {
	c.polls.Add(1)
	resp, err := c.queueClient.GetCommandsLimit(ctx, limit)
	if err == nil {
		for _, cmd := range resp.Commands {
			cmd.Claimed = true
		}
	}
	return resp, err
}

func (c *churnClient) ReleaseCommand(ctx context.Context, id, reason string) error {
	c.releases.Add(1)
	err := c.queueClient.ReleaseCommand(ctx, id, reason)
	c.bell.ring()
	return err
}

// The loop seen on a live sensor: a command whose host is busy here is
// claimed, handed back, offered again at once and claimed again, about twice
// a second. With the claim backoff the polls and releases stay bounded, and
// the command still runs as soon as the host is free.
func TestClaimBackoff_BoundsTheClaimReleaseLoop(t *testing.T) {
	busy := scanCmd("busy", "normal", map[string]any{"target": "https://a.example.com/"})
	same := scanCmd("same-host", "normal", map[string]any{"target": "a.example.com"})
	bell := NewDoorbell(nil)
	c := &churnClient{queueClient: newQueueClient(busy, same), bell: bell}
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4, PollInterval: time.Hour, DrainGrace: 100 * time.Millisecond})
	p.SetDoorbell(bell)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	if id := <-e.started; id != "busy" {
		t.Fatalf("first run %s, want busy", id)
	}

	time.Sleep(2500 * time.Millisecond)
	polls, releases := c.polls.Load(), c.releases.Load()
	// Unbounded, this is hundreds of round trips. Bounded: the start poll,
	// then backoffs of 1s and 2s (plus jitter) within 2.5s.
	if polls > 5 || releases > 4 {
		t.Fatalf("%d polls and %d releases in 2.5s: the claim/release loop is not bounded", polls, releases)
	}
	if releases == 0 {
		t.Fatal("the same-host command was never handed back")
	}

	// The busy command ends: the host is free and the backoff is over, so
	// the handed-back command runs without waiting for the next backoff.
	close(e.release)
	select {
	case id := <-e.started:
		if id != "same-host" {
			t.Fatalf("next run %s, want same-host", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the handed-back command did not run once its host was free")
	}
	cancel()
	<-done
}

func TestClaimBackoff_GrowsWithJitterAndCaps(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newClaimBackoff()
	b.now = func() time.Time { return now }
	var jitterArg []time.Duration
	b.jitter = func(d time.Duration) time.Duration { jitterArg = append(jitterArg, d); return d - 1 }

	want := MinClaimBackoff
	for i := range 10 {
		d := b.fruitless()
		if d != want+want/2-1 {
			t.Fatalf("step %d: wait %s, want %s plus jitter below %s", i, d, want, want/2)
		}
		if got := b.wait(); got != d {
			t.Fatalf("step %d: wait() %s, want %s", i, got, d)
		}
		want = min(want*2, MaxClaimBackoff)
	}
	if jitterArg[len(jitterArg)-1] != MaxClaimBackoff/2 {
		t.Fatalf("jitter bound %s at the cap, want %s", jitterArg[len(jitterArg)-1], MaxClaimBackoff/2)
	}
	b.progressed()
	if b.wait() != 0 {
		t.Fatal("progress must end the backoff")
	}
	if d := b.fruitless(); d < MinClaimBackoff || d >= 2*MinClaimBackoff {
		t.Fatalf("after progress the backoff starts again from the minimum, got %s", d)
	}

	// Real jitter stays within half a step.
	r := newClaimBackoff()
	for range 100 {
		r.progressed()
		if d := r.fruitless(); d < MinClaimBackoff || d >= MinClaimBackoff+MinClaimBackoff/2 {
			t.Fatalf("jittered wait %s outside [%s, %s)", d, MinClaimBackoff, MinClaimBackoff+MinClaimBackoff/2)
		}
	}
}

type hintErr struct{ d time.Duration }

func (e hintErr) Error() string                 { return "429" }
func (e hintErr) RetryAfterHint() time.Duration { return e.d }

func TestRetryAfterOf(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want time.Duration
	}{
		{nil, 0},
		{errors.New("plain"), 0},
		{hintErr{30 * time.Second}, 30 * time.Second},
		{fmt.Errorf("poll: %w", hintErr{30 * time.Second}), 30 * time.Second},
		{hintErr{-time.Second}, 0},
		{hintErr{24 * time.Hour}, MaxPollRetryAfter},
	} {
		if got := retryAfterOf(tc.err); got != tc.want {
			t.Fatalf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

// failingClient refuses every poll with a Retry-After.
type failingClient struct {
	*queueClient
	mu    sync.Mutex
	polls int
	err   error
}

func (c *failingClient) GetCommandsLimit(context.Context, int) (*GetCommandsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.polls++
	return nil, c.err
}

// A poll refused with a Retry-After is not repeated before it, whatever
// wakes the poller; a command that ends here does not lift it.
func TestClaimBackoff_HonoursThePlatformRetryAfter(t *testing.T) {
	c := &failingClient{queueClient: newQueueClient(), err: hintErr{2 * time.Minute}}
	p := NewCommandPoller(c, newCtxExecutor(), &CommandPollerConfig{MaxConcurrent: 2, PollInterval: time.Hour})
	p.pollAndExecute(context.Background())
	p.pollAndExecute(context.Background())
	p.claims.progressed()
	p.pollAndExecute(context.Background())
	if c.polls != 1 {
		t.Fatalf("%d polls, want 1: the Retry-After must hold", c.polls)
	}
	if !p.pollDeferred {
		t.Fatal("a skipped poll must be remembered so it runs once the wait is over")
	}
	if w := p.claims.wait(); w <= time.Minute || w > 2*time.Minute {
		t.Fatalf("wait %s, want the 2m the platform asked for", w)
	}
}

// A poll that only hands commands back starts the backoff; a poll that
// starts one does not.
func TestClaimBackoff_OnlyFruitlessPollsBackOff(t *testing.T) {
	c := newQueueClient(scanCmd("x", "normal", map[string]any{"target": "x.example.com"}))
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2, PollInterval: time.Hour, AllowedTypes: []string{"collect"}})
	p.pollAndExecute(context.Background()) // scan not allowed: handed back
	if p.claims.wait() == 0 {
		t.Fatal("a poll that only handed commands back must start the backoff")
	}

	c2 := newQueueClient(scanCmd("y", "normal", map[string]any{"target": "y.example.com"}))
	e2 := newCtxExecutor()
	p2 := NewCommandPoller(c2, e2, &CommandPollerConfig{MaxConcurrent: 2, PollInterval: time.Hour})
	p2.pollAndExecute(context.Background())
	<-e2.started
	if p2.claims.wait() != 0 {
		t.Fatal("a poll that started a command must not back off")
	}
	close(e2.release)
	p2.activeCmds.Wait()
}
