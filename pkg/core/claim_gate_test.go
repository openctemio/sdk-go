package core

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// While the claim gate says no (storage full), the poller asks the platform
// for nothing; it resumes the moment the gate clears, and each change of
// state is logged once.
func TestCommandPoller_ClaimGateStopsAndResumes(t *testing.T) {
	cc := &countingCommandClient{}
	p := NewCommandPoller(cc, &recordingExecutor{ran: make(chan string, 1)}, nil)
	var open atomic.Bool
	p.SetClaimGate(func() (bool, string) {
		if open.Load() {
			return true, ""
		}
		return false, "the outbox is full"
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	ctx := context.Background()
	for range 5 {
		p.pollAndExecute(ctx)
	}
	blockedPolls := cc.polls.Load()
	open.Store(true)
	for range 3 {
		p.pollAndExecute(ctx)
	}
	os.Stdout = stdout
	_ = w.Close()
	logged, _ := io.ReadAll(r)

	if blockedPolls != 0 {
		t.Fatalf("polled %d times while the gate was closed", blockedPolls)
	}
	if cc.polls.Load() == 0 {
		t.Fatal("did not poll after the gate cleared")
	}
	if n := strings.Count(string(logged), "Not claiming new jobs: the outbox is full"); n != 1 {
		t.Errorf("stop logged %d times, want once:\n%s", n, logged)
	}
	if n := strings.Count(string(logged), "Claiming new jobs again"); n != 1 {
		t.Errorf("resume logged %d times, want once:\n%s", n, logged)
	}
}

func TestCommandPoller_NoClaimGateClaims(t *testing.T) {
	cc := &countingCommandClient{}
	p := NewCommandPoller(cc, &recordingExecutor{ran: make(chan string, 1)}, nil)
	p.pollAndExecute(context.Background())
	if cc.polls.Load() != 1 {
		t.Fatalf("polls = %d", cc.polls.Load())
	}
	p.SetClaimGate(func() (bool, string) { return false, "x" })
	p.SetClaimGate(nil)
	p.pollAndExecute(context.Background())
	if cc.polls.Load() != 2 {
		t.Fatalf("a removed gate still blocked: %d", cc.polls.Load())
	}
}
