package core

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// releasingClaimClient is a poll that claims (claim-N): every command it
// returns is already claimed for the sensor, and it records releases.
type releasingClaimClient struct {
	legacyListClient
	relMu    sync.Mutex
	released map[string]string
}

func (c *releasingClaimClient) ReleaseCommand(_ context.Context, id, reason string) error {
	c.relMu.Lock()
	defer c.relMu.Unlock()
	c.released[id] = reason
	return nil
}

func (c *releasingClaimClient) releasedIDs() []string {
	c.relMu.Lock()
	defer c.relMu.Unlock()
	out := make([]string, 0, len(c.released))
	for id := range c.released {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func newClaimClient(n int) *releasingClaimClient {
	c := &releasingClaimClient{legacyListClient: *newLegacyClient(n), released: map[string]string{}}
	for _, cmd := range c.cmds {
		cmd.Claimed = true
	}
	return c
}

func waitReleased(t *testing.T, c *releasingClaimClient, want []string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := c.releasedIDs()
		if len(got) == len(want) {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("released %v, want %v", got, want)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("released %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Claim-N: a claimed command the poller cannot run now (no slot, wrong type,
// expired) is handed back at once, not left to its lease.
func TestCommandPoller_ReleasesClaimedCommandsItDoesNotRun(t *testing.T) {
	c := newClaimClient(4)
	c.cmds[2].Type = "forbidden"
	c.cmds[3].ExpiresAt = time.Now().Add(-time.Minute)
	e := &parkedExecutor{release: make(chan struct{}), ran: make(chan string, 4)}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p.pollAndExecute(ctx)
	if got := <-e.ran; got != "c0" {
		t.Fatalf("ran %s, want c0", got)
	}
	// c1: no slot; c2: type not allowed; c3: expired.
	waitReleased(t, c, []string{"c1", "c2", "c3"})
	close(e.release)
}

// A command the poll only listed (no claim-N) is never released: it is still
// pending on the platform.
func TestCommandPoller_DoesNotReleaseListedCommands(t *testing.T) {
	c := newClaimClient(3)
	for _, cmd := range c.cmds {
		cmd.Claimed = false
	}
	e := &parkedExecutor{release: make(chan struct{}), ran: make(chan string, 3)}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p.pollAndExecute(ctx)
	<-e.ran
	time.Sleep(50 * time.Millisecond)
	if got := c.releasedIDs(); len(got) != 0 {
		t.Fatalf("released listed commands %v", got)
	}
	close(e.release)
}
