package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// legacyListClient returns every command it has on each poll, whatever the
// poller's free slots (a CommandClient without GetCommandsLimit).
type legacyListClient struct {
	mu       sync.Mutex
	cmds     []*Command
	acked    map[string]bool
	startErr error
}

func (c *legacyListClient) GetCommands(context.Context) (*GetCommandsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*Command
	for _, cmd := range c.cmds {
		if !c.acked[cmd.ID] {
			out = append(out, cmd)
		}
	}
	return &GetCommandsResponse{Commands: out}, nil
}

func (c *legacyListClient) AcknowledgeCommand(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acked[id] = true
	return nil
}

func (c *legacyListClient) StartCommand(context.Context, string) error { return c.startErr }
func (c *legacyListClient) ReportCommandResult(context.Context, string, *CommandResult) error {
	return nil
}
func (c *legacyListClient) ReportCommandProgress(context.Context, string, int, string) error {
	return nil
}

func (c *legacyListClient) ackedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.acked)
}

type parkedExecutor struct {
	release chan struct{}
	ran     chan string
}

func (e *parkedExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.ran <- cmd.ID
	select {
	case <-e.release:
	case <-ctx.Done():
	}
	return &CommandExecutionResult{}, nil
}

func newLegacyClient(n int) *legacyListClient {
	c := &legacyListClient{acked: map[string]bool{}}
	for i := 0; i < n; i++ {
		c.cmds = append(c.cmds, &Command{ID: fmt.Sprintf("c%d", i), Type: "scan"})
	}
	return c
}

// A client that returns more commands than free slots: the extra commands
// are left unclaimed, not acknowledged and parked.
func TestCommandPoller_ClaimsOnlyFreeSlots(t *testing.T) {
	c := newLegacyClient(10)
	e := &parkedExecutor{release: make(chan struct{}), ran: make(chan string, 10)}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p.pollAndExecute(ctx)
	for i := 0; i < 2; i++ {
		<-e.ran
	}
	if got := c.ackedCount(); got != 2 {
		t.Fatalf("acknowledged %d commands with 2 slots, want 2", got)
	}
	// All slots busy: a poll (e.g. a doorbell ring) claims nothing.
	p.pollAndExecute(ctx)
	if got := c.ackedCount(); got != 2 {
		t.Fatalf("acknowledged %d commands with no free slot, want 2", got)
	}
	if !p.backlog.Load() {
		t.Fatal("backlog not recorded while work was left pending")
	}
	close(e.release)
	p.activeCmds.Wait()
	if p.ActiveJobs() != 0 {
		t.Fatalf("active %d after all ended", p.ActiveJobs())
	}
	select {
	case <-p.slotFreed:
	case <-time.After(time.Second):
		t.Fatal("a freed slot with work left did not signal a poll")
	}
}

// A failed start releases the slot and does not run the command.
func TestCommandPoller_FailedStartDoesNotExecute(t *testing.T) {
	c := newLegacyClient(1)
	c.startErr = errors.New("409 invalid-transition")
	e := &parkedExecutor{release: make(chan struct{}), ran: make(chan string, 1)}
	close(e.release)
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 1})

	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()
	select {
	case id := <-e.ran:
		t.Fatalf("executed %s after a failed start", id)
	default:
	}
	if p.ActiveJobs() != 0 {
		t.Fatalf("slot not released: active %d", p.ActiveJobs())
	}
}
