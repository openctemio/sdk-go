package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

// stuckExecutor ignores its context: a tool runner blocked where a cancel
// cannot reach (the incident 2026-10-25, before the forwarder fix).
type stuckExecutor struct{ started chan struct{} }

func (e *stuckExecutor) Execute(context.Context, *Command) (*CommandExecutionResult, error) {
	close(e.started)
	select {} // never returns
}

// releaseClient records releases and results.
type releaseClient struct {
	mu       sync.Mutex
	released []string
	results  map[string]*CommandResult
}

func (c *releaseClient) GetCommands(context.Context) (*GetCommandsResponse, error) {
	return &GetCommandsResponse{}, nil
}
func (c *releaseClient) AcknowledgeCommand(context.Context, string) error { return nil }
func (c *releaseClient) StartCommand(context.Context, string) error       { return nil }
func (c *releaseClient) ReportCommandResult(_ context.Context, id string, r *CommandResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results == nil {
		c.results = map[string]*CommandResult{}
	}
	c.results[id] = r
	return nil
}
func (c *releaseClient) ReportCommandProgress(context.Context, string, int, string) error {
	return nil
}
func (c *releaseClient) ReleaseCommand(_ context.Context, id, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.released = append(c.released, id)
	return nil
}

// A canceled command whose executor never returns is handed back within
// the stop grace: its slot is free again and the platform is told, instead
// of the sensor holding it (and logging the platform's repeated cancel)
// until it restarts.
func TestCanceledCommandIsGivenUpWhenItsExecutorIgnoresTheCancel(t *testing.T) {
	client := &releaseClient{}
	exec := &stuckExecutor{started: make(chan struct{})}
	p := NewCommandPoller(client, exec, &CommandPollerConfig{MaxConcurrent: 1, AllowedTypes: []string{"scan"}})
	p.stopGraceNs.Store(int64(200 * time.Millisecond))
	done := make(chan error, 1)
	go func() {
		done <- p.RunClaimed(context.Background(), &Command{ID: "c-stuck", Type: "scan", Payload: []byte(`{"scanner":"x","target":"a.example"}`)})
	}()
	<-exec.started
	p.CancelCommands("c-stuck")
	p.CancelCommands("c-stuck") // repeated by the platform: a no-op
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the canceled command was never given up")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.released) != 1 || client.released[0] != "c-stuck" {
		t.Fatalf("released %v", client.released)
	}
	if client.results["c-stuck"] != nil {
		t.Fatalf("a canceled command was reported: %+v", client.results["c-stuck"])
	}
	if len(p.HeldCommandIDs()) != 0 || len(p.sem) != 0 {
		t.Fatalf("still held %v, slots in use %d", p.HeldCommandIDs(), len(p.sem))
	}
}
