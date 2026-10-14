package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// finishOnStop runs until its context ends; stopped by the platform it
// returns what it finished, as a tool runner delivering a partial run does.
type finishOnStop struct{ started chan string }

func (e *finishOnStop) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.started <- cmd.ID
	<-ctx.Done()
	if errors.Is(context.Cause(ctx), ErrStoppedByPlatform) {
		return &CommandExecutionResult{FindingsCount: 1}, nil
	}
	return nil, ctx.Err()
}

func TestParseHeartbeatHints_StopIDs(t *testing.T) {
	h := ParseHeartbeatHints([]byte(`{"stop_command_ids":["a","","b"]}`))
	if fmt.Sprint(h.StopCommandIDs) != "[a b]" {
		t.Fatalf("ids %v", h.StopCommandIDs)
	}
	long := make([]byte, maxCancelIDLen+1)
	for i := range long {
		long[i] = 'x'
	}
	if h := ParseHeartbeatHints([]byte(`{"stop_command_ids":["` + string(long) + `"]}`)); len(h.StopCommandIDs) != 0 {
		t.Fatalf("an over-long id was kept: %v", h.StopCommandIDs)
	}
}

// The platform asks the sensor to stop a stalled command and deliver what
// it finished: the command is reported (completed with the finished work),
// not released and not reported failed. A cancel still releases.
func TestQueue_StopFromHeartbeatReportsFinishedWork(t *testing.T) {
	c := newQueueClient(scanCmd("x", "normal", map[string]any{"target": "x.example.com"}))
	e := &finishOnStop{started: make(chan string, 4)}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2})
	d := NewDoorbell(nil)
	p.SetDoorbell(d)
	p.pollAndExecute(context.Background())
	<-e.started

	d.Handle(ParseHeartbeatHints([]byte(`{"pending_jobs":0,"stop_command_ids":["x","not-held"]}`)))
	p.activeCmds.Wait()
	_, st, rel := c.snapshot()
	if _, released := rel["x"]; released {
		t.Fatalf("a stopped command was released: %v", rel)
	}
	if st["x"] != "completed" || c.full["x"] == nil || c.full["x"].FindingsCount != 1 {
		t.Fatalf("state %v result %+v", st, c.full["x"])
	}
}

// What a stopped run finished is parsed and pushed under a context the stop
// does not end.
func TestDeliveryContext_Stop(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrStoppedByPlatform)
	if deliveryContext(ctx, ctx).Err() != nil {
		t.Fatal("a stopped run's delivery context is done")
	}
	cctx, ccancel := context.WithCancelCause(context.Background())
	ccancel(errCanceledByPlatform)
	if deliveryContext(cctx, cctx).Err() == nil {
		t.Fatal("a canceled run still delivers")
	}
}
