package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The platform re-sends its cancel on every heartbeat until the command is
// gone: only the first one cancels (and is logged); the rest are no-ops
// and keep the first cause.
func TestQueueCancelIsIdempotent(t *testing.T) {
	q := newLocalQueue()
	q.admit("c1", nil, 0, time.Now())
	ctx, cancel := context.WithCancelCause(context.Background())
	q.setCancel("c1", cancel)
	if !q.cancel("c1", errCanceledByPlatform) {
		t.Fatal("first cancel not reported")
	}
	for range 5 {
		if q.cancel("c1", ErrStoppedByPlatform) {
			t.Fatal("a repeated cancel was reported again")
		}
	}
	if !errors.Is(context.Cause(ctx), errCanceledByPlatform) {
		t.Fatalf("cause %v, want the first one", context.Cause(ctx))
	}
	if q.cancel("unknown", errCanceledByPlatform) {
		t.Fatal("a command not held was reported canceled")
	}
}

// A cancel that arrives before the command's context exists is not
// swallowed: the next one (the platform repeats it) still cancels.
func TestQueueCancelBeforeContextIsRetried(t *testing.T) {
	q := newLocalQueue()
	q.admit("c1", nil, 0, time.Now())
	_ = q.cancel("c1", errCanceledByPlatform)
	ctx, cancel := context.WithCancelCause(context.Background())
	q.setCancel("c1", cancel)
	if !q.cancel("c1", errCanceledByPlatform) || ctx.Err() == nil {
		t.Fatal("the repeated cancel did not cancel the command")
	}
}
