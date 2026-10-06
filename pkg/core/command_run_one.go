package core

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNotRun is the error of a claimed command RunClaimed did not run (it
// was released back to the platform).
var ErrNotRun = errors.New("command not run")

// RunClaimed runs one command this sensor already claimed, and returns
// when its result was reported (or queued in the outbox): the sensor that
// runs one job and exits (a Kubernetes Job). The command passes every
// check a polled command passes: the local kill switch, the command types
// this sensor serves, the expiry, then (as for any command) the local
// policy admission, the start transition, the platform's tool gate, the
// executor and the result report. A command that is not run is released
// to the platform (an error wrapping ErrNotRun says why). Canceling ctx
// stops the command and releases it, as a drain does.
func (p *CommandPoller) RunClaimed(ctx context.Context, cmd *Command) error {
	if cmd == nil || cmd.ID == "" {
		return fmt.Errorf("%w: no command", ErrNotRun)
	}
	notRun := func(reason string) error {
		p.release(cmd.ID, reason)
		return fmt.Errorf("%w: %s", ErrNotRun, reason)
	}
	switch {
	case p.checkKillSwitch():
		return notRun("stopped by the sensor owner (local kill switch)")
	case !p.allowedTypes[cmd.Type]:
		return notRun(fmt.Sprintf("command type %q is not served by this sensor", cmd.Type))
	case !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt):
		return notRun("command expired")
	case ctx.Err() != nil:
		return notRun(ReleaseReasonShutdown)
	}
	meta := parseCommandMeta(cmd)
	p.queue.admit(cmd.ID, commandHosts(meta), 0, time.Now())
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		p.queue.forget(cmd.ID)
		return notRun(ReleaseReasonShutdown)
	}
	cmdCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	defer cancel(nil)
	p.queue.setCancel(cmd.ID, cancel)
	// A stop (SIGTERM on the Job) is a drain: the command is released, not
	// reported failed.
	stop := context.AfterFunc(ctx, func() { cancel(errDrained) })
	defer stop()
	p.activeCmds.Add(1)
	p.executeCommand(cmdCtx, cmd)
	return nil
}
