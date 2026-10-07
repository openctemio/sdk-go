package core

// The poller's own lines in a command's log (sensor protocol v2 feature
// "logs", api RFC-029 §4.4.1): what happened to the command on this sensor
// before and after its tool ran: received, the local policy check and every
// target it refused with the reason, the platform's tool gate, the outcome
// (completed, partial, failed, timed out, refused) and a hand-back to the
// platform (no free slot, busy hosts, drain). A command refused before any
// tool started has these lines and nothing else, so the task's log on the
// platform says why it did not run.
//
// The sink (sensorkit's log shipper) redacts, strips control characters,
// bounds lines per command and delivers through the outbox ahead of the
// command's result. Logs are best effort: losing them never fails a command.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CommandLogSink takes the poller's lines about a command.
type CommandLogSink interface {
	// CommandLog adds one line (level: info, warn or error) to the log of
	// command commandID. It never blocks on the network.
	CommandLog(ctx context.Context, commandID, level, msg string, fields map[string]any)
	// FinishCommandLog sends what is left of the command's lines. Queued
	// (direct false), the lines are delivered by the outbox ahead of the
	// result reported after it. Direct, they are sent before it returns:
	// for a command about to be handed back, after which the platform no
	// longer takes this sensor's lines for it.
	FinishCommandLog(ctx context.Context, commandID string, direct bool)
}

// maxRefusedTargetLines bounds the per-target lines one admission logs.
const maxRefusedTargetLines = 50

// maxHandBackNotes bounds the commands whose hand-back reason the poller
// remembers (a command handed back for the same reason on every poll is
// logged once).
const maxHandBackNotes = 1024

// SetCommandLogSink makes the poller write its own lines about each command
// to sink (nil: none). Call before Start.
func (p *CommandPoller) SetCommandLogSink(sink CommandLogSink) {
	p.logSink = sink
}

// clog adds one line to the log of cmdID.
func (p *CommandPoller) clog(ctx context.Context, cmdID, level, msg string, fields map[string]any) {
	if p.logSink == nil || cmdID == "" {
		return
	}
	p.logSink.CommandLog(ctx, cmdID, level, msg, fields)
}

// finishLog sends the rest of cmdID's lines (queued ahead of its result).
func (p *CommandPoller) finishLog(ctx context.Context, cmdID string) {
	if p.logSink == nil || cmdID == "" {
		return
	}
	p.logSink.FinishCommandLog(context.WithoutCancel(ctx), cmdID, false)
}

// logAdmission writes the local policy's decision about cmd's targets.
func (p *CommandPoller) logAdmission(ctx context.Context, cmd *Command, adm *CommandAdmission, err error) {
	if p.logSink == nil || adm == nil {
		return
	}
	fields := map[string]any{"targets": adm.Total, "refused": len(adm.Refused)}
	if adm.Total > 0 || err != nil {
		p.clog(ctx, cmd.ID, "info", "Local policy check", fields)
	}
	for i, r := range adm.Refused {
		if i == maxRefusedTargetLines {
			p.clog(ctx, cmd.ID, "warn", fmt.Sprintf("%d more refused target(s) not listed", len(adm.Refused)-i), nil)
			break
		}
		f := map[string]any{"target": r.Target, "reason": r.Reason}
		if r.Rule != "" {
			f["rule"] = r.Rule
		}
		if r.Detail != "" {
			f["detail"] = r.Detail
		}
		p.clog(ctx, cmd.ID, "warn", "Target refused by the local policy: "+r.Target, f)
	}
	switch {
	case err != nil:
		p.clog(ctx, cmd.ID, "error", "Refused before running: "+err.Error(), refusalFields(err))
	case adm.Partial():
		p.clog(ctx, cmd.ID, "info", fmt.Sprintf("Running on %d of %d target(s); %d skipped", adm.Total-len(adm.Refused), adm.Total, len(adm.Refused)), nil)
	}
}

// refusalFields are the structured fields of a policy refusal.
func refusalFields(err error) map[string]any {
	r := RefusalOf(err)
	if r == nil {
		return nil
	}
	return map[string]any{"layer": r.Layer, "rule": r.Rule}
}

// logOutcome writes how the command ended on this sensor.
func (p *CommandPoller) logOutcome(ctx context.Context, cmd *Command, res *CommandResult, runErr error, took time.Duration) {
	if p.logSink == nil {
		return
	}
	switch {
	case runErr != nil && errors.Is(runErr, context.DeadlineExceeded):
		p.clog(ctx, cmd.ID, "error", fmt.Sprintf("Timed out after %s: %v", took.Round(time.Second), runErr), nil)
	case res.Status == "failed":
		p.clog(ctx, cmd.ID, "error", "Failed: "+res.Error, refusalFields(runErr))
	default:
		fields := map[string]any{"findings": res.FindingsCount, "duration_ms": res.DurationMs}
		refused := refusedTargetsFrom(res.Metadata)
		if len(refused) == 0 {
			p.clog(ctx, cmd.ID, "info", "Completed", fields)
			return
		}
		fields["refused_targets"] = len(refused)
		p.clog(ctx, cmd.ID, "warn", "Completed with "+refusedSummary(refused), fields)
	}
}

// handBack logs why a command this sensor claimed is handed back without
// running (no free slot, busy hosts, drain, expired), once per command and
// reason, sends that line directly and releases the command.
func (p *CommandPoller) handBack(id, reason string) {
	if p.logSink != nil && p.notedHandBack(id, reason) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(p.cmdBase), 10*time.Second)
		p.clog(ctx, id, "info", "Not run on this sensor now: "+reason+"; handed back to the platform", nil)
		p.logSink.FinishCommandLog(ctx, id, true)
		cancel()
	}
	p.release(id, reason)
}

// handBackNotes remembers the last hand-back reason logged per command.
type handBackNotes struct {
	mu   sync.Mutex
	last map[string]string
}

// notedHandBack reports whether (id, reason) is new and remembers it.
func (p *CommandPoller) notedHandBack(id, reason string) bool {
	n := &p.handBacks
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.last == nil || len(n.last) >= maxHandBackNotes {
		n.last = make(map[string]string)
	}
	if n.last[id] == reason {
		return false
	}
	n.last[id] = reason
	return true
}
