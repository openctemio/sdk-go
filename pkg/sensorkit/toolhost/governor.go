package toolhost

// Host pressure and tool starts (research/318 §6.3). Before a tool process
// starts, the host asks the Governor (resource.Governor) to admit it: the
// launch waits while the sensor's host is overloaded. The start handshake
// timeout grows with the measured stall. When a start still fails for a
// transient reason (no handshake from a starved process, no handshake or an
// out-of-memory kill under host pressure, the kernel refusing a fork for a
// while), the task is tried once more after a short backoff, and only when
// the first attempt settled nothing. A policy refusal, a protocol or
// manifest mismatch, a tool that crashed while busy and an out-of-memory
// kill by the task's own envelope are never retried: those are facts a
// second attempt cannot change.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/resource"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Governor admits tool launches under host pressure (resource.Governor
// implements it; resource.Manager.Governor returns the sensor's).
type Governor interface {
	// Admit waits until a tool may start; release is called when its
	// process has ended.
	Admit(ctx context.Context, tool string) (release func(), held time.Duration, err error)
	// StartTimeoutFactor multiplies the start handshake timeout (1-4).
	StartTimeoutFactor() float64
	// Pressure is the host's pressure now.
	Pressure() resource.Pressure
	// Transient counts a transient start failure, a retry or a recovery.
	Transient(kind string)
}

// MaxStartAttempts is how many times a task is started at most: once, and
// once more after a transient start failure.
const MaxStartAttempts = 2

// HostOverloaded is the phrase a failure's detail carries when the task
// failed to start under host pressure (tool.Error.FailureClass reads it).
const HostOverloaded = "sensor host overloaded"

// slowStartCPU is the CPU time below which a process that has not shaken
// hands is starved rather than busy.
const slowStartCPU = 50 * time.Millisecond

// startCPU reads the CPU time a task used so far at the handshake deadline.
// Tests replace it: a test binary's own runtime start-up (race detector,
// coverage) can use more CPU than slowStartCPU on a slow runner, which would
// make a sleeping child look busy.
var startCPU = func(c *core.ProcessCPU) (time.Duration, bool) { return c.Read() }

var retryBackoff = 2 * time.Second

// startFailure kinds an attempt can end with (Outcome.Transient).
const (
	startSlow      = resource.TransientSlowStart
	startHandshake = resource.TransientHandshakeTimeout
	startOOM       = resource.TransientOOMKill
	startEAGAIN    = resource.TransientStartEAGAIN
)

// pressure is the governor's pressure, ok without a governor.
func (h *Host) pressure() resource.Pressure {
	if h.Governor == nil {
		return resource.Pressure{Level: resource.PressureOK}
	}
	return h.Governor.Pressure()
}

func pressured(p resource.Pressure) bool {
	return p.Level == resource.PressureElevated || p.Level == resource.PressureOverloaded
}

// handshakeTimeout is the start handshake timeout now.
func (h *Host) handshakeTimeout() time.Duration {
	f := 1.0
	if h.Governor != nil {
		f = min(max(h.Governor.StartTimeoutFactor(), resource.MinStartFactor), resource.MaxStartFactor)
	}
	return time.Duration(float64(handshakeTimeout) * f).Round(time.Second)
}

// admit waits for the governor (no governor: at once).
func (h *Host) admit(ctx context.Context, m tool.Manifest) (func(), error) {
	if h.Governor == nil {
		return func() {}, nil
	}
	release, held, err := h.Governor.Admit(ctx, m.Name)
	if err != nil {
		return nil, fmt.Errorf("toolhost: %s waited %s for the sensor host's pressure to drop: %w", m.Name, held.Round(time.Second), err)
	}
	return release, nil
}

// envelopeFor is the executor envelope of the manifest's resources.
func envelopeFor(m tool.Manifest) *executor.Envelope {
	e := m.Resources.Envelope()
	return &executor.Envelope{CPU: e.CPU, MemoryMax: uint64(max(e.MemoryMax, 0)), Pids: uint64(max(e.Pids, 0))} //nolint:gosec // clamped to >= 0
}

// startErrorKind is the transient kind of a start error ("" when it is
// not transient).
func startErrorKind(err error) string {
	for _, e := range []error{syscall.EAGAIN, syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM} {
		if errors.Is(err, e) {
			return startEAGAIN
		}
	}
	return ""
}

// settledNothing reports whether an attempt delivered nothing a retry
// could duplicate: no record and no settled target.
func settledNothing(out *Outcome) bool {
	if out == nil {
		return true
	}
	if out.Stats.Records > 0 {
		return false
	}
	for _, t := range out.Targets {
		if t.State == tool.StateDone {
			return false
		}
	}
	return true
}

// retryable returns the transient kind of a failed attempt when one more
// attempt may help, "" otherwise.
func (h *Host) retryable(out *Outcome, err error) string {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ""
		}
		return startErrorKind(err)
	}
	if out == nil || out.Err == nil || out.Status != tool.StatusFailed || !settledNothing(out) {
		return ""
	}
	switch out.startKind {
	case startSlow:
		// Alive and starved: contention, whatever the probe says.
		return startSlow
	case startHandshake, startOOM:
		if pressured(h.pressure()) {
			return out.startKind
		}
	}
	return ""
}

// withRetry runs one task, and once more after a transient start failure
// (see the file comment). The outcome says how many attempts ran and why
// the first failed (Outcome.Attempts, Outcome.Transient).
func (h *Host) withRetry(ctx context.Context, m tool.Manifest, run func() (*Outcome, error)) (*Outcome, error) {
	out, err := run()
	kind := h.retryable(out, err)
	if kind == "" {
		if out != nil {
			out.Attempts = 1
		}
		return out, err
	}
	p := h.pressure()
	if h.Governor != nil {
		h.Governor.Transient(kind)
	}
	why := startFailureText(kind, out, err)
	wait := jitter(retryBackoff)
	h.note(ctx, m, "warn", fmt.Sprintf("Tool %s did not start: %s; %s; retrying once in %s", m.Name, why, hostLabel(p, kind), wait.Round(100*time.Millisecond)), p, kind)
	t := time.NewTimer(wait)
	select {
	case <-ctx.Done():
		t.Stop()
		if out != nil {
			out.Attempts, out.Transient = 1, kind
			h.tagOverloaded(out, kind, p, 1)
		}
		return out, err
	case <-t.C:
	}
	if h.Governor != nil {
		h.Governor.Transient(resource.TransientRetried)
	}
	out2, err2 := run()
	p2 := h.pressure()
	if err2 == nil && out2 != nil && out2.Status != tool.StatusFailed {
		if h.Governor != nil {
			h.Governor.Transient(resource.TransientRecovered)
		}
		out2.Attempts, out2.Transient = 2, kind
		line := LogLine{Level: "info", Msg: fmt.Sprintf("Tool %s started on the second attempt (%s; retried)", m.Name, hostLabel(p, kind)),
			Fields: pressureFields(p, kind)}
		out2.Logs = append(out2.Logs, line)
		h.note(ctx, m, line.Level, line.Msg, p, kind)
		return out2, nil
	}
	if out2 != nil {
		out2.Attempts, out2.Transient = 2, kind
		if k2 := out2.startKind; k2 != "" && h.Governor != nil {
			h.Governor.Transient(k2)
		}
		h.tagOverloaded(out2, kind, maxPressure(p, p2), 2)
	}
	return out2, err2
}

// tagOverloaded marks a final start failure as caused by host pressure:
// the detail names it (core classifies it as infra.resource.host_pressure)
// and the error carries the attempts and the level.
func (h *Host) tagOverloaded(out *Outcome, kind string, p resource.Pressure, attempts int) {
	if out == nil || out.Err == nil || (kind != startSlow && !pressured(p)) {
		return
	}
	if !strings.Contains(out.Err.Detail, HostOverloaded) {
		out.Err.Detail = tool.CapDetail(out.Err.Detail + "; " + HostOverloaded + reasonsText(p))
	}
	out.Err.Attempts = attempts
	lvl := p.Level
	if !pressured(p) {
		lvl = resource.PressureElevated // a starved process is contention
	}
	out.Err.Pressure = string(lvl)
	out.Err.StartFailure = kind
}

func maxPressure(a, b resource.Pressure) resource.Pressure {
	rank := func(l resource.PressureLevel) int {
		switch l {
		case resource.PressureOverloaded:
			return 2
		case resource.PressureElevated:
			return 1
		}
		return 0
	}
	if rank(b.Level) > rank(a.Level) {
		return b
	}
	return a
}

func reasonsText(p resource.Pressure) string {
	if len(p.Reasons) == 0 {
		return ""
	}
	return " (" + strings.Join(p.Reasons, ", ") + ")"
}

func hostLabel(p resource.Pressure, kind string) string {
	if pressured(p) || kind == startSlow {
		return HostOverloaded + reasonsText(p)
	}
	return "transient start failure"
}

func startFailureText(kind string, out *Outcome, err error) string {
	switch {
	case err != nil:
		return "the process could not be started (" + err.Error() + ")"
	case kind == startOOM:
		return "the tool was killed for lack of memory before it settled anything"
	case out != nil && out.Err != nil:
		return out.Err.Detail
	}
	return kind
}

func pressureFields(p resource.Pressure, kind string) map[string]any {
	f := map[string]any{"pressure": string(p.Level), "start_failure": kind}
	if len(p.Reasons) > 0 {
		f["pressure_reasons"] = strings.Join(p.Reasons, ",")
	}
	return f
}

// note sends a line to the task's command log and the sensor's log.
func (h *Host) note(ctx context.Context, m tool.Manifest, level, msg string, p resource.Pressure, kind string) {
	l := LogLine{Level: level, Msg: msg, Fields: pressureFields(p, kind)}
	if h.LogSink != nil {
		h.LogSink(ctx, m.Name, l)
	}
	if h.Logger != nil {
		h.Logger.Warn(msg, "tool", m.Name, "pressure", string(p.Level), "start_failure", kind)
	} else if h.LogSink == nil {
		fmt.Fprintf(os.Stderr, "[toolhost] %s: %s\n", m.Name, msg)
	}
}

func jitter(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()-0.5)*0.5*float64(d)) //nolint:gosec // backoff jitter
}

// startKindAtHandshake is the kind of a missing handshake: a process that
// got almost no CPU since it started is starved (slow start), one that
// used CPU and still said nothing is not.
func startKindAtHandshake(cpu time.Duration, readable bool) string {
	if readable && cpu < slowStartCPU {
		return startSlow
	}
	return startHandshake
}

// exitedNoResult is the stop reason of a tool that ended without a result.
const exitedNoResult = "exited without a result"

// oomLike reports whether a task ended by a SIGKILL nobody asked for: the
// kernel's OOM killer (the host's, or the task envelope's).
func oomLike(res *executor.Result) bool {
	if res == nil || res.Killed != "" || res.State == nil {
		return false
	}
	ws, ok := res.State.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

// noHandshake records how a start without a handshake failed and returns
// the stop reason: a starved process (slow start) or a silent busy one.
func (s *session) noHandshake(hs time.Duration) string {
	used, readable := startCPU(s.cpu)
	s.out.startKind = startKindAtHandshake(used, readable)
	if s.out.startKind == startSlow {
		return "no handshake within " + hs.String() + ": the process is alive but got almost no CPU (slow start)"
	}
	return "no handshake within " + hs.String()
}

// execOOM is the stop reason and start-failure kind of an exec-profile task
// the kernel killed for memory ("" when it was not).
func execOOM(ctx, runCtx context.Context, res *executor.Result) (reason, kind string) {
	if res == nil || ctx.Err() != nil || runCtx.Err() != nil || !oomLike(res) {
		return "", ""
	}
	if res.EnvelopeOOM {
		return "killed at its memory limit (the tool's resources.memory)", "oom_envelope"
	}
	return "killed for lack of memory (SIGKILL)", startOOM
}

// startAndWait starts an exec-profile task once the governor admits it and
// waits for it to end.
func (h *Host) startAndWait(ctx, runCtx context.Context, m tool.Manifest, t executor.Task) (*executor.Result, error) {
	// The launch waits while the sensor's host is overloaded (Governor).
	release, err := h.admit(ctx, m)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := t.Start(runCtx); err != nil {
		return nil, fmt.Errorf("toolhost: start %s: %w", m.Name, err)
	}
	res, _ := t.Wait()
	return res, nil
}
