package toolhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/resource"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// pressureHostile are adapters that misbehave at start (research/318); ok
// is false for any other mode.
func pressureHostile(mode string) (code int, ok bool) {
	switch mode {
	case "slow-once":
		// The first start hangs before the handshake without using CPU (a
		// starved start); the second shakes hands and succeeds.
		mark := os.Getenv("TOOLHOST_MARK")
		if _, err := os.Stat(mark); err != nil {
			_ = os.WriteFile(mark, []byte("1"), 0o600)
			time.Sleep(time.Minute)
			return 0, true
		}
		return hostile("claims-ok"), true
	case "slow-always":
		time.Sleep(time.Minute)
		return 0, true
	case "spin":
		// Busy, and never answers hello: a tool bug, not a starved start.
		deadline := time.Now().Add(time.Minute)
		x := 0
		for time.Now().Before(deadline) {
			x++
		}
		return x & 1, true
	case "exit-at-once":
		return 3, true
	}
	return 0, false
}

// fakeGov is a Governor with a fixed pressure.
type fakeGov struct {
	mu        sync.Mutex
	p         resource.Pressure
	factor    float64
	admitted  int
	transient []string
	gate      chan struct{}
	admitErr  error
}

func (g *fakeGov) Admit(ctx context.Context, _ string) (func(), time.Duration, error) {
	start := time.Now()
	if g.gate != nil {
		select {
		case <-g.gate:
		case <-ctx.Done():
			return nil, time.Since(start), ctx.Err()
		}
	}
	if g.admitErr != nil {
		return nil, 0, g.admitErr
	}
	g.mu.Lock()
	g.admitted++
	g.mu.Unlock()
	return func() {}, time.Since(start), nil
}
func (g *fakeGov) StartTimeoutFactor() float64 { return g.factor }
func (g *fakeGov) Pressure() resource.Pressure {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.p
}
func (g *fakeGov) Transient(kind string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.transient = append(g.transient, kind)
}
func (g *fakeGov) kinds() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.Join(g.transient, ",")
}

func shortHandshake(t *testing.T, d time.Duration) {
	t.Helper()
	old, oldBackoff := handshakeTimeout, retryBackoff
	handshakeTimeout, retryBackoff = d, 50*time.Millisecond
	t.Cleanup(func() { handshakeTimeout, retryBackoff = old, oldBackoff })
}

func pressureRun(t *testing.T, h *Host, mode string, env map[string]string) *Outcome {
	t.Helper()
	exe, _ := os.Executable()
	m := hostileManifest
	m.Run = &tool.RunSpec{Argv: []string{exe}}
	if env == nil {
		env = map[string]string{}
	}
	env["TOOLHOST_HOSTILE"] = mode
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := h.RunManifest(ctx, m, tool.Task{Targets: oneTarget}, RunOptions{Trusted: true, Env: env,
		Credentials: map[string]string{"api_key": "sk-declared-123"}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The prod incident: a tool starved at start missed the 30 s handshake and
// was reported as crashed. A starved start is retried once and recovers.
func TestStarvedStartIsRetriedOnceAndRecovers(t *testing.T) {
	shortHandshake(t, 400*time.Millisecond)
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded, Reasons: []string{"cpu"}}, factor: 1}
	h := testHost(t)
	h.Governor = g
	var mu sync.Mutex
	var lines []string
	h.LogSink = func(_ context.Context, _ string, l LogLine) { mu.Lock(); lines = append(lines, l.Msg); mu.Unlock() }
	out := pressureRun(t, h, "slow-once", map[string]string{"TOOLHOST_MARK": filepath.Join(t.TempDir(), "mark")})
	if out.Status == tool.StatusFailed || out.Err != nil {
		t.Fatalf("status %s err %v", out.Status, out.Err)
	}
	if out.Attempts != 2 || out.Transient != resource.TransientSlowStart {
		t.Fatalf("attempts %d transient %q", out.Attempts, out.Transient)
	}
	if got := g.kinds(); got != "slow_start,retried,recovered" {
		t.Fatalf("transient counts %q", got)
	}
	mu.Lock()
	joined := strings.Join(lines, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "sensor host overloaded (cpu)") || !strings.Contains(joined, "second attempt") {
		t.Fatalf("command log does not explain the retry:\n%s", joined)
	}
}

// Without a governor the same starved start is still told apart from a
// crash and retried.
func TestStarvedStartWithoutGovernor(t *testing.T) {
	shortHandshake(t, 400*time.Millisecond)
	out := pressureRun(t, testHost(t), "slow-once", map[string]string{"TOOLHOST_MARK": filepath.Join(t.TempDir(), "mark")})
	if out.Status == tool.StatusFailed || out.Attempts != 2 {
		t.Fatalf("status %s attempts %d err %v", out.Status, out.Attempts, out.Err)
	}
}

// A start that stays starved fails after the one retry, as host pressure:
// the class says so, and so do the attempts and the level.
func TestStarvedTwiceFailsAsHostPressure(t *testing.T) {
	shortHandshake(t, 300*time.Millisecond)
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded, Reasons: []string{"cpu", "io"}}, factor: 1}
	h := testHost(t)
	h.Governor = g
	out := pressureRun(t, h, "slow-always", nil)
	if out.Status != tool.StatusFailed || out.Err == nil || out.Attempts != 2 {
		t.Fatalf("status %s attempts %d err %v", out.Status, out.Attempts, out.Err)
	}
	if !strings.Contains(out.Err.Detail, HostOverloaded+" (cpu, io)") {
		t.Fatalf("detail %q", out.Err.Detail)
	}
	f := core.ClassifyFailure(core.FailureInput{Err: out.Err, Tool: "hostile"})
	if f.Class != core.FailureHostPressure || f.Evidence.Reason != core.ReasonSlowStart ||
		f.Evidence.Attempts != 2 || f.Evidence.Pressure != "overloaded" {
		t.Fatalf("failure %+v", f)
	}
}

// The handshake waits longer on a stalled host: a start that needs more
// than the base timeout succeeds at once when the governor scales it.
func TestHandshakeScalesWithPressure(t *testing.T) {
	shortHandshake(t, 250*time.Millisecond)
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded}, factor: 4}
	h := testHost(t)
	h.Governor = g
	if got := h.handshakeTimeout(); got != time.Second {
		t.Fatalf("scaled handshake %s, want 1s", got)
	}
	g.factor = 99 // a governor out of bounds is clamped
	if got := h.handshakeTimeout(); got != time.Second {
		t.Fatalf("clamped handshake %s, want 1s", got)
	}
}

// A busy tool that never answers is a tool bug: with an ok host it is
// not retried and stays a crash.
func TestBusyNoHandshakeOnAQuietHostIsNotRetried(t *testing.T) {
	// Long enough that the spinning tool gets well over the slow-start
	// CPU mark even on a loaded test machine.
	shortHandshake(t, 1500*time.Millisecond)
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOK}, factor: 1}
	h := testHost(t)
	h.Governor = g
	out := pressureRun(t, h, "spin", nil)
	if out.Attempts != 1 || out.Status != tool.StatusFailed {
		t.Fatalf("attempts %d status %s", out.Attempts, out.Status)
	}
	f := core.ClassifyFailure(core.FailureInput{Err: out.Err, Tool: "hostile"})
	if f.Class != core.FailureToolCrashed || f.Evidence.Reason != core.ReasonNoHandshake {
		t.Fatalf("failure %+v", f)
	}
}

// The same busy tool under host pressure gets its one retry.
func TestNoHandshakeUnderPressureIsRetried(t *testing.T) {
	shortHandshake(t, 1500*time.Millisecond)
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureElevated, Reasons: []string{"cpu"}}, factor: 1}
	h := testHost(t)
	h.Governor = g
	out := pressureRun(t, h, "spin", nil)
	// On a loaded test machine the spinning tool may also look starved:
	// either way it is retried once.
	if out.Attempts != 2 || !strings.Contains(g.kinds(), ",retried") {
		t.Fatalf("attempts %d kinds %q", out.Attempts, g.kinds())
	}
	f := core.ClassifyFailure(core.FailureInput{Err: out.Err, Tool: "hostile"})
	if f.Class != core.FailureHostPressure || f.Evidence.Pressure != "elevated" {
		t.Fatalf("failure %+v", f)
	}
}

// A tool that exits at once is a crash, never retried, even under
// pressure: it would crash again.
func TestImmediateCrashIsNotRetried(t *testing.T) {
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded}, factor: 1}
	h := testHost(t)
	h.Governor = g
	out := pressureRun(t, h, "exit-at-once", nil)
	if out.Attempts != 1 || g.kinds() != "" {
		t.Fatalf("attempts %d kinds %q", out.Attempts, g.kinds())
	}
}

// Every launch passes the governor first; a launch that is still held
// when its job ends never starts.
func TestLaunchWaitsForTheGovernor(t *testing.T) {
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded}, factor: 1, gate: make(chan struct{})}
	h := testHost(t)
	h.Governor = g
	go func() { time.Sleep(300 * time.Millisecond); close(g.gate) }()
	start := time.Now()
	out := pressureRun(t, h, "claims-ok", nil)
	if out.Status == tool.StatusFailed || time.Since(start) < 300*time.Millisecond || g.admitted != 1 {
		t.Fatalf("status %s took %s admitted %d", out.Status, time.Since(start), g.admitted)
	}

	g2 := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded}, factor: 1, gate: make(chan struct{})}
	h.Governor = g2
	exe, _ := os.Executable()
	m := hostileManifest
	m.Run = &tool.RunSpec{Argv: []string{exe}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := h.RunManifest(ctx, m, tool.Task{Targets: oneTarget}, RunOptions{Trusted: true,
		Env: map[string]string{"TOOLHOST_HOSTILE": "claims-ok"}, Credentials: map[string]string{"api_key": "k"}})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || g2.admitted != 0 {
		t.Fatalf("held launch: err %v admitted %d", err, g2.admitted)
	}
}

// What may be retried, and what never is.
func TestRetryableClasses(t *testing.T) {
	h := testHost(t)
	g := &fakeGov{p: resource.Pressure{Level: resource.PressureOverloaded}, factor: 1}
	h.Governor = g
	failed := func(kind string, mut func(*Outcome)) *Outcome {
		o := &Outcome{Status: tool.StatusFailed, Err: &tool.Error{Class: tool.ToolCrashed, Detail: "x"}, startKind: kind}
		if mut != nil {
			mut(o)
		}
		return o
	}
	for _, c := range []struct {
		name string
		out  *Outcome
		err  error
		want string
	}{
		{"slow start", failed(startSlow, nil), nil, startSlow},
		{"handshake under pressure", failed(startHandshake, nil), nil, startHandshake},
		{"host oom under pressure", failed(startOOM, nil), nil, startOOM},
		{"fork EAGAIN", nil, &os.SyscallError{Syscall: "fork", Err: syscall.EAGAIN}, startEAGAIN},
		{"policy refusal", &Outcome{Status: tool.StatusFailed, Err: tool.AsError(tool.Refused("no"))}, nil, ""},
		{"crash after records", failed(startOOM, func(o *Outcome) { o.Stats.Records = 3 }), nil, ""},
		{"crash after a settled target", failed(startSlow, func(o *Outcome) { o.Targets = []TargetOutcome{{State: tool.StateDone}} }), nil, ""},
		{"envelope oom", failed("", func(o *Outcome) { o.Err.StartFailure = "oom_envelope" }), nil, ""},
		{"canceled", nil, context.Canceled, ""},
		{"partial", &Outcome{Status: tool.StatusPartial, Err: &tool.Error{Class: tool.Timeout}, startKind: startSlow}, nil, ""},
	} {
		if got := h.retryable(c.out, c.err); got != c.want {
			t.Errorf("%s: retryable %q, want %q", c.name, got, c.want)
		}
	}
	g.p.Level = resource.PressureOK
	if got := h.retryable(failed(startHandshake, nil), nil); got != "" {
		t.Errorf("handshake on a quiet host retried: %q", got)
	}
	if got := h.retryable(failed(startOOM, nil), nil); got != "" {
		t.Errorf("oom on a quiet host retried: %q", got)
	}
}

// A tool cannot pass its own failure off as the host's: only the runtime
// sets the pressure, whatever the detail says.
func TestToolCannotClaimHostPressure(t *testing.T) {
	e := &tool.Error{Class: tool.ToolCrashed, Detail: "no handshake; " + HostOverloaded + " (cpu) slow start lack of memory"}
	if c, _ := e.FailureClass(); c != string(core.FailureToolCrashed) {
		t.Fatalf("a tool's detail made class %s", c)
	}
	e = &tool.Error{Class: tool.ToolError, Detail: "lack of memory"}
	if c, _ := e.FailureClass(); c == string(core.FailureMemory) {
		t.Fatal("a tool's detail made a memory failure")
	}
}

func TestEnvelopeFromManifest(t *testing.T) {
	m := hostileManifest
	m.Resources.Profile = tool.ProfileLight
	e := envelopeFor(m)
	if e.CPU != 1 || e.MemoryMax != 512<<20 || e.Pids != 256 {
		t.Fatalf("light envelope %+v", e)
	}
	m.Resources = tool.Resources{Profile: tool.ProfileHeavy, Memory: tool.ByteSize(6 << 30)}
	if e := envelopeFor(m); e.CPU != 4 || e.MemoryMax != 6<<30 || e.Pids != 1024 {
		t.Fatalf("heavy envelope with memory %+v", e)
	}
	if e := envelopeFor(hostileManifest); e.CPU != 2 || e.MemoryMax != 2<<30 {
		t.Fatalf("default envelope %+v", e)
	}
	_ = executor.Envelope{}
}
