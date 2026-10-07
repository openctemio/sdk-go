// Package toolhost is the runtime side of the tool contract: it runs one
// task of a tool (pkg/tool) out of process, inside the Executor sandbox
// (pkg/sensorkit/executor), and turns what the tool reports into a checked,
// stamped CTIS report.
//
// Stability: Beta (docs/STABILITY.md). The sensorkit task pipeline will be
// its main caller; until then a sensor calls it from its scanners.
//
// Three kinds of tool reach it, all out of process:
//
//   - a Go tool compiled into the sensor (RunBuiltin): the sensor binary is
//     re-executed as "<sensor> __openctem-tool <name>" (pkg/tool/adapter
//     Dispatch) and speaks adapter protocol v1;
//   - a tool that is its own program and speaks adapter protocol v1
//     (RunManifest, run.profile adapter);
//   - a CLI that writes CTIS or SARIF, with no code (RunManifest,
//     run.profile exec).
//
// Before anything starts, every task is admitted (Admit): the manifest's
// permissions intersected with the sensor-local policy (Host.Policy). A
// target the policy refuses is removed from the task and reported skipped
// (refused_by_policy); the tool never receives it.
//
// Whatever the tool does on its side, the host checks every message and
// record again: protocol limits (1 MiB lines, an invalid-message budget,
// the idle timeout and the task timeout), CTIS validity, the manifest's
// produces (undeclared output is quarantined), record and byte caps (the
// tool is stopped when it reaches them), control and bidi characters,
// artifacts confined to the task directory, and provenance stamped by the
// runtime. A retest task (tool.Retester) is admitted the same way, carries
// only items on admitted targets, may send verdicts but no records, and
// its Fixed verdicts stand only for targets reported done in a task that
// finished (Outcome.Verdicts). Only credentials the manifest declares are
// delivered, inside
// the run message (never as a file, never in the environment or argv),
// and their values are masked in everything the host keeps.
package toolhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/openctemio/ctis/importer/mapping"
	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/internal/toolwire"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// Protocol limits.
const (
	// MaxInvalidMessages is how many unreadable or refused messages an
	// adapter may send before it is stopped.
	MaxInvalidMessages = 1000
	// MaxStderr is how much of a tool's stderr is kept.
	MaxStderr = 64 << 10
	// MaxArtifactBytes bounds one artifact.
	MaxArtifactBytes = 64 << 20
	// MaxTargets bounds a task's targets.
	MaxTargets = 10000
	// MaxLogLines is how many log lines an Outcome keeps.
	MaxLogLines = 500
)

var (
	handshakeTimeout = 30 * time.Second
	cancelGrace      = 10 * time.Second
)

// Host runs tool tasks.
type Host struct {
	// Backend runs the task processes (nil: executor.Current()).
	Backend executor.Backend
	// Self is the sensor binary re-executed for compiled-in tools (""
	// this program). It must call adapter.Dispatch first in main.
	Self string
	// Sensor names the sensor in the provenance.
	Sensor string
	// RuntimeName and RuntimeVersion are announced to adapters.
	RuntimeName, RuntimeVersion string
	// Logger receives the tools' log lines, redacted (nil: kept in the
	// Outcome only).
	Logger *slog.Logger
	// LogSink also receives each of a task's log lines, redacted and
	// cleaned, with the context the task was run with (which carries the
	// platform command, core.CommandIDFromContext). It must not block.
	LogSink func(ctx context.Context, tool string, l LogLine)
	// Policy admits every task before it starts (see Admit): the
	// sensor-local policy. nil admits by the manifest alone.
	Policy Policy
}

// RunOptions adjust one task.
type RunOptions struct {
	// Credentials the operator stored for this tool. Only those the
	// manifest declares are delivered; a declared required one that is
	// missing fails the task before it starts.
	Credentials map[string]string
	// WritePaths the task may write besides its directory (a built-in
	// tool's cache).
	WritePaths []string
	// Limits override the sandbox's default limits (zero: defaults).
	Limits executor.Limits
	// Env are extra environment variables, added to the scanner allowlist.
	Env map[string]string
	// Progress receives progress, at most once a second.
	Progress func(done, total int, msg string)
	// Trusted says the operator installed this adapter (RunManifest). An
	// untrusted adapter runs only on a backend that enforces the network
	// class in required mode.
	Trusted bool
	// Dir is the manifest's directory: a relative program in run.argv is
	// resolved against it.
	Dir string
	// Mode is the sensor mode the task runs in (daemon or runner; "": not
	// checked against the manifest's modes).
	Mode tool.Mode
}

// TargetOutcome is one target's outcome.
type TargetOutcome struct {
	Ref    string           `json:"ref"`
	Value  string           `json:"value"`
	State  tool.TargetState `json:"state"`
	Class  tool.ErrorClass  `json:"class,omitempty"`
	Detail string           `json:"detail,omitempty"`
}

// Stats are what the host accepted and refused.
type Stats struct {
	Records     int            `json:"records"`
	Bytes       int64          `json:"bytes"`
	Capped      bool           `json:"capped,omitempty"`
	Quarantined map[string]int `json:"quarantined,omitempty"`
	Invalid     int            `json:"invalid,omitempty"`
	// ContractViolations counts records that miss the task capability's
	// contract (required paths, allowed outputs).
	ContractViolations int `json:"contract_violations,omitempty"`
}

// LogLine is one line a tool logged (redacted).
type LogLine struct {
	Level  string         `json:"level"`
	Msg    string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Artifact is a file a tool produced, verified (size and digest) and read.
type Artifact struct {
	Name      string
	MediaType string
	SHA256    string
	Data      []byte
}

// Outcome is how a task ended. Report holds every accepted record, also
// for a failed task.
type Outcome struct {
	Report    *ctis.Report
	Status    tool.Status
	Err       *tool.Error
	Targets   []TargetOutcome
	Stats     Stats
	Logs      []LogLine
	Artifacts []Artifact
	// Verdicts of a retest task, one per item in task order (see
	// tool.Retester): an item whose target the policy refused, an item
	// without a verdict, and Fixed on a target not reported done or in a
	// task that did not finish are Unverifiable.
	Verdicts []tool.RetestVerdict
	Sandbox  executor.Status
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// ReportJSON is the report as JSON (a scanner's raw output for the
// existing parsers: the generic CTIS parser reads it as it is).
func (o *Outcome) ReportJSON() ([]byte, error) { return json.Marshal(o.Report) }

// RunBuiltin runs one task of a tool compiled into this sensor: the binary
// is re-executed as "<self> __openctem-tool <name>" in the sandbox.
func (h *Host) RunBuiltin(ctx context.Context, t tool.Tool, task tool.Task, o RunOptions) (*Outcome, error) {
	self := h.Self
	if self == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("toolhost: find this program: %w", err)
		}
		self = exe
	}
	m := t.Manifest().Normalized()
	return h.run(ctx, m, task, o, []string{self, adapter.ToolArg, m.Name}, "built-in (re-executed, adapter protocol v1)")
}

// RunManifest runs one task of a tool described by a manifest file: an
// adapter (run.profile adapter) or a CLI (run.profile exec).
func (h *Host) RunManifest(ctx context.Context, m tool.Manifest, task tool.Task, o RunOptions) (*Outcome, error) {
	m = m.Normalized()
	if m.Run == nil {
		return nil, errors.New("toolhost: the manifest has no run section")
	}
	if !o.Trusted {
		st := h.backend().Status()
		if !st.NetworkEnforced || st.Mode != executor.ModeRequired {
			return nil, tool.Refused("an untrusted adapter runs only on a sandbox backend that enforces its network class in required mode")
		}
	}
	argv := slices.Clone(m.Run.Argv)
	if o.Dir != "" && !filepath.IsAbs(argv[0]) && strings.ContainsRune(argv[0], filepath.Separator) {
		argv[0] = filepath.Join(o.Dir, argv[0])
	}
	if m.Run.Profile == tool.ProfileExec {
		return h.runExec(ctx, m, task, o, argv)
	}
	return h.run(ctx, m, task, o, argv, "adapter (adapter protocol v1)")
}

func (h *Host) backend() executor.Backend {
	if h.Backend != nil {
		return h.Backend
	}
	return executor.Current()
}

// prepared is a task checked and ready to start.
type prepared struct {
	m       tool.Manifest
	task    tool.Task
	creds   []toolwire.Credential
	secrets []string
	workdir string
	asm     *toolrt.Assembler
	// refused are the targets the policy refused (never sent to the tool).
	refused []TargetOutcome
	// timeout is the task's run time after admission.
	timeout time.Duration
	// asked are the retest items as asked; refusedItems those on refused
	// targets (never sent to the tool).
	asked        []tool.RetestItem
	refusedItems map[string]bool
	// rateLine says the local policy changed the rate (nil: it did not).
	rateLine *LogLine
	// mapping turns an exec tool's json or jsonl output into CTIS.
	mapping *mapping.Mapping
	// notes are the runtime's own log lines for the outcome (parser
	// issues), bounded.
	notes []LogLine
}

// prepare checks the manifest and the task (targets, config), admits it
// against the policy, checks the credentials and makes the task directory.
// Nothing exists on disk and no credential is read before the task is
// admitted.
func (h *Host) prepare(ctx context.Context, m tool.Manifest, task tool.Task, o RunOptions) (*prepared, *tool.Error, error) {
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	if task.ID == "" {
		task.ID = fmt.Sprintf("task-%d", time.Now().UnixNano())
	}
	if ierr := checkTargets(m, task.Targets); ierr != nil {
		return nil, ierr, nil
	}
	if ierr := toolrt.CheckRetest(m, task); ierr != nil {
		return nil, ierr, nil
	}
	task, ierr := admitContract(m, task)
	if ierr != nil {
		return nil, ierr, nil
	}
	cfg, ierr := effectiveConfig(m, task.Config)
	if ierr != nil {
		return nil, ierr, nil
	}
	cfg, rateLine, err := capRate(m, cfg, h.Policy)
	if err != nil {
		return nil, tool.AsError(tool.Invalid("%v", err)), nil
	}
	task.Config = cfg
	adm, ierr := Admit(ctx, m, task, h.Policy, o.Mode)
	if ierr != nil {
		return nil, ierr, nil
	}
	task = adm.Task
	p := &prepared{m: m, task: task, refused: adm.Refused, timeout: adm.Timeout, asked: task.Retest, rateLine: rateLine}
	if task.IsRetest() && len(adm.Refused) > 0 {
		// A retest never reaches a target the policy refused: its items
		// are not sent and end unverifiable.
		refused := map[string]bool{}
		for _, r := range adm.Refused {
			refused[r.Ref] = true
		}
		p.refusedItems = map[string]bool{}
		kept := task.Retest[:0:0]
		for _, it := range task.Retest {
			if refused[it.Target] {
				p.refusedItems[it.Ref] = true
				continue
			}
			kept = append(kept, it)
		}
		p.task.Retest = kept
	}
	for _, req := range m.Permissions.Credentials {
		v, ok := o.Credentials[req.Name]
		if !ok || v == "" {
			if req.Required {
				return nil, tool.AsError(tool.Invalid("credential %q is required and not configured on this sensor", req.Name)), nil
			}
			continue
		}
		p.creds = append(p.creds, toolwire.Credential{Name: req.Name, Value: v})
		if len(v) >= 4 {
			p.secrets = append(p.secrets, v)
		}
	}
	slices.SortFunc(p.secrets, func(a, b string) int { return len(b) - len(a) })
	dir, err := os.MkdirTemp("", "openctem-tool-")
	if err != nil {
		return nil, nil, fmt.Errorf("toolhost: task directory: %w", err)
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	p.workdir = dir
	p.asm = toolrt.NewAssembler(m, p.task, toolrt.NewChecker(m))
	return p, nil, nil
}

func checkTargets(m tool.Manifest, targets []tool.Target) *tool.Error {
	if len(targets) > MaxTargets {
		return tool.AsError(tool.Invalid("%d targets, more than %d", len(targets), MaxTargets))
	}
	if m.Class == tool.TargetScan && len(targets) == 0 {
		return tool.AsError(tool.Invalid("a target-scan task needs targets"))
	}
	seen := map[string]bool{}
	for i, t := range targets {
		if t.Ref == "" || seen[t.Ref] {
			return tool.AsError(tool.Invalid("target %d: a unique ref is required", i))
		}
		seen[t.Ref] = true
		if strings.TrimSpace(t.Value) == "" || strings.IndexFunc(t.Value, unicode.IsControl) >= 0 || len(t.Value) > 4096 {
			return tool.AsError(tool.Invalid("target %q: empty, too long or with control characters", t.Ref))
		}
		if t.Type != "" && len(m.Consumes) > 0 && !slices.Contains(m.Consumes, t.Type) {
			return tool.AsError(tool.Invalid("target %q: %s does not consume %s", t.Ref, m.Name, t.Type))
		}
	}
	return nil
}

// effectiveConfig validates the task's configuration against the schema
// and fills the defaults.
func effectiveConfig(m tool.Manifest, raw json.RawMessage) (json.RawMessage, *tool.Error) {
	schema, err := m.ConfigSchema()
	if err != nil {
		return nil, tool.AsError(tool.Invalid("config schema: %v", err))
	}
	raw = bytes.TrimSpace(raw)
	empty := len(raw) == 0 || string(raw) == "{}" || string(raw) == "null"
	if schema == nil {
		if !empty {
			return nil, tool.AsError(tool.Invalid("%s takes no configuration", m.Name))
		}
		return json.RawMessage("{}"), nil
	}
	if empty {
		raw = []byte("{}")
	}
	if err := schema.ValidateJSON(raw); err != nil {
		return nil, tool.AsError(tool.Invalid("%v", err))
	}
	var given map[string]any
	if err := json.Unmarshal(raw, &given); err != nil {
		return nil, tool.AsError(tool.Invalid("%v", err))
	}
	merged := schema.Defaults()
	for k, v := range given {
		if sub, ok := v.(map[string]any); ok {
			if def, ok := merged[k].(map[string]any); ok {
				for sk, sv := range sub {
					def[sk] = sv
				}
				continue
			}
		}
		merged[k] = v
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return nil, tool.AsError(tool.Invalid("%v", err))
	}
	return b, nil
}

func (p *prepared) redact(s string) string {
	for _, v := range p.secrets {
		s = strings.ReplaceAll(s, v, tool.Redacted)
	}
	return s
}

// failedOutcome is the outcome of a task refused before it started.
func (h *Host) failedOutcome(m tool.Manifest, task tool.Task, e *tool.Error) *Outcome {
	asm := toolrt.NewAssembler(m, task, toolrt.NewChecker(m))
	out := &Outcome{Status: tool.StatusFailed, Err: e, Report: asm.Report(time.Now().UTC()), ExitCode: -1}
	for _, it := range task.Retest {
		detail := "the retest did not run"
		if e != nil {
			detail += ": " + string(e.Class)
		}
		out.Verdicts = append(out.Verdicts, tool.RetestVerdict{Ref: it.Ref, Verdict: tool.Unverifiable, Detail: detail})
	}
	if e != nil && e.Class == tool.RefusedByPolicy {
		out.Status = tool.StatusFailed
	}
	h.stamp(out, m, task, "not started")
	return out
}

func (h *Host) stamp(out *Outcome, m tool.Manifest, task tool.Task, execution string) {
	toolrt.Stamp(out.Report, toolrt.Provenance{
		Tool: m.Name, ToolVersion: m.Version, ManifestDigest: m.Digest(), Protocol: toolwire.Version,
		Execution: execution, Sandbox: out.Sandbox, Network: string(m.Permissions.Network), Sensor: h.Sensor,
		TaskID: task.ID, Attempt: task.Attempt, Status: out.Status, Records: out.Stats.Records,
		Quarantined: out.Stats.Quarantined, Invalid: out.Stats.Invalid, Capped: out.Stats.Capped,
		Capability: task.Capability, ContractViolations: out.Stats.ContractViolations,
	})
}

// session is one running adapter task.
type session struct {
	h   *Host
	p   *prepared
	o   RunOptions
	out *Outcome
	// ctx is the context the task was run with (for LogSink).
	ctx context.Context

	invalid  int
	lastProg time.Time
	result   *toolwire.Result
	logMu    sync.Mutex
}

// run runs an adapter-protocol task.
func (h *Host) run(ctx context.Context, m tool.Manifest, task tool.Task, o RunOptions, argv []string, execution string) (*Outcome, error) {
	start := time.Now()
	p, ierr, err := h.prepare(ctx, m, task, o)
	if err != nil {
		return nil, err
	}
	if ierr != nil {
		return h.failedOutcome(m, task, ierr), nil
	}
	defer func() { _ = os.RemoveAll(p.workdir) }()

	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return nil, err
	}
	defer func() { _ = inW.Close(); _ = outR.Close() }()
	stderr := &cappedBuffer{max: MaxStderr}
	be := h.backend()
	t, err := be.Prepare(executor.TaskSpec{
		ID: m.Name, Argv: argv, Env: core.ScannerEnviron(o.Env), SetEnv: o.Env, Dir: p.workdir,
		WritePaths: append([]string{p.workdir}, o.WritePaths...), Limits: o.Limits,
		Network: networkClass(m.Permissions.Network), Stdin: inR, Stdout: outW, Stderr: stderr,
		Hooks: executor.ProcessHooks{Configure: core.ConfigureScannerProcess, Started: core.ApplyScannerPriority, Finished: core.ReapScannerProcess},
	})
	if err != nil {
		_ = inR.Close()
		_ = outW.Close()
		return nil, fmt.Errorf("toolhost: %w", err)
	}
	defer func() { _ = t.Cleanup() }()

	_, idle, _, maxRecords := m.Resources.Limits()
	timeout := p.timeout
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !task.Deadline.IsZero() {
		var c context.CancelFunc
		runCtx, c = context.WithDeadline(runCtx, task.Deadline)
		defer c()
	}
	// The process gets its own context: a cancel is a protocol cancel
	// first (the tool may stop cleanly within the grace), then a kill.
	procCtx, procCancel := context.WithTimeout(context.WithoutCancel(ctx), timeout+3*cancelGrace)
	defer procCancel()
	if err := t.Start(procCtx); err != nil {
		_ = inR.Close()
		_ = outW.Close()
		return nil, fmt.Errorf("toolhost: start %s: %w", m.Name, err)
	}
	_ = inR.Close()
	_ = outW.Close()

	s := &session{h: h, p: p, o: o, out: &Outcome{Sandbox: be.Status()}, ctx: ctx}
	_, _, maxBytes, _ := m.Resources.Limits()
	stopReason, stopClass := s.drive(runCtx, ctx, t, toolwire.NewWriter(inW), outR, idle, maxRecords, maxBytes)
	_ = inW.Close()

	waitDone := make(chan *executor.Result, 1)
	go func() {
		res, _ := t.Wait()
		waitDone <- res
	}()
	var res *executor.Result
	select {
	case res = <-waitDone:
	case <-time.After(cancelGrace):
		t.Kill("did not exit after its result")
		res = <-waitDone
	}
	s.finish(res, stopReason, stopClass, stderr, start, execution)
	return s.out, nil
}

func networkClass(n tool.Network) executor.NetworkClass {
	switch n {
	case tool.NetNone:
		return executor.NetworkNone
	case tool.NetTargets:
		return executor.NetworkTargetsOnly
	case tool.NetEgressProxy:
		return executor.NetworkEgressProxy
	}
	return executor.NetworkAny
}

type lineOrErr struct {
	line []byte
	err  error
}

// drive speaks the protocol until the result, a protocol violation, the
// idle timeout, the task timeout or a cancel. It returns why it stopped
// the tool ("" when the tool sent its result).
func (s *session) drive(runCtx, parent context.Context, t executor.Task, w *toolwire.Writer, out io.Reader,
	idle time.Duration, maxRecords int, maxBytes int64) (string, tool.ErrorClass) {
	lines := make(chan lineOrErr, 64)
	go func() {
		r := toolwire.NewReader(out)
		for {
			line, err := r.Next()
			lines <- lineOrErr{line, err}
			if err != nil {
				close(lines)
				return
			}
		}
	}()
	m, p := s.p.m, s.p
	hello := toolwire.Hello{Envelope: toolwire.Env(toolwire.TypeHello), Protocol: []int{toolwire.Version},
		Runtime:  toolwire.RuntimeInfo{Name: firstNonEmpty(s.h.RuntimeName, "openctem-sensor"), Version: s.h.RuntimeVersion, OS: runtime.GOOS, Arch: runtime.GOARCH},
		Limits:   toolwire.Limits{MaxLine: toolwire.MaxLine, MaxRecords: maxRecords, MaxOutputBytes: maxBytes, MaxArtifactBytes: MaxArtifactBytes},
		Features: toolwire.Features}
	if err := w.Write(hello); err != nil {
		return "the tool did not read its input: " + err.Error(), tool.ToolCrashed
	}
	const (
		stHello = iota
		stManifest
		stRunning
	)
	state := stHello
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	reset := func(d time.Duration) {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(d)
	}
	stop := func(reason string, class tool.ErrorClass) (string, tool.ErrorClass) {
		t.Kill(reason)
		return reason, class
	}
	canceled := false
	var cancelAt <-chan time.Time
	for {
		select {
		case <-runCtx.Done():
			if parent.Err() != nil {
				if !canceled {
					canceled = true
					_ = w.Write(toolwire.Cancel{Envelope: toolwire.Env(toolwire.TypeCancel), Reason: "canceled"})
					cancelAt = time.After(cancelGrace)
				}
				runCtx = context.Background() // keep reading until the result or the grace ends
				continue
			}
			return stop("task timeout", tool.Timeout)
		case <-cancelAt:
			return stop("canceled (did not stop within the grace period)", tool.Canceled)
		case <-timer.C:
			if state != stRunning {
				return stop("no handshake within "+handshakeTimeout.String(), tool.ToolCrashed)
			}
			return stop("no message for "+idle.String()+" (idle timeout)", tool.Timeout)
		case le, ok := <-lines:
			if !ok || le.err != nil {
				if le.err != nil && errors.Is(le.err, toolwire.ErrLineTooLong) {
					return stop("a message larger than 1 MiB", tool.OutputRejected)
				}
				if canceled {
					return "canceled", tool.Canceled
				}
				return "exited without a result", tool.ToolCrashed
			}
			if state == stRunning {
				reset(idle)
			}
			env, err := toolwire.Peek(le.line)
			if err != nil || env.V != toolwire.Version {
				if s.bad() {
					return stop("too many invalid messages", tool.OutputRejected)
				}
				continue
			}
			switch state {
			case stHello:
				var hr toolwire.HelloReply
				if env.Type != toolwire.TypeHello || toolwire.Decode(le.line, &hr) != nil {
					return stop("the first message is not hello", tool.ToolCrashed)
				}
				if hr.Protocol != toolwire.Version {
					return stop(fmt.Sprintf("protocol %d is not supported", hr.Protocol), tool.ToolCrashed)
				}
				if err := w.Write(toolwire.Envelope{V: toolwire.Version, Type: toolwire.TypeDescribe}); err != nil {
					return stop("the tool closed its input", tool.ToolCrashed)
				}
				state = stManifest
			case stManifest:
				if env.Type != toolwire.TypeManifest {
					if s.bad() {
						return stop("too many invalid messages", tool.OutputRejected)
					}
					continue
				}
				var mm toolwire.ManifestMsg
				if toolwire.Decode(le.line, &mm) != nil {
					return stop("unreadable manifest", tool.OutputRejected)
				}
				var self tool.Manifest
				d := json.NewDecoder(bytes.NewReader(mm.Manifest))
				d.DisallowUnknownFields()
				// How the tool is started is the runtime's business; the
				// rest must match the file exactly.
				want := m
				want.Run, self.Run = nil, nil
				if d.Decode(&self) != nil || func() bool { self.Run = nil; return self.Normalized().Digest() != want.Digest() }() {
					return stop("the tool describes itself differently from its manifest", tool.OutputRejected)
				}
				run := toolwire.Run{Envelope: toolwire.Env(toolwire.TypeRun), Task: toolwire.RunTask{Task: p.task, Workdir: p.workdir, Credentials: p.creds}}
				if err := w.Write(run); err != nil {
					return stop("the tool closed its input", tool.ToolCrashed)
				}
				state = stRunning
				reset(idle)
			case stRunning:
				if res, stopNow, reason, class := s.handle(env, le.line); stopNow {
					return stop(reason, class)
				} else if res != nil {
					s.result = res
					return "", ""
				}
			}
		}
	}
}

func (s *session) bad() bool {
	s.invalid++
	return s.invalid > MaxInvalidMessages
}

// handle processes one message of a running task.
func (s *session) handle(env toolwire.Envelope, line []byte) (res *toolwire.Result, stop bool, reason string, class tool.ErrorClass) {
	asm, chk := s.p.asm, s.p.asm.Checker()
	refuse := func(why string) (*toolwire.Result, bool, string, tool.ErrorClass) {
		s.log("warn", "refused output: "+why, nil)
		if s.bad() {
			return nil, true, "too many invalid messages", tool.OutputRejected
		}
		return nil, false, "", ""
	}
	switch env.Type {
	case toolwire.TypeRecord:
		if s.p.task.IsRetest() {
			return refuse("a retest task reports verdicts, not records")
		}
		var rec toolwire.Record
		if toolwire.Decode(line, &rec) != nil {
			return refuse("unreadable record")
		}
		if rec.Target != "" {
			if _, ok := asm.LookupTarget(rec.Target); !ok {
				return refuse("record for a target not in the task")
			}
		}
		var err error
		switch rec.Kind {
		case tool.KindAsset:
			var a ctis.Asset
			if a, err = chk.AssetJSON(rec.Data); err == nil {
				asm.AddCheckedAsset(a)
			}
		case tool.KindFinding:
			var f ctis.Finding
			if f, err = chk.FindingJSON(rec.Data); err == nil {
				err = asm.AddCheckedFinding(rec.Target, f)
			}
		case tool.KindDependency:
			var d ctis.Dependency
			if d, err = chk.DependencyJSON(rec.Data); err == nil {
				asm.AddCheckedDependency(d)
			}
		default:
			return refuse("unknown record kind")
		}
		switch {
		case errors.Is(err, tool.ErrOutputLimit):
			return nil, true, "output limit reached", tool.ResourceExhausted
		case errors.Is(err, tool.ErrUndeclaredOutput):
			s.log("warn", "quarantined: "+s.p.redact(err.Error()), nil)
		case err != nil:
			return refuse(s.p.redact(err.Error()))
		}
	case toolwire.TypeReportInfo:
		var ri toolwire.ReportInfoMsg
		if toolwire.Decode(line, &ri) != nil {
			return refuse("unreadable report info")
		}
		info, err := chk.InfoJSON(ri.Info)
		if err != nil {
			return refuse(s.p.redact(err.Error()))
		}
		asm.SetInfo(info)
	case toolwire.TypeTargetStatus:
		var ts toolwire.TargetStatus
		if toolwire.Decode(line, &ts) != nil {
			return refuse("unreadable target status")
		}
		e := ts.Error.ToError()
		if e != nil {
			e.Detail = s.p.redact(toolrt.CleanString(e.Detail))
		}
		if err := asm.Target(ts.Target, ts.Status, e); err != nil {
			return refuse(err.Error())
		}
	case toolwire.TypeLog:
		var l toolwire.Log
		if toolwire.Decode(line, &l) != nil {
			return refuse("unreadable log")
		}
		s.log(l.Level, l.Msg, l.Fields)
	case toolwire.TypeProgress:
		var pr toolwire.Progress
		if toolwire.Decode(line, &pr) == nil && s.o.Progress != nil && time.Since(s.lastProg) >= time.Second {
			s.lastProg = time.Now()
			s.o.Progress(max(pr.Done, 0), max(pr.Total, 0), s.p.redact(toolrt.CleanString(truncate(pr.Msg, 512))))
		}
	case toolwire.TypeArtifact:
		var a toolwire.Artifact
		if toolwire.Decode(line, &a) != nil {
			return refuse("unreadable artifact")
		}
		art, err := readArtifact(s.p.workdir, a)
		if err != nil {
			return refuse("artifact: " + err.Error())
		}
		s.out.Artifacts = append(s.out.Artifacts, art)
	case toolwire.TypeVerdict:
		var v toolwire.VerdictMsg
		if toolwire.Decode(line, &v) != nil {
			return refuse("unreadable verdict")
		}
		if err := asm.Verdict(v.Item, v.Verdict, s.p.redact(toolrt.CleanString(v.Detail))); err != nil {
			return refuse(s.p.redact(err.Error()))
		}
	case toolwire.TypeHeartbeat:
	case toolwire.TypeResult:
		var r toolwire.Result
		if toolwire.Decode(line, &r) != nil {
			return refuse("unreadable result")
		}
		return &r, false, "", ""
	default:
		// Unknown types are ignored (a newer adapter).
	}
	return nil, false, "", ""
}

func (s *session) log(level, msg string, fields map[string]any) {
	msg = s.p.redact(toolrt.CleanString(truncate(msg, 8<<10)))
	clean := map[string]any{}
	for k, v := range fields {
		if len(clean) >= 32 {
			break
		}
		if str, ok := v.(string); ok {
			v = s.p.redact(toolrt.CleanString(truncate(str, 8<<10)))
		} else if b, err := json.Marshal(v); err == nil {
			v = s.p.redact(toolrt.CleanString(truncate(string(b), 8<<10)))
		}
		clean[toolrt.CleanString(truncate(k, 128))] = v
	}
	switch level {
	case "debug", "info", "warn", "error":
	default:
		level = "info"
	}
	line := LogLine{Level: level, Msg: msg, Fields: clean}
	s.logMu.Lock()
	if len(s.out.Logs) < MaxLogLines {
		s.out.Logs = append(s.out.Logs, line)
	}
	s.logMu.Unlock()
	if sink := s.h.LogSink; sink != nil && s.ctx != nil {
		sink(s.ctx, s.p.m.Name, line)
	}
	if l := s.h.Logger; l != nil {
		lv := map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}[level]
		args := []any{"tool", s.p.m.Name, "task", s.p.task.ID}
		for k, v := range clean {
			args = append(args, k, v)
		}
		l.Log(context.Background(), lv, msg, args...)
	}
}

// finish computes the outcome.
func (s *session) finish(res *executor.Result, stopReason string, stopClass tool.ErrorClass, stderr *cappedBuffer, start time.Time, execution string) {
	out, p := s.out, s.p
	out.Duration = time.Since(start)
	out.ExitCode = -1
	if res != nil {
		out.ExitCode = res.ExitCode
		out.Sandbox = res.Sandbox
	}
	out.Stderr = p.redact(toolrt.CleanString(stderr.String()))
	var runErr *tool.Error
	switch {
	case stopReason != "":
		runErr = &tool.Error{Class: stopClass, Retryable: stopClass.Retryable(), Detail: stopReason}
	case s.result != nil && (s.result.Status == tool.StatusFailed || s.result.Status == tool.StatusCanceled):
		runErr = s.result.Error.ToError()
		if runErr == nil {
			runErr = &tool.Error{Class: tool.ToolError, Detail: "the tool reported a failure"}
		}
		if s.result.Status == tool.StatusCanceled {
			runErr = &tool.Error{Class: tool.Canceled, Detail: "canceled"}
		}
		runErr.Detail = p.redact(toolrt.CleanString(runErr.Detail))
	}
	switch {
	case runErr != nil && runErr.Class == tool.ResourceExhausted:
		// Stopped at the output limit: what was accepted is delivered.
		out.Status = tool.StatusPartial
	default:
		out.Status = p.asm.Status(runErr)
		if runErr == nil && s.result != nil && s.result.Status == tool.StatusPartial {
			out.Status = tool.StatusPartial
		}
	}
	out.Err = runErr
	out.Report = p.asm.Report(time.Now().UTC())
	st := p.asm.Checker().Stats()
	out.Stats = Stats{Records: st.Records, Bytes: st.Bytes, Capped: st.Capped, Quarantined: st.Quarantined, Invalid: st.Invalid + s.invalidMessages()}
	for _, r := range p.asm.Results() {
		to := TargetOutcome{Ref: r.Target.Ref, Value: r.Target.Value, State: r.State}
		if r.Error != nil {
			to.Class, to.Detail = r.Error.Class, r.Error.Detail
		}
		out.Targets = append(out.Targets, to)
	}
	p.checkContract(out)
	p.addRefused(out)
	out.Verdicts = p.verdicts(runErr)
	if p.rateLine != nil {
		out.Logs = append(out.Logs, *p.rateLine)
	}
	s.h.stamp(out, p.m, p.task, execution)
}

// verdicts are the final verdicts in the order of the task as it was asked
// (before admission removed items on refused targets).
func (p *prepared) verdicts(runErr *tool.Error) []tool.RetestVerdict {
	asked := p.asked
	if len(asked) == 0 {
		return nil
	}
	got := map[string]tool.RetestVerdict{}
	for _, v := range p.asm.Verdicts(runErr) {
		got[v.Ref] = v
	}
	out := make([]tool.RetestVerdict, 0, len(asked))
	for _, it := range asked {
		if p.refusedItems[it.Ref] {
			out = append(out, tool.RetestVerdict{Ref: it.Ref, Verdict: tool.Unverifiable, Detail: "the local policy refused the target"})
			continue
		}
		out = append(out, got[it.Ref])
	}
	return out
}

// addRefused reports the targets the policy refused; a task that ran on
// the rest is at best partial.
func (p *prepared) addRefused(out *Outcome) {
	if len(p.refused) == 0 {
		return
	}
	out.Targets = append(out.Targets, p.refused...)
	if out.Status == tool.StatusOK {
		out.Status = tool.StatusPartial
	}
}

func (s *session) invalidMessages() int { return max(s.invalid, 0) }

// readArtifact opens an artifact beneath the task directory (no symlink
// escape), checks its size and digest and reads it.
func readArtifact(workdir string, a toolwire.Artifact) (Artifact, error) {
	if a.Name == "" || len(a.Name) > 128 || strings.ContainsAny(a.Name, "/\\\x00") {
		return Artifact{}, errors.New("invalid name")
	}
	if a.Size < 0 || a.Size > MaxArtifactBytes {
		return Artifact{}, fmt.Errorf("larger than %d bytes", MaxArtifactBytes)
	}
	rel := filepath.Clean(filepath.FromSlash(a.Path))
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Artifact{}, errors.New("path outside the task directory")
	}
	full := filepath.Join(workdir, rel)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return Artifact{}, errors.New("not found")
	}
	if resolved != full || !strings.HasPrefix(resolved, workdir+string(filepath.Separator)) {
		return Artifact{}, errors.New("path escapes the task directory (symlink)")
	}
	data, digest, err := readRegular(resolved, a.Size)
	if err != nil {
		return Artifact{}, err
	}
	if !strings.EqualFold(digest, a.SHA256) {
		return Artifact{}, errors.New("digest mismatch")
	}
	return Artifact{Name: toolrt.CleanString(a.Name), MediaType: toolrt.CleanString(truncate(a.MediaType, 128)), SHA256: digest, Data: data}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
	cut bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.cut = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.cut = true
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.buf.String()
	if c.cut {
		s += "\n[output cut]"
	}
	return s
}

func (c *cappedBuffer) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Len()
}

func (c *cappedBuffer) Overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cut
}

func (c *cappedBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.buf.Bytes())
}
