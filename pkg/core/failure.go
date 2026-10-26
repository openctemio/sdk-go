package core

// Structured failure of a command (api research/302 §6): when a job fails,
// the sensor says what kind of failure it was and shows bounded evidence.
// The sensor observes and classifies; the platform decides whether the job
// goes to another sensor, waits or ends. Nothing here chooses a destination.
//
// The class is one of a closed set. Evidence holds closed values and numbers
// only (a tool name, a digest, an exit code, a signal, a stage, counts): never
// a path, a host name, a proxy address or any text a tool or a proxy wrote,
// so a credential cannot travel in it. The failure message that older
// platforms read is redacted and cut by RedactFailureText.

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

// FailureClass is the closed set of failure classes (research/302 §2). Their
// wire values are the platform's.
type FailureClass string

// Failure classes. The target.* classes are facts about the target; the
// infra.* classes are faults of the sensor, its tool or its path; config.*
// are faults of the job's configuration.
const (
	// FailureToolCrashed: the tool ended without a result (a signal, an exit
	// code, no handshake).
	FailureToolCrashed FailureClass = "infra.tool_crashed"
	// FailureToolUnavailable: the tool is missing, not executable, of a
	// version the sensor cannot run, or its digest does not match
	// (Evidence.Reason says which).
	FailureToolUnavailable FailureClass = "infra.tool_unavailable"
	// FailureMemory: the tool or the sensor ran out of memory (OOM kill).
	FailureMemory FailureClass = "infra.resource.memory"
	// FailureDisk: the workspace, outbox or content cache is out of space.
	FailureDisk FailureClass = "infra.resource.disk"
	// FailureOutputLimit: the tool wrote more than the host allows.
	FailureOutputLimit FailureClass = "infra.resource.output_limit"
	// FailureBudgetExceeded: the whole job ran past its time budget.
	FailureBudgetExceeded FailureClass = "infra.budget_exceeded"
	// FailureSensorNetwork: the sensor's own path failed its control probe.
	FailureSensorNetwork FailureClass = "infra.sensor_network"
	// FailureDNSResolver: the sensor's resolver failed its control probe.
	FailureDNSResolver FailureClass = "infra.dns_resolver"
	// FailureProxyAuth: the proxy pool refused our credentials.
	FailureProxyAuth FailureClass = "infra.egress.proxy_auth"
	// FailureProxyDown: the proxy refused connections or hung.
	FailureProxyDown FailureClass = "infra.egress.proxy_down"
	// FailurePoolExhausted: no endpoint of the job's proxy pool carried a
	// connection.
	FailurePoolExhausted FailureClass = "infra.egress.pool_exhausted"
	// FailureContentUnavailable: the content pack (templates, rules, a
	// database) cannot be fetched, does not verify or is revoked.
	FailureContentUnavailable FailureClass = "infra.content_unavailable"
	// FailureJobSignature: the job's signature does not verify.
	FailureJobSignature FailureClass = "infra.job_signature"
	// FailureTransient: the tool reported a temporary error.
	FailureTransient FailureClass = "infra.transient"

	// FailureTargetUnreachable and the classes after it are about the
	// target and are never retried elsewhere in the run.
	FailureTargetUnreachable   FailureClass = "target.unreachable"
	FailureTargetRefused       FailureClass = "target.refused"
	FailureTargetTimeout       FailureClass = "target.timeout"
	FailureTargetEdgeBlocked   FailureClass = "target.edge_blocked"
	FailureTargetEdgeChallenge FailureClass = "target.edge_challenged"
	FailureTargetRateLimited   FailureClass = "target.rate_limited"
	FailureTargetNameGone      FailureClass = "target.name_gone"

	// FailureConfigInvalid, FailureConfigAuth and FailureConfigPermission:
	// the job's configuration or credentials are wrong; not retried.
	FailureConfigInvalid    FailureClass = "config.invalid_input"
	FailureConfigAuth       FailureClass = "config.auth_failed"
	FailureConfigPermission FailureClass = "config.permission_denied"

	// FailureUnknown: nothing above fits; the platform treats it as
	// ambiguous.
	FailureUnknown FailureClass = "unknown"
)

// Failure scopes.
const (
	FailureScopeCommand = "command"
	FailureScopeTargets = "targets"
)

// Stages of a job a failure happened in.
const (
	StagePrepare      = "prepare"
	StageFetchContent = "fetch_content"
	StageStart        = "start"
	StageHandshake    = "handshake"
	StageRun          = "run"
	StageParse        = "parse"
	StageUpload       = "upload"
)

// Reasons that refine a class (Evidence.Reason).
const (
	ReasonToolMissing            = "tool_missing"
	ReasonToolNotExecutable      = "not_executable"
	ReasonToolVersion            = "tool_version"
	ReasonDigestMismatch         = "digest_mismatch"
	ReasonVerificationRefused    = "verification_refused"
	ReasonContentUnsupported     = "content_unsupported"
	ReasonContentRevoked         = "content_revoked"
	ReasonNoHandshake            = "no_handshake"
	ReasonExitedWithoutResult    = "exited_without_result"
	ReasonJobSignature           = "job_signature"
	ReasonOutputLimit            = "output_limit"
	ReasonPoolAllDown            = "pool_all_down"
	ReasonPoolCredentialsRefused = "pool_credentials_refused"
)

// Bounds of a Failure on the wire.
const (
	MaxFailureTool    = 64
	MaxFailureReason  = 48
	MaxFailureEvBytes = 1024
	// MaxFailureText bounds the failure message (RedactFailureText).
	MaxFailureText = 4096
	maxCount       = 1 << 30
	maxExitCode    = 65535
	maxRetryAfter  = 3600
)

// Failure is the structured failure of a command.
type Failure struct {
	Class FailureClass `json:"class"`
	// Scope is FailureScopeCommand, or FailureScopeTargets when only some
	// targets failed.
	Scope             string          `json:"scope,omitempty"`
	RetryAfterSeconds int             `json:"retry_after_seconds,omitempty"`
	Evidence          FailureEvidence `json:"evidence"`
}

// FailureEvidence is the bounded evidence of a failure. Every member is
// optional and closed (see the package comment).
type FailureEvidence struct {
	Tool          string `json:"tool,omitempty"`
	ToolDigest    string `json:"tool_digest,omitempty"`
	ContentDigest string `json:"content_digest,omitempty"`
	Stage         string `json:"stage,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
	Signal        string `json:"signal,omitempty"`
	OOMKilled     bool   `json:"oom_killed,omitempty"`
	// Probe is the sensor's control check (nil: it did not run).
	Probe  *FailureProbe  `json:"probe,omitempty"`
	Egress *FailureEgress `json:"egress,omitempty"`
	Errno  string         `json:"errno,omitempty"`
}

// FailureProbe is the control check of a failed job: "ok", "failed" or
// "skipped" for the path and for DNS.
type FailureProbe struct {
	Path string `json:"path"`
	DNS  string `json:"dns"`
}

// FailureEgress counts the proxy-pool connection failures of the job. Counts
// only: no endpoint address, no credential.
type FailureEgress struct {
	ProxyDown     int64 `json:"proxy_down"`
	ProxyAuth     int64 `json:"proxy_auth"`
	PoolExhausted bool  `json:"pool_exhausted"`
}

// FailureClassifier is implemented by an error that knows its own failure
// class: packages that core cannot import (the content cache, the proxy pool)
// tag their errors with it. Reason is a Reason* value or "".
type FailureClassifier interface {
	FailureClass() (class, reason string)
}

// FailureInput is what ClassifyFailure reads: the error and the facts the
// poller has about the job.
type FailureInput struct {
	Err error
	// Tool is the scanner or collector name.
	Tool                      string
	ToolDigest, ContentDigest string
	// Stage is the stage the error came from when the error carries none
	// (see StageOf).
	Stage string
	// OOMKilled is set when a process of the job was killed with SIGKILL
	// while neither the job's deadline nor a stop was the cause.
	OOMKilled bool
	// Egress is the job's proxy-pool report (nil: no pool).
	Egress *upstream.Report
	// Control is the sensor's control check (nil: it did not run).
	Control *reach.ControlResult
}

// stageError carries the stage a job step failed in. Its text is the wrapped
// error's, so messages do not change.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

// atStage tags err with a stage (nil stays nil).
func atStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stageError{stage: stage, err: err}
}

// StageOf returns the stage err was tagged with, or "".
func StageOf(err error) string {
	var se *stageError
	if errors.As(err, &se) {
		return se.stage
	}
	return ""
}

// ClassifyFailure classifies a failed command. It returns nil for no error
// and for a policy refusal (RefusalOf: reported as a refusal). Order of
// precedence: what the error itself says about the tool, the system or the
// content; then the proxy pool's evidence; then the sensor's control check;
// then the tool's own error class. The evidence only ever holds closed
// values (Failure.Bounded).
func ClassifyFailure(in FailureInput) *Failure {
	if in.Err == nil || RefusalOf(in.Err) != nil {
		return nil
	}
	f := &Failure{Class: FailureUnknown, Scope: FailureScopeCommand}
	ev := &f.Evidence
	ev.Tool, ev.ToolDigest, ev.ContentDigest = in.Tool, in.ToolDigest, in.ContentDigest
	ev.Stage = cmpStage(StageOf(in.Err), in.Stage)

	if in.Control != nil && in.Control.Checked() {
		ev.Probe = &FailureProbe{Path: string(in.Control.Path), DNS: string(in.Control.DNS)}
	}
	pool := poolEvidence(in.Egress)
	ev.Egress = pool

	strong := classifyError(in, f)
	if in.OOMKilled && !strong {
		f.Class, ev.OOMKilled, strong = FailureMemory, true, true
	}
	if in.OOMKilled {
		ev.OOMKilled = true
	}
	if !strong && pool != nil && pool.PoolExhausted {
		switch {
		case pool.ProxyAuth > 0 && pool.ProxyDown == 0:
			f.Class, ev.Reason = FailureProxyAuth, ReasonPoolCredentialsRefused
		default:
			f.Class, ev.Reason = FailurePoolExhausted, ReasonPoolAllDown
		}
		strong = true
	}
	if !strong && in.Control != nil {
		switch {
		case in.Control.Path == reach.ProbeFailed:
			f.Class = FailureSensorNetwork
		case in.Control.DNS == reach.ProbeFailed && f.Class == FailureTargetUnreachable:
			f.Class = FailureDNSResolver
		}
	}
	return f.Bounded()
}

func cmpStage(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// poolEvidence reduces the pool's report to counts. exhausted: the pool
// carried no connection and failed at least one.
func poolEvidence(r *upstream.Report) *FailureEgress {
	if r == nil {
		return nil
	}
	var ok, down, auth int64
	for _, e := range r.Endpoints {
		ok += e.OK
		down += e.ProxyDown
		auth += e.ProxyAuth
	}
	if ok+down+auth == 0 {
		return nil
	}
	return &FailureEgress{ProxyDown: down, ProxyAuth: auth, PoolExhausted: ok == 0 && down+auth > 0}
}

// classifyError sets the class from the error itself. It returns true for a
// class that a pool or a control probe must not override (the error names
// the cause), false for a weak one (an unknown error, a target answer, a
// time-out, a temporary error).
func classifyError(in FailureInput, f *Failure) bool {
	err := in.Err
	ev := &f.Evidence

	var cl FailureClassifier
	if errors.As(err, &cl) {
		class, reason := cl.FailureClass()
		if c := FailureClass(class); knownFailureClass(c) {
			f.Class, ev.Reason = c, reason
			var ra interface{ FailureRetryAfter() time.Duration }
			if errors.As(err, &ra) {
				f.RetryAfterSeconds = int(min(ra.FailureRetryAfter().Seconds(), maxRetryAfter))
			}
			return !weakFailureClass(c)
		}
	}
	switch {
	case errors.Is(err, ErrScannerOutputTooLarge):
		f.Class, ev.Reason = FailureOutputLimit, ReasonOutputLimit
		return true
	case isNoSpace(err):
		f.Class, ev.Errno = FailureDisk, "ENOSPC"
		if errors.Is(err, syscall.EDQUOT) {
			ev.Errno = "EDQUOT"
		}
		return true
	case errors.Is(err, syscall.ENOMEM):
		f.Class, ev.Errno = FailureMemory, "ENOMEM"
		return true
	}
	if reason, ok := execStartFault(err); ok {
		f.Class, ev.Reason = FailureToolUnavailable, reason
		ev.Stage = cmpStage(ev.Stage, StageStart)
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return classifyExit(ee, f, in.OOMKilled)
	}
	return false
}

func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

// execStartFault reports a tool that could not be started: not found, not
// executable. A *exec.Error is a failed lookup; a *fs.PathError of op
// "fork/exec" or "exec" is the start itself.
func execStartFault(err error) (reason string, ok bool) {
	var xe *exec.Error
	if errors.As(err, &xe) {
		if errors.Is(xe.Err, exec.ErrNotFound) || errors.Is(xe.Err, fs.ErrNotExist) {
			return ReasonToolMissing, true
		}
		return ReasonToolNotExecutable, true
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && (pe.Op == "fork/exec" || pe.Op == "exec") {
		switch {
		case errors.Is(pe.Err, syscall.ENOENT):
			return ReasonToolMissing, true
		case errors.Is(pe.Err, syscall.EACCES), errors.Is(pe.Err, syscall.ENOEXEC), errors.Is(pe.Err, syscall.EPERM):
			return ReasonToolNotExecutable, true
		}
	}
	return "", false
}

// signalNames are the signals evidence may name.
var signalNames = map[syscall.Signal]string{
	syscall.SIGSEGV: "SIGSEGV", syscall.SIGABRT: "SIGABRT", syscall.SIGBUS: "SIGBUS",
	syscall.SIGILL: "SIGILL", syscall.SIGFPE: "SIGFPE", syscall.SIGKILL: "SIGKILL",
	syscall.SIGTERM: "SIGTERM", syscall.SIGPIPE: "SIGPIPE", syscall.SIGINT: "SIGINT",
}

// classifyExit classifies a process that ended on its own. The shell's
// conventional codes count (127 not found, 126 not executable, 128+n a
// signal), because tools are often wrappers.
func classifyExit(ee *exec.ExitError, f *Failure, oomKilled bool) bool {
	ev := &f.Evidence
	code := ee.ExitCode()
	var sig syscall.Signal
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		sig = ws.Signal()
		code = -1
	} else if code > 128 && code < 128+65 {
		sig = syscall.Signal(code - 128)
	}
	if code >= 0 {
		c := code
		ev.ExitCode = &c
	}
	if name, ok := signalNames[sig]; ok {
		ev.Signal = name
	}
	switch {
	case code == 127:
		f.Class, ev.Reason = FailureToolUnavailable, ReasonToolMissing
		return true
	case code == 126:
		f.Class, ev.Reason = FailureToolUnavailable, ReasonToolNotExecutable
		return true
	case sig == syscall.SIGKILL && oomKilled:
		// The poller sets OOMKilled when the kill was nobody's request.
		f.Class, ev.OOMKilled = FailureMemory, true
		return true
	case sig == syscall.SIGKILL:
		f.Class = FailureToolCrashed
		return true
	case sig != 0:
		f.Class = FailureToolCrashed
		return true
	}
	// An exit code alone says nothing about the cause (a tool exits 2 for
	// bad arguments and for a bad target): the platform sees it as unknown,
	// with the code as evidence.
	return false
}

// weakFailureClass reports whether a class says little about the cause: a
// target answer, a time-out or a temporary error may be the proxy pool's or
// the sensor's own path, which the job's evidence can then name.
func weakFailureClass(c FailureClass) bool {
	switch c {
	case FailureUnknown, FailureTargetUnreachable, FailureTargetTimeout, FailureBudgetExceeded, FailureTransient:
		return true
	}
	return false
}

func knownFailureClass(c FailureClass) bool {
	switch c {
	case FailureToolCrashed, FailureToolUnavailable, FailureMemory, FailureDisk, FailureOutputLimit,
		FailureBudgetExceeded, FailureSensorNetwork, FailureDNSResolver, FailureProxyAuth, FailureProxyDown,
		FailurePoolExhausted, FailureContentUnavailable, FailureJobSignature, FailureTransient,
		FailureTargetUnreachable, FailureTargetRefused, FailureTargetTimeout, FailureTargetEdgeBlocked,
		FailureTargetEdgeChallenge, FailureTargetRateLimited, FailureTargetNameGone,
		FailureConfigInvalid, FailureConfigAuth, FailureConfigPermission, FailureUnknown:
		return true
	}
	return false
}

// ErrorCode is the platform's failure code for the class, or "" when the
// class has none (the platform then classifies from the message). Codes the
// platform treats as permanent (SCANNER_NOT_FOUND, TARGET_REFUSED) are not
// used: a tool missing on this sensor is not missing everywhere.
func (f *Failure) ErrorCode() string {
	if f == nil {
		return ""
	}
	switch {
	case f.Class == FailureToolCrashed:
		return "TOOL_EXIT"
	case f.Class == FailureBudgetExceeded:
		return "TIMEOUT"
	case f.Class == FailureTargetUnreachable:
		return "TARGET_UNREACHABLE"
	case f.Evidence.Stage == StageParse:
		return "PARSE_ERROR"
	}
	return ""
}

var (
	toolRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	errnoSet = map[string]bool{"ENOSPC": true, "EDQUOT": true, "ENOMEM": true, "EMFILE": true, "ENFILE": true}
	stageSet = map[string]bool{StagePrepare: true, StageFetchContent: true, StageStart: true, StageHandshake: true,
		StageRun: true, StageParse: true, StageUpload: true}
	probeSet = map[string]bool{string(reach.ProbeOK): true, string(reach.ProbeFailed): true, string(reach.ProbeSkipped): true}
)

// Bounded returns the failure with every member checked against its closed
// set or bound: a value outside it is dropped, a class outside the set is
// "unknown", numbers are clamped. Nothing a tool or a proxy wrote survives
// it. Safe on nil.
func (f *Failure) Bounded() *Failure {
	if f == nil {
		return nil
	}
	out := &Failure{Class: f.Class, Scope: f.Scope}
	if !knownFailureClass(out.Class) {
		out.Class = FailureUnknown
	}
	if out.Scope != FailureScopeTargets {
		out.Scope = FailureScopeCommand
	}
	out.RetryAfterSeconds = max(0, min(f.RetryAfterSeconds, maxRetryAfter))
	e, o := f.Evidence, &out.Evidence
	if toolRE.MatchString(strings.ToLower(e.Tool)) {
		o.Tool = strings.ToLower(e.Tool)
	}
	if digestRE.MatchString(e.ToolDigest) {
		o.ToolDigest = e.ToolDigest
	}
	if digestRE.MatchString(e.ContentDigest) {
		o.ContentDigest = e.ContentDigest
	}
	if stageSet[e.Stage] {
		o.Stage = e.Stage
	}
	if len(e.Reason) <= MaxFailureReason && tokenRE.MatchString(e.Reason) {
		o.Reason = e.Reason
	}
	if e.ExitCode != nil && *e.ExitCode >= 0 && *e.ExitCode <= maxExitCode {
		c := *e.ExitCode
		o.ExitCode = &c
	}
	for _, name := range signalNames {
		if e.Signal == name {
			o.Signal = name
		}
	}
	o.OOMKilled = e.OOMKilled
	if e.Probe != nil && probeSet[e.Probe.Path] && probeSet[e.Probe.DNS] {
		p := *e.Probe
		o.Probe = &p
	}
	if e.Egress != nil {
		o.Egress = &FailureEgress{
			ProxyDown:     max(0, min(e.Egress.ProxyDown, maxCount)),
			ProxyAuth:     max(0, min(e.Egress.ProxyAuth, maxCount)),
			PoolExhausted: e.Egress.PoolExhausted,
		}
	}
	if errnoSet[e.Errno] {
		o.Errno = e.Errno
	}
	return out
}

var (
	// failUserinfoRE matches credentials in a URL: scheme://user:pass@host.
	failUserinfoRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]*:?[^\s/@]*@`)
	// failHeaderSecretRE matches an authorization header's value.
	failHeaderSecretRE = regexp.MustCompile(`(?i)\b(proxy-authorization|authorization)\s*[:=]\s*[^\r\n]*`)
	// failBearerRE matches a bearer or basic credential.
	failBearerRE = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`)
	// failKVSecretRE matches key=value pairs and flags that name a secret.
	failKVSecretRE = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credential)[a-z0-9_.-]*)(\s*[=:]\s*|\s+)("[^"]*"|'[^']*'|[^\s,;&]+)`)
)

// RedactFailureText prepares the failure message for the platform: control
// and bidi characters are dropped, credentials are replaced (userinfo of a
// URL such as a proxy address, authorization headers, bearer tokens, values
// of keys that name a secret) and the text is cut at MaxFailureText bytes
// on a rune boundary.
func RedactFailureText(s string) string {
	s = failUserinfoRE.ReplaceAllString(s, "${1}[redacted]@")
	s = failHeaderSecretRE.ReplaceAllString(s, "${1}: [redacted]")
	s = failBearerRE.ReplaceAllString(s, "${1} [redacted]")
	s = failKVSecretRE.ReplaceAllString(s, "${1}${2}[redacted]")
	var b strings.Builder
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar {
			continue
		}
		if b.Len()+len(string(r)) > MaxFailureText {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// FailureTargetOutcomes are the per-target outcomes of a command that
// failed: what ended before the failure, and what did not. A target the
// report (or an earlier partial result) settled keeps that outcome; a target
// the run's own evidence marks (a coverage gap, an unreached target, with
// the control check deciding whose side it is on) gets that outcome; every
// other target is unfinished, never done, because a failed command did not
// cover it. settled are outcomes already known (the executor's partial
// result); they win.
func FailureTargetOutcomes(ctx context.Context, targets []string, ev OutcomeEvidence, settled []outcome.Target) []outcome.Target {
	if len(targets) == 0 {
		return nil
	}
	marked := append([]outcome.Target(nil), settled...)
	if ev.Report != nil {
		marked = append(marked, reportOutcomes(ev.Report)...)
	}
	marked = append(marked, evidenceOutcomes(ctx, targets, ev)...)
	for _, t := range targets {
		marked = append(marked, outcome.Target{Target: t, State: outcome.Unfinished})
	}
	return downgradeOutcomes(outcome.Normalize(marked, targets), ev.Revision)
}

// failureInput gathers what the poller knows about a failed job: the tool,
// whether a process of the job was killed without our asking, the proxy
// pool's report and the sensor's control check (run now, from the sensor's
// side, because a failed job is when it matters).
func (p *CommandPoller) failureInput(ctx context.Context, cmd *Command, err error, usage *usageRecorder, h *egressHolder) FailureInput {
	m := parseCommandMeta(cmd)
	in := FailureInput{Err: err, Tool: cmp.Or(m.Scanner, m.Collector)}
	if usage != nil {
		_, _, killed := usage.sample()
		// A SIGKILL while the job's own deadline and the platform's stop
		// are not the cause is the memory limit's in practice.
		in.OOMKilled = killed && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded)
	}
	if pool := h.get(); pool != nil {
		rep := pool.Report()
		in.Egress = &rep
	}
	if c := reach.ControlFromContext(ctx); c != nil {
		res := c.Check(context.WithoutCancel(ctx))
		in.Control = &res
	}
	return in
}

// classedError is a sentinel error that carries its failure class.
type classedError struct {
	msg, class, reason string
}

func (e *classedError) Error() string                  { return e.msg }
func (e *classedError) FailureClass() (string, string) { return e.class, e.reason }

// NewClassedError returns a sentinel error that tells ClassifyFailure its
// class (a FailureClass value) and reason ("" for none). Wrapping it with %w
// keeps the class, and errors.Is works on the value as on any sentinel.
func NewClassedError(msg string, class FailureClass, reason string) error {
	return &classedError{msg: msg, class: string(class), reason: reason}
}
