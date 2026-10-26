package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func requireSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
}

// runFailing runs a real process and returns its start or exit error, as the
// executors see it.
func runFailing(t *testing.T, script string) error {
	t.Helper()
	requireSh(t)
	err := exec.Command("sh", "-c", script).Run()
	if err == nil {
		t.Fatalf("%q did not fail", script)
	}
	return err
}

func TestClassifyFailure_RealProcesses(t *testing.T) {
	missing := exec.Command("openctem-no-such-tool-xyz").Run()
	dir := t.TempDir()
	plain := filepath.Join(dir, "not-exec")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	notExec := exec.Command(plain).Run()
	gone := exec.Command(filepath.Join(dir, "absent")).Run()

	tests := []struct {
		name       string
		err        error
		class      core.FailureClass
		reason     string
		signal     string
		exit       int // -1: none
		strongCode string
	}{
		{"binary not on PATH", missing, core.FailureToolUnavailable, core.ReasonToolMissing, "", -1, ""},
		{"binary path absent", gone, core.FailureToolUnavailable, core.ReasonToolMissing, "", -1, ""},
		{"binary not executable", notExec, core.FailureToolUnavailable, core.ReasonToolNotExecutable, "", -1, ""},
		{"shell: command not found (127)", runFailing(t, "exit 127"), core.FailureToolUnavailable, core.ReasonToolMissing, "", 127, ""},
		{"shell: not executable (126)", runFailing(t, "exit 126"), core.FailureToolUnavailable, core.ReasonToolNotExecutable, "", 126, ""},
		{"segfault", runFailing(t, "kill -SEGV $$"), core.FailureToolCrashed, "", "SIGSEGV", -1, "TOOL_EXIT"},
		{"abort", runFailing(t, "kill -ABRT $$"), core.FailureToolCrashed, "", "SIGABRT", -1, "TOOL_EXIT"},
		{"killed", runFailing(t, "kill -KILL $$"), core.FailureToolCrashed, "", "SIGKILL", -1, "TOOL_EXIT"},
		{"wrapper reports 139", runFailing(t, "exit 139"), core.FailureToolCrashed, "", "SIGSEGV", 139, "TOOL_EXIT"},
		{"wrapper reports 137", runFailing(t, "exit 137"), core.FailureToolCrashed, "", "SIGKILL", 137, "TOOL_EXIT"},
		{"plain exit 2 says nothing", runFailing(t, "exit 2"), core.FailureUnknown, "", "", 2, ""},
		{"plain exit 1 says nothing", runFailing(t, "exit 1"), core.FailureUnknown, "", "", 1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := fmt.Errorf("scan failed: %w", tt.err)
			f := core.ClassifyFailure(core.FailureInput{Err: wrapped, Tool: "nuclei"})
			if f == nil {
				t.Fatal("no failure")
			}
			if f.Class != tt.class || f.Evidence.Reason != tt.reason || f.Evidence.Signal != tt.signal {
				t.Fatalf("got class %s reason %q signal %q; want %s %q %q", f.Class, f.Evidence.Reason, f.Evidence.Signal, tt.class, tt.reason, tt.signal)
			}
			switch {
			case tt.exit < 0 && f.Evidence.ExitCode != nil && tt.signal != "":
				t.Fatalf("exit code %d with a signal", *f.Evidence.ExitCode)
			case tt.exit >= 0 && (f.Evidence.ExitCode == nil || *f.Evidence.ExitCode != tt.exit):
				t.Fatalf("exit code = %v, want %d", f.Evidence.ExitCode, tt.exit)
			}
			if f.ErrorCode() != tt.strongCode {
				t.Fatalf("error code %q, want %q", f.ErrorCode(), tt.strongCode)
			}
			if f.Evidence.Tool != "nuclei" {
				t.Fatalf("tool %q", f.Evidence.Tool)
			}
		})
	}
}

func TestClassifyFailure_Errors(t *testing.T) {
	enospc := &os.PathError{Op: "write", Path: "/var/lib/sensor/ws/out.json", Err: syscall.ENOSPC}
	tests := []struct {
		name   string
		err    error
		class  core.FailureClass
		reason string
		errno  string
	}{
		{"disk full", fmt.Errorf("scan failed: %w", enospc), core.FailureDisk, "", "ENOSPC"},
		{"quota", fmt.Errorf("x: %w", &os.PathError{Op: "write", Err: syscall.EDQUOT}), core.FailureDisk, "", "EDQUOT"},
		{"enomem", fmt.Errorf("x: %w", syscall.ENOMEM), core.FailureMemory, "", "ENOMEM"},
		{"output too large", fmt.Errorf("x: %w", core.ErrScannerOutputTooLarge), core.FailureOutputLimit, core.ReasonOutputLimit, ""},
		{"tool crashed", &tool.Error{Class: tool.ToolCrashed, Detail: "exited without a result"}, core.FailureToolCrashed, core.ReasonExitedWithoutResult, ""},
		{"no handshake", &tool.Error{Class: tool.ToolCrashed, Detail: "no handshake within 10s"}, core.FailureToolCrashed, core.ReasonNoHandshake, ""},
		{"protocol", &tool.Error{Class: tool.ToolCrashed, Detail: "protocol 9 is not supported"}, core.FailureToolUnavailable, core.ReasonToolVersion, ""},
		{"output limit", &tool.Error{Class: tool.ResourceExhausted, Detail: "output larger than the limit"}, core.FailureOutputLimit, core.ReasonOutputLimit, ""},
		{"memory", &tool.Error{Class: tool.ResourceExhausted, Detail: "memory limit"}, core.FailureMemory, "", ""},
		{"budget", &tool.Error{Class: tool.Timeout, Detail: "time budget"}, core.FailureBudgetExceeded, "", ""},
		{"target unreachable", tool.Unreachable(errors.New("no route")), core.FailureTargetUnreachable, "", ""},
		{"rate limited", tool.RateLimit(time.Minute, errors.New("429")), core.FailureTargetRateLimited, "", ""},
		{"transient", tool.Retry(errors.New("blip")), core.FailureTransient, "", ""},
		{"invalid input", tool.Invalid("bad %s", "x"), core.FailureConfigInvalid, "", ""},
		{"auth", tool.AuthFailure(errors.New("401")), core.FailureConfigAuth, "", ""},
		{"plain tool error", tool.Failed(errors.New("x")), core.FailureUnknown, "", ""},
		{"plain error", errors.New("something odd"), core.FailureUnknown, "", ""},
		{"pool: no endpoint", fmt.Errorf("dial: %w", upstream.ErrNoEndpoint), core.FailurePoolExhausted, "pool_all_down", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := core.ClassifyFailure(core.FailureInput{Err: tt.err})
			if f.Class != tt.class || f.Evidence.Reason != tt.reason || f.Evidence.Errno != tt.errno {
				t.Fatalf("got %s %q %q, want %s %q %q", f.Class, f.Evidence.Reason, f.Evidence.Errno, tt.class, tt.reason, tt.errno)
			}
		})
	}
}

func TestClassifyFailure_NilAndRefusal(t *testing.T) {
	if core.ClassifyFailure(core.FailureInput{}) != nil {
		t.Fatal("no error classified")
	}
	if f := core.ClassifyFailure(core.FailureInput{Err: &core.LocalPolicyError{Rule: "tools.allow", Detail: "x"}}); f != nil {
		t.Fatalf("a refusal got a failure class: %+v", f)
	}
}

func TestClassifyFailure_RetryAfterHintIsBounded(t *testing.T) {
	f := core.ClassifyFailure(core.FailureInput{Err: tool.RateLimit(1000*time.Hour, errors.New("429"))})
	if f.RetryAfterSeconds != 3600 {
		t.Fatalf("retry_after_seconds = %d", f.RetryAfterSeconds)
	}
}

func rep(endpoints ...upstream.EndpointReport) *upstream.Report {
	return &upstream.Report{PoolID: "p", Endpoints: endpoints}
}

func TestClassifyFailure_ProxyPoolEvidence(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		rep   *upstream.Report
		class core.FailureClass
		pool  bool
	}{
		{"every endpoint down", tool.Unreachable(errors.New("dial")), rep(upstream.EndpointReport{EndpointID: "a", ProxyDown: 5}, upstream.EndpointReport{EndpointID: "b", ProxyDown: 4}), core.FailurePoolExhausted, true},
		{"every endpoint refused credentials", errors.New("scan failed"), rep(upstream.EndpointReport{EndpointID: "a", ProxyAuth: 2}), core.FailureProxyAuth, true},
		{"mixed down and auth", errors.New("scan failed"), rep(upstream.EndpointReport{EndpointID: "a", ProxyAuth: 2}, upstream.EndpointReport{EndpointID: "b", ProxyDown: 1}), core.FailurePoolExhausted, true},
		{"pool carried connections: not the pool's fault", tool.Unreachable(errors.New("dial")), rep(upstream.EndpointReport{EndpointID: "a", OK: 40, ProxyDown: 2}), core.FailureTargetUnreachable, false},
		{"a crash stays a crash", &tool.Error{Class: tool.ToolCrashed}, rep(upstream.EndpointReport{EndpointID: "a", ProxyDown: 5}), core.FailureToolCrashed, true},
		{"target answers only", tool.Unreachable(errors.New("dial")), rep(upstream.EndpointReport{EndpointID: "a", TargetUnreachable: 9}), core.FailureTargetUnreachable, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := core.ClassifyFailure(core.FailureInput{Err: tt.err, Egress: tt.rep})
			if f.Class != tt.class {
				t.Fatalf("class %s, want %s", f.Class, tt.class)
			}
			got := f.Evidence.Egress != nil && f.Evidence.Egress.PoolExhausted
			if got != tt.pool {
				t.Fatalf("pool_exhausted = %v, want %v (%+v)", got, tt.pool, f.Evidence.Egress)
			}
		})
	}
}

func TestClassifyFailure_ControlProbe(t *testing.T) {
	ctl := func(path, dns reach.ProbeState) *reach.ControlResult {
		return &reach.ControlResult{Path: path, DNS: dns}
	}
	unreachable := tool.Unreachable(errors.New("no route"))
	tests := []struct {
		name  string
		err   error
		ctl   *reach.ControlResult
		class core.FailureClass
		probe bool
	}{
		{"path failed: the sensor's network", unreachable, ctl(reach.ProbeFailed, reach.ProbeOK), core.FailureSensorNetwork, true},
		{"dns failed on a target error", unreachable, ctl(reach.ProbeOK, reach.ProbeFailed), core.FailureDNSResolver, true},
		{"control passed: a fact about the target", unreachable, ctl(reach.ProbeOK, reach.ProbeOK), core.FailureTargetUnreachable, true},
		{"control did not run", unreachable, ctl(reach.ProbeSkipped, reach.ProbeSkipped), core.FailureTargetUnreachable, false},
		{"no control", unreachable, nil, core.FailureTargetUnreachable, false},
		{"a rate limit is the target's even if the path failed", tool.RateLimit(0, errors.New("429")), ctl(reach.ProbeFailed, reach.ProbeOK), core.FailureTargetRateLimited, true},
		{"unknown error with a failed path", errors.New("scan failed"), ctl(reach.ProbeFailed, reach.ProbeOK), core.FailureSensorNetwork, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := core.ClassifyFailure(core.FailureInput{Err: tt.err, Control: tt.ctl})
			if f.Class != tt.class || (f.Evidence.Probe != nil) != tt.probe {
				t.Fatalf("class %s probe %+v, want %s probe=%v", f.Class, f.Evidence.Probe, tt.class, tt.probe)
			}
		})
	}
}

func TestClassifyFailure_OOMKill(t *testing.T) {
	killed := runFailing(t, "kill -KILL $$")
	f := core.ClassifyFailure(core.FailureInput{Err: killed, OOMKilled: true})
	if f.Class != core.FailureMemory || !f.Evidence.OOMKilled || f.Evidence.Signal != "SIGKILL" {
		t.Fatalf("%+v", f)
	}
	// Without the memory limit's mark a SIGKILL is a crash.
	if g := core.ClassifyFailure(core.FailureInput{Err: killed}); g.Class != core.FailureToolCrashed || g.Evidence.OOMKilled {
		t.Fatalf("%+v", g)
	}
	// An OOM mark on an unknown error still says memory.
	if g := core.ClassifyFailure(core.FailureInput{Err: errors.New("scan failed"), OOMKilled: true}); g.Class != core.FailureMemory {
		t.Fatalf("%+v", g)
	}
}

func TestClassifyFailure_Stage(t *testing.T) {
	f := core.ClassifyFailure(core.FailureInput{Err: errors.New("x"), Stage: core.StageFetchContent})
	if f.Evidence.Stage != core.StageFetchContent {
		t.Fatalf("stage %q", f.Evidence.Stage)
	}
	parse := core.ClassifyFailure(core.FailureInput{Err: errors.New("parse failed: bad json"), Stage: core.StageParse})
	if parse.ErrorCode() != "PARSE_ERROR" {
		t.Fatalf("code %q", parse.ErrorCode())
	}
}

// Evidence holds closed values and bounded numbers only. A tool name, a
// digest, a signal or a reason that is anything else is dropped, and the
// largest evidence stays under the cap.
func TestFailureBounded(t *testing.T) {
	huge := strings.Repeat("A", 100_000)
	exit := 1 << 30
	f := (&core.Failure{Class: "not.a.class", Scope: huge, RetryAfterSeconds: 1 << 30, Evidence: core.FailureEvidence{
		Tool: huge, ToolDigest: huge, ContentDigest: "sha256:zz", Stage: huge, Reason: huge, ExitCode: &exit, Signal: huge,
		Errno: huge, Probe: &core.FailureProbe{Path: huge, DNS: "ok"},
		Egress: &core.FailureEgress{ProxyDown: 1 << 62, ProxyAuth: -5, PoolExhausted: true},
	}}).Bounded()
	if f.Class != core.FailureUnknown || f.Scope != core.FailureScopeCommand || f.RetryAfterSeconds != 3600 {
		t.Fatalf("%+v", f)
	}
	e := f.Evidence
	if e.Tool != "" || e.ToolDigest != "" || e.ContentDigest != "" || e.Stage != "" || e.Reason != "" || e.ExitCode != nil ||
		e.Signal != "" || e.Errno != "" || e.Probe != nil {
		t.Fatalf("unbounded evidence kept: %+v", e)
	}
	if e.Egress == nil || e.Egress.ProxyDown != 1<<30 || e.Egress.ProxyAuth != 0 || !e.Egress.PoolExhausted {
		t.Fatalf("egress %+v", e.Egress)
	}
	if (*core.Failure)(nil).Bounded() != nil {
		t.Fatal("nil")
	}

	// The largest valid evidence fits the cap.
	code := 65535
	max := (&core.Failure{Class: core.FailurePoolExhausted, Scope: core.FailureScopeTargets, RetryAfterSeconds: 3600, Evidence: core.FailureEvidence{
		Tool: strings.Repeat("a", 64), ToolDigest: "sha256:" + strings.Repeat("a", 64), ContentDigest: "sha256:" + strings.Repeat("b", 64),
		Stage: core.StageFetchContent, Reason: strings.Repeat("r", 48), ExitCode: &code, Signal: "SIGSEGV", OOMKilled: true,
		Probe: &core.FailureProbe{Path: "failed", DNS: "skipped"}, Egress: &core.FailureEgress{ProxyDown: 1 << 30, ProxyAuth: 1 << 30, PoolExhausted: true},
		Errno: "ENOSPC",
	}}).Bounded()
	raw, _ := json.Marshal(max.Evidence)
	if len(raw) > core.MaxFailureEvBytes {
		t.Fatalf("evidence is %d bytes, cap %d", len(raw), core.MaxFailureEvBytes)
	}
	if max.Evidence.Tool == "" || max.Evidence.Reason == "" || max.Evidence.Signal == "" {
		t.Fatalf("valid evidence dropped: %+v", max.Evidence)
	}
}

// No evidence member can hold a proxy credential, whatever the error text
// says: the classifier reads types and codes, never the text.
func TestClassifyFailure_NoSecretsInEvidence(t *testing.T) {
	secret := "http://alice:hunter2@10.0.0.9:3128"
	errs := []error{
		fmt.Errorf("dial %s: connection refused", secret),
		&tool.Error{Class: tool.ToolCrashed, Detail: "no handshake from " + secret},
		&tool.Error{Class: tool.ResourceExhausted, Detail: "output " + secret},
		tool.Unreachable(fmt.Errorf("proxy %s: 407 Proxy Authentication Required", secret)),
		&os.PathError{Op: "fork/exec", Path: "/opt/" + secret, Err: syscall.ENOENT},
	}
	for i, err := range errs {
		f := core.ClassifyFailure(core.FailureInput{Err: err, Tool: "nuclei",
			Egress: rep(upstream.EndpointReport{EndpointID: "a", ProxyAuth: 3, LastError: "407 for " + secret})})
		raw, _ := json.Marshal(f)
		for _, bad := range []string{"hunter2", "alice", "10.0.0.9", "3128", "/opt/"} {
			if strings.Contains(string(raw), bad) {
				t.Fatalf("case %d: %q in %s", i, bad, raw)
			}
		}
	}
}

func TestRedactFailureText(t *testing.T) {
	tests := []struct{ name, in, notWant string }{
		{"proxy url userinfo", "dial http://alice:hunter2@10.0.0.1:3128: refused", "hunter2"},
		{"socks url", "socks5://bob:pw-9@proxy.example:1080 failed", "pw-9"},
		{"user only", "https://token123@proxy.example/x", "token123"},
		{"proxy auth header", "got Proxy-Authorization: Basic YWxpY2U6aHVudGVyMg== from client", "YWxpY2U6aHVudGVyMg"},
		{"bearer", "request failed with Bearer abcdefghijklmnop", "abcdefghijklmnop"},
		{"password flag", "run: tool --password=s3cr3t-value --x", "s3cr3t-value"},
		{"api key", "api_key: AKIA1234567890", "AKIA1234567890"},
		{"token json-ish", `token="abc123def456"`, "abc123def456"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := core.RedactFailureText(tt.in)
			if strings.Contains(got, tt.notWant) {
				t.Fatalf("%q still in %q", tt.notWant, got)
			}
			if !strings.Contains(got, "redacted") {
				t.Fatalf("nothing marked redacted: %q", got)
			}
		})
	}
	// Ordinary text, including a refusal's text form, is kept.
	keep := "refused by local policy: tools.allow: nuclei is not in tools.allow"
	if got := core.RedactFailureText(keep); got != keep {
		t.Fatalf("changed %q to %q", keep, got)
	}
	// Control and bidi characters go; the cap holds on a rune boundary.
	if got := core.RedactFailureText("a\x00b\u202ec\x1b[31md"); strings.ContainsAny(got, "\x00\u202e\x1b") {
		t.Fatalf("%q", got)
	}
	long := strings.Repeat("é", 10_000)
	got := core.RedactFailureText(long)
	if len(got) > core.MaxFailureText || strings.ContainsRune(got, '�') {
		t.Fatalf("len %d", len(got))
	}
}

func TestFailureTargetOutcomes(t *testing.T) {
	targets := []string{"done.example", "sensor.example", "target.example", "never.example"}
	settled := []outcome.Target{{Target: "done.example", State: outcome.Done}}
	rec := reach.NewRecorder()
	ctx := context.Background()
	_ = rec
	got := core.FailureTargetOutcomes(ctx, targets, core.OutcomeEvidence{Revision: 2}, settled)
	by := map[string]outcome.Target{}
	for _, o := range got {
		by[o.Target] = o
	}
	if len(got) != 4 {
		t.Fatalf("%d outcomes: %+v", len(got), got)
	}
	if by["done.example"].State != outcome.Done {
		t.Fatalf("finished target: %+v", by["done.example"])
	}
	// A failed command never marks an unmarked target done.
	for _, h := range []string{"sensor.example", "target.example", "never.example"} {
		if by[h].State != outcome.Unfinished {
			t.Fatalf("%s: %+v, want unfinished", h, by[h])
		}
	}
	// A target the payload does not carry is dropped.
	extra := core.FailureTargetOutcomes(ctx, targets[:1], core.OutcomeEvidence{Revision: 2}, []outcome.Target{{Target: "other.example", State: outcome.Done}})
	if len(extra) != 1 || extra[0].Target != "done.example" || extra[0].State != outcome.Unfinished {
		t.Fatalf("%+v", extra)
	}
	if core.FailureTargetOutcomes(ctx, nil, core.OutcomeEvidence{}, nil) != nil {
		t.Fatal("no targets")
	}
}
