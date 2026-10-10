package toolcompat

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ScannerConfig configures AsScanner.
type ScannerConfig struct {
	// Host runs the tasks (required): its Policy admits each one.
	Host *toolhost.Host
	// Credentials returns the credentials the operator stored for the
	// tool (nil: none). Only those the manifest declares are delivered.
	Credentials func() map[string]string
	// Mode is the sensor mode the tasks run in (checked against the
	// manifest's modes; "": not checked).
	Mode tool.Mode
	// Dir is the manifest's directory, for a tool that is its own program
	// (run.argv relative to it).
	Dir string
}

// AsScanner returns t as a core.Scanner, so the command executor, the
// scheduler, the outbox and the heartbeat serve it like any scanner, while
// every task runs out of process through the host: a tool compiled into
// the sensor is re-executed (toolhost RunBuiltin), a tool with a run
// section (an adapter or exec-profile CLI the operator installed) runs as
// its own program (RunManifest). Its raw output is the checked CTIS report.
//
// The scanner reports the tool's contract (core.ToolContractProvider) and
// its configuration schema (core.SettingsSchemaProvider), so the platform
// validates scan settings against the manifest; those settings become the
// task's configuration. A bridged legacy scanner (FromScanner) keeps its
// name, version, capabilities and installation check, and its scan options
// travel in Task.Local.
func AsScanner(t tool.Tool, cfg ScannerConfig) core.Scanner {
	if cfg.Host == nil {
		panic("toolcompat: AsScanner without a host")
	}
	m := t.Manifest().Normalized()
	if err := m.Validate(); err != nil {
		panic(fmt.Sprintf("toolcompat: tool %s: %v", m.Name, err))
	}
	return &toolScanner{t: t, m: m, cfg: cfg}
}

type toolScanner struct {
	t   tool.Tool
	m   tool.Manifest
	cfg ScannerConfig
}

// Retester is a scanner that also runs retest tasks of its tool (the
// sensor's retest command): Retests reports whether the manifest declares
// retest, RunRetest runs one retest task through the same host, admission
// and options as a scan.
type Retester interface {
	core.Scanner
	Retests() bool
	RunRetest(ctx context.Context, task tool.Task) (*toolhost.Outcome, error)
}

// RetestCapability is the capability a sensor reports for a tool that can
// retest: "retest:<tool>". The platform routes retest commands by it.
func RetestCapability(name string) string { return "retest:" + strings.ToLower(name) }

var (
	_ Retester                    = (*toolScanner)(nil)
	_ core.MultiTargetScanner     = (*toolScanner)(nil)
	_ core.ToolContractProvider   = (*toolScanner)(nil)
	_ core.SettingsSchemaProvider = (*toolScanner)(nil)
	_ core.CapabilityScanner      = (*toolScanner)(nil)
)

// TakesCapabilityJobs: a tool that implements capabilities runs
// capability jobs (the runtime maps their params, tool.Manifest.ApplyParams).
func (s *toolScanner) TakesCapabilityJobs() bool { return len(s.m.Implements) > 0 }

// EnforcesScopeLimits: the tool host enforces a task's scope limits (it
// refuses the task on a sandbox that cannot).
func (s *toolScanner) EnforcesScopeLimits() bool { return true }

func (s *toolScanner) legacy() core.Scanner {
	if b, ok := s.t.(ScannerBridge); ok {
		return b.Scanner()
	}
	return nil
}

func (s *toolScanner) Name() string { return s.m.Name }

func (s *toolScanner) Version() string {
	if l := s.legacy(); l != nil {
		return l.Version()
	}
	return s.m.Version
}

func (s *toolScanner) Capabilities() []string {
	if l := s.legacy(); l != nil {
		return l.Capabilities()
	}
	return append([]string(nil), s.m.Capabilities...)
}

// Retests reports whether the tool can retest (its manifest declares it).
func (s *toolScanner) Retests() bool { return s.m.RetestFeature() }

// RunRetest runs one retest task (tool.Task.Retest set) out of process.
func (s *toolScanner) RunRetest(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
	if !s.m.RetestFeature() || !task.IsRetest() {
		return nil, fmt.Errorf("%s: not a retest", s.m.Name)
	}
	return s.run(ctx, task)
}

// run runs one task through the host: a tool with a run section as its own
// program (installed by the operator), else re-executed as a compiled-in
// tool.
func (s *toolScanner) run(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
	o := toolhost.RunOptions{Mode: s.cfg.Mode, Dir: s.cfg.Dir}
	if s.cfg.Credentials != nil {
		o.Credentials = s.cfg.Credentials()
	}
	if s.m.Run != nil {
		o.Trusted = true // installed by the operator in an adapter directory
		return s.cfg.Host.RunManifest(ctx, s.m, task, o)
	}
	return s.cfg.Host.RunBuiltin(ctx, s.t, task, o)
}

// IsInstalled: a bridged scanner answers for its engine; a tool with its
// own program needs that program; a compiled-in tool is always here.
func (s *toolScanner) IsInstalled(ctx context.Context) (bool, string, error) {
	if l := s.legacy(); l != nil {
		return l.IsInstalled(ctx)
	}
	if s.m.Run != nil {
		prog := s.program()
		if _, err := exec.LookPath(prog); err != nil {
			return false, "", fmt.Errorf("%s: program %s: %w", s.m.Name, prog, err)
		}
	}
	return true, s.m.Version, nil
}

func (s *toolScanner) program() string {
	prog := s.m.Run.Argv[0]
	if s.cfg.Dir != "" && !filepath.IsAbs(prog) && strings.ContainsRune(prog, filepath.Separator) {
		prog = filepath.Join(s.cfg.Dir, prog)
	}
	return prog
}

// ToolContract is the tool's contract with its origin: an adapter the
// operator installed (a run section) or a tool compiled into the sensor.
func (s *toolScanner) ToolContract() *core.ToolContract {
	c := s.m.Contract()
	c.Origin = core.ToolOriginBuiltin
	if s.m.Run != nil {
		c.Origin = core.ToolOriginAdapter
	}
	return c
}

func (s *toolScanner) SettingsSchema() *core.SettingsSchema {
	if schema, err := s.m.ConfigSchema(); err == nil && schema != nil {
		return schema
	}
	if p, ok := s.legacy().(core.SettingsSchemaProvider); ok {
		return p.SettingsSchema()
	}
	return nil
}

func (s *toolScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	var targets []string
	if strings.TrimSpace(target) != "" {
		targets = []string{target}
	}
	return s.ScanTargets(ctx, targets, opts)
}

func (s *toolScanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	task := tool.Task{Targets: make([]tool.Target, len(targets))}
	for i, v := range targets {
		task.Targets[i] = tool.Target{Ref: fmt.Sprintf("t%d", i), Value: v}
	}
	if opts != nil {
		task.Capability, task.Params, task.MaxTier = opts.Capability, opts.Params, tool.Tier(opts.MaxTier)
		task.WebScope = opts.WebScope
		task.Limits = opts.Limits
		task.OrgHTTP = opts.OrgHTTP
	}
	if opts != nil && opts.Settings != nil && len(s.m.Config) > 0 {
		raw, err := json.Marshal(opts.Settings.Values())
		if err != nil {
			return nil, fmt.Errorf("%s: encode the settings: %w", s.m.Name, err)
		}
		task.Config = raw
	}
	if b, ok := s.t.(ScannerBridge); ok {
		local, err := b.Local(opts)
		if err != nil {
			return nil, err
		}
		task.Local = local
	}
	out, err := s.run(ctx, task)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.m.Name, err)
	}
	if out.Err != nil && out.Status != tool.StatusPartial {
		return nil, fmt.Errorf("%s: %w", s.m.Name, out.Err)
	}
	if err := allTargetsFailed(out); err != nil {
		// Not a scan with nothing to report: the command fails, as the
		// scanner's own error made it fail before.
		return nil, fmt.Errorf("%s: %w", s.m.Name, err)
	}
	raw, err := out.ReportJSON()
	if err != nil {
		return nil, err
	}
	version := s.Version()
	if out.Report != nil && out.Report.Tool != nil && out.Report.Tool.Version != "" {
		version = out.Report.Tool.Version
	}
	return &core.ScanResult{ScannerName: s.m.Name, ScannerVersion: version, DurationMs: out.Duration.Milliseconds(),
		ExitCode: out.ExitCode, RawOutput: raw, Stderr: out.Stderr}, nil
}

// allTargetsFailed is the error of a task none of whose targets was done
// (nil when one was, or the task had none).
func allTargetsFailed(out *toolhost.Outcome) error {
	if len(out.Targets) == 0 {
		return nil
	}
	var first *toolhost.TargetOutcome
	for i := range out.Targets {
		to := &out.Targets[i]
		if to.State == tool.StateDone {
			return nil
		}
		if first == nil && to.State == tool.StateFailed {
			first = to
		}
	}
	if first == nil {
		first = &out.Targets[0]
	}
	return &tool.Error{Class: firstClass(first.Class), Detail: fmt.Sprintf("no target was scanned (%s: %s)", first.Value, first.Detail)}
}

func firstClass(c tool.ErrorClass) tool.ErrorClass {
	if c == "" {
		return tool.ToolError
	}
	return c
}
