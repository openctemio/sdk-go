// Package toolcompat runs code written against the older interfaces
// (core.Scanner, core.Collector) as tools of the tool contract (pkg/tool),
// so it gets the contract's runtime without a rewrite: out-of-process
// execution in the task sandbox, admission against the policy, declared
// credentials only, checked and stamped output.
//
// Stability: Beta (docs/STABILITY.md). The bridges are transitional: new
// code implements tool.Tool directly; the bridges are removed once every
// in-tree scanner is ported (docs/rfcs/sensor-sdk-v2.md D.12).
//
// A bridged tool is compiled into the sensor like any tool: list it in
// adapter.Dispatch in main, so the re-executed child can serve it. In the
// child, Run calls the scanner (or collector), converts its raw output to
// CTIS with a parser, and emits the report through the runtime's emitter,
// which refuses any record type the manifest does not declare.
//
// What crosses from the sensor into the child is Task.Local: the scan
// options a run uses and, with WithState, the scanner's exported fields as
// JSON. Secrets never travel that way: declare them as credentials in the
// manifest and set them in the child with WithPrepare (ctx.Secret); fields
// tagged json:"-" stay behind.
package toolcompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Bridge is a tool built from a scanner or a collector.
type Bridge interface {
	tool.Tool
	// Legacy is the bridged scanner (core.Scanner) or collector
	// (core.Collector), as the sensor configured it.
	Legacy() any
}

// ScannerBridge is a tool built from a core.Scanner.
type ScannerBridge interface {
	Bridge
	// Scanner is the bridged scanner.
	Scanner() core.Scanner
	// Local is the Task.Local of a scan with opts: what the child needs to
	// run the scanner as the sensor configured it. Credentials are never
	// part of it.
	Local(opts *core.ScanOptions) (json.RawMessage, error)
}

// Option configures a bridge.
type Option func(*options)

type options struct {
	parser  core.Parser
	state   bool
	prepare func(ctx tool.Context, legacy any) error
	apiKey  string
}

// WithParser converts the scanner's raw output with p. Without it the
// child picks a parser the way the command executor does: the SDK's SARIF
// and CTIS parsers.
func WithParser(p core.Parser) Option { return func(o *options) { o.parser = p } }

// WithState sends the scanner's exported state (encoding/json of the
// scanner, which must be a pointer to a struct) to the child, which
// decodes it into a fresh value before the scan. Without it the child uses
// the scanner as its own main built it. Fields tagged json:"-" stay in the
// sensor; never put a secret in a field that is sent.
func WithState() Option { return func(o *options) { o.state = true } }

// WithPrepare runs fn in the child before each run, with the scanner or
// collector the run uses: the place to set declared credentials
// (ctx.Secret) on it.
func WithPrepare(fn func(ctx tool.Context, legacy any) error) Option {
	return func(o *options) { o.prepare = fn }
}

// WithAPIKeyCredential sets CollectOptions.APIKey of a bridged collector
// from the declared credential name (ctx.Secret). The sensor's own APIKey
// is never sent to the child.
func WithAPIKeyCredential(name string) Option { return func(o *options) { o.apiKey = name } }

// scanLocal is the part of core.ScanOptions a bridged scan uses.
type scanLocal struct {
	TargetDir         string            `json:"target_dir,omitempty"`
	Include           []string          `json:"include,omitempty"`
	Exclude           []string          `json:"exclude,omitempty"`
	ConfigFile        string            `json:"config_file,omitempty"`
	ExtraArgs         []string          `json:"extra_args,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
	CustomTemplateDir string            `json:"custom_template_dir,omitempty"`
	AllowInteractsh   bool              `json:"allow_interactsh,omitempty"`
	RateLimit         int               `json:"rate_limit,omitempty"`
	BulkSize          int               `json:"bulk_size,omitempty"`
	Concurrency       int               `json:"concurrency,omitempty"`
	RepoURL           string            `json:"repo_url,omitempty"`
	Branch            string            `json:"branch,omitempty"`
	CommitSHA         string            `json:"commit_sha,omitempty"`
	Verbose           bool              `json:"verbose,omitempty"`
}

func scanLocalOf(o *core.ScanOptions) scanLocal {
	if o == nil {
		return scanLocal{}
	}
	return scanLocal{TargetDir: o.TargetDir, Include: o.Include, Exclude: o.Exclude, ConfigFile: o.ConfigFile,
		ExtraArgs: o.ExtraArgs, Env: o.Env, CustomTemplateDir: o.CustomTemplateDir, AllowInteractsh: o.AllowInteractsh,
		RateLimit: o.RateLimit, BulkSize: o.BulkSize, Concurrency: o.Concurrency, RepoURL: o.RepoURL,
		Branch: o.Branch, CommitSHA: o.CommitSHA, Verbose: o.Verbose}
}

func (l scanLocal) options() *core.ScanOptions {
	return &core.ScanOptions{TargetDir: l.TargetDir, Include: l.Include, Exclude: l.Exclude, ConfigFile: l.ConfigFile,
		ExtraArgs: l.ExtraArgs, Env: l.Env, CustomTemplateDir: l.CustomTemplateDir, AllowInteractsh: l.AllowInteractsh,
		RateLimit: l.RateLimit, BulkSize: l.BulkSize, Concurrency: l.Concurrency, RepoURL: l.RepoURL,
		Branch: l.Branch, CommitSHA: l.CommitSHA, Verbose: l.Verbose}
}

// bridgeLocal is a bridged scan's Task.Local.
type bridgeLocal struct {
	State json.RawMessage `json:"state,omitempty"`
	Scan  scanLocal       `json:"scan"`
}

type scannerBridge struct {
	tool.Tool
	s    core.Scanner
	o    options
	m    tool.Manifest
	elem reflect.Type // WithState: the struct type the scanner points to
}

// FromScanner returns s as a tool described by m. Each task scans its
// targets (all at once when s is a core.MultiTargetScanner, else one by
// one), converts the raw output to CTIS and emits it; a target whose scan
// failed is reported failed, the others done.
//
// m.Config, when set, is the schema the task's configuration is validated
// against; the child hands the configuration to the scanner as
// ScanOptions.Settings. FromScanner panics on an invalid manifest, or on
// WithState with a scanner that is not a pointer to a struct (a bridged
// tool with a broken definition must stop the sensor at start).
func FromScanner(m tool.Manifest, s core.Scanner, opts ...Option) ScannerBridge {
	if s == nil {
		panic("toolcompat: FromScanner with a nil scanner")
	}
	b := &scannerBridge{s: s}
	for _, o := range opts {
		o(&b.o)
	}
	if b.o.state {
		t := reflect.TypeOf(s)
		if t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
			panic(fmt.Sprintf("toolcompat: WithState needs a pointer to a struct, %s is %s", m.Name, t))
		}
		b.elem = t.Elem()
	}
	b.Tool = newTool(m, b.run)
	b.m = b.Tool.Manifest()
	return b
}

// newTool builds the tool with a configuration of any shape the schema
// allows (validated by the runtime, defaults filled).
func newTool(m tool.Manifest, run func(ctx tool.Context, task tool.Task, cfg map[string]any) error) tool.Tool {
	if len(m.Config) == 0 {
		return tool.New(m, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error { return run(ctx, task, nil) })
	}
	return tool.New(m, run)
}

func (b *scannerBridge) Legacy() any             { return b.s }
func (b *scannerBridge) Scanner() core.Scanner   { return b.s }
func (b *scannerBridge) Manifest() tool.Manifest { return b.m }

func (b *scannerBridge) Local(opts *core.ScanOptions) (json.RawMessage, error) {
	l := bridgeLocal{Scan: scanLocalOf(opts)}
	if b.o.state {
		st, err := json.Marshal(b.s)
		if err != nil {
			return nil, fmt.Errorf("%s: encode the scanner state: %w", b.m.Name, err)
		}
		l.State = st
	}
	return json.Marshal(l)
}

// scanner is the scanner a child run uses: a fresh value decoded from the
// state the sensor sent (WithState), else the compiled-in one.
func (b *scannerBridge) scanner(l bridgeLocal) (core.Scanner, error) {
	if !b.o.state || len(l.State) == 0 {
		return b.s, nil
	}
	v := reflect.New(b.elem)
	d := json.NewDecoder(bytes.NewReader(l.State))
	if err := d.Decode(v.Interface()); err != nil {
		return nil, tool.Invalid("%s: the sensor's scanner state is unreadable: %v", b.m.Name, err)
	}
	s, ok := v.Interface().(core.Scanner)
	if !ok {
		return nil, tool.Invalid("%s: the decoded state is not a scanner", b.m.Name)
	}
	return s, nil
}

func decodeLocal(raw json.RawMessage, into any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return tool.Invalid("the sensor's task configuration is unreadable: %v", err)
	}
	return nil
}

func (b *scannerBridge) run(ctx tool.Context, task tool.Task, cfg map[string]any) error {
	var l bridgeLocal
	if err := decodeLocal(task.Local, &l); err != nil {
		return err
	}
	s, err := b.scanner(l)
	if err != nil {
		return err
	}
	opts := l.Scan.options()
	if len(cfg) > 0 {
		schema, err := b.m.ConfigSchema()
		if err != nil {
			return tool.Invalid("config schema: %v", err)
		}
		settings, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: cfg})
		if err != nil {
			return tool.Invalid("%v", err)
		}
		opts.Settings = settings
	}
	if b.o.prepare != nil {
		if err := b.o.prepare(ctx, s); err != nil {
			return err
		}
	}
	values := make([]string, len(task.Targets))
	for i, t := range task.Targets {
		values[i] = t.Value
	}
	if ms, ok := s.(core.MultiTargetScanner); ok && len(task.Targets) > 1 {
		res, err := ms.ScanTargets(ctx, values, opts)
		return b.deliver(ctx, s, task.Targets, res, err)
	}
	if len(task.Targets) == 0 {
		// A scanner without targets (a filesystem scan of opts.TargetDir).
		res, err := s.Scan(ctx, opts.TargetDir, opts)
		return b.deliver(ctx, s, nil, res, err)
	}
	for _, t := range task.Targets {
		res, err := s.Scan(ctx, t.Value, opts)
		if derr := b.deliver(ctx, s, []tool.Target{t}, res, err); derr != nil {
			return derr
		}
	}
	return nil
}

// deliver converts one scan's output and emits it; the targets it covered
// are done, or failed with the scan's error. It returns an error only when
// the task must stop.
func (b *scannerBridge) deliver(ctx tool.Context, s core.Scanner, targets []tool.Target, res *core.ScanResult, scanErr error) error {
	fail := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if len(targets) == 0 {
			return tool.Failed(err)
		}
		for _, t := range targets {
			ctx.TargetError(t, tool.Failed(err))
		}
		return nil
	}
	if scanErr != nil {
		return fail(scanErr)
	}
	if res != nil && len(bytes.TrimSpace(res.RawOutput)) > 0 {
		report, err := b.parse(ctx, s, res.RawOutput)
		if err != nil {
			return fail(err)
		}
		if err := ctx.Emit().Report(report); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return nil // the runtime ends the task partial
			}
			ctx.Log().Warn(b.m.Name+": a record was refused", "error", err.Error())
		}
	}
	for _, t := range targets {
		ctx.TargetDone(t)
	}
	return nil
}

func (b *scannerBridge) parse(ctx context.Context, s core.Scanner, raw []byte) (*ctis.Report, error) {
	p := b.o.parser
	if p == nil {
		var err error
		if p, err = core.NewParserRegistry().ForScanner(s.Name(), raw); err != nil {
			return nil, err
		}
	}
	report, err := p.Parse(ctx, raw, &core.ParseOptions{ToolName: s.Name()})
	if err != nil {
		return nil, fmt.Errorf("convert the %s output: %w", s.Name(), err)
	}
	if report == nil {
		return nil, fmt.Errorf("the %s parser returned no report", s.Name())
	}
	return report, nil
}

// collectLocal is a bridged collection's Task.Local.
type collectLocal struct {
	Options *core.CollectOptions `json:"options,omitempty"`
}

type collectorBridge struct {
	tool.Tool
	c core.Collector
	o options
	m tool.Manifest
}

// CollectorBridge is a tool built from a core.Collector.
type CollectorBridge interface {
	Bridge
	// Collector is the bridged collector.
	Collector() core.Collector
	// Local is the Task.Local of a collection with opts. Its APIKey is
	// never part of it (WithAPIKeyCredential).
	Local(opts *core.CollectOptions) (json.RawMessage, error)
}

// FromCollector returns c as a tool described by m (a connector: its
// network is the declared vendor hosts). Each task collects once and emits
// every report.
func FromCollector(m tool.Manifest, c core.Collector, opts ...Option) CollectorBridge {
	if c == nil {
		panic("toolcompat: FromCollector with a nil collector")
	}
	b := &collectorBridge{c: c}
	for _, o := range opts {
		o(&b.o)
	}
	b.Tool = newTool(m, b.run)
	b.m = b.Tool.Manifest()
	return b
}

func (b *collectorBridge) Legacy() any               { return b.c }
func (b *collectorBridge) Collector() core.Collector { return b.c }
func (b *collectorBridge) Manifest() tool.Manifest   { return b.m }

func (b *collectorBridge) Local(opts *core.CollectOptions) (json.RawMessage, error) {
	l := collectLocal{}
	if opts != nil {
		cp := *opts
		cp.APIKey = ""
		l.Options = &cp
	}
	return json.Marshal(l)
}

func (b *collectorBridge) run(ctx tool.Context, task tool.Task, _ map[string]any) error {
	var l collectLocal
	if err := decodeLocal(task.Local, &l); err != nil {
		return err
	}
	opts := &core.CollectOptions{}
	if l.Options != nil {
		opts = l.Options
	}
	opts.APIKey = ""
	if b.o.apiKey != "" {
		sec, err := ctx.Secret(b.o.apiKey)
		if err != nil {
			return tool.Invalid("%s: credential %q: %v", b.m.Name, b.o.apiKey, err)
		}
		opts.APIKey = sec.Reveal()
	}
	if b.o.prepare != nil {
		if err := b.o.prepare(ctx, b.c); err != nil {
			return err
		}
	}
	res, err := b.c.Collect(ctx, opts)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return tool.Failed(err)
	}
	if res == nil {
		return nil
	}
	for _, r := range res.Reports {
		if r == nil {
			continue
		}
		if err := ctx.Emit().Report(r); err != nil {
			if errors.Is(err, tool.ErrOutputLimit) {
				return nil
			}
			ctx.Log().Warn(b.m.Name+": a record was refused", "error", err.Error())
		}
	}
	return nil
}
