package tool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Handler does the work of one task of a tool declared with Define. job
// holds the task and its parameters (validated, defaults filled); emit
// builds CTIS records.
type Handler func(ctx Context, job *Job, emit Emit) error

// Builder declares a simple tool without writing a manifest by hand:
//
//	var Dotenv = tool.Define("dotenv", "1.0.0").
//		Describe("Finds .env files a web server serves").
//		Targets("http_service", "domain").
//		Produces("finding:misconfiguration").
//		Params(
//			tool.StringParam("path").Label("Path").Default("/.env").Pattern("^/").MaxLength(256),
//			tool.IntParam("timeout").Label("Timeout (s)").Default(10).Range(1, 60),
//		).
//		Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
//			for _, t := range job.Targets() {
//				// ... probe t.URL(job.Param("path").String()) ...
//				_ = emit.Misconfiguration(t, tool.Issue{RuleID: "dotenv-exposed", Title: ".env is readable", Severity: "high"})
//				ctx.TargetDone(t)
//			}
//			return nil
//		}).
//		MustBuild()
//
// The result is an ordinary Tool: the same manifest checks, the same
// runtime guarantees (out-of-process execution, admission, output checks,
// provenance) and the same tests (pkg/testkit) as a tool written with New.
// Fields the builder has no method for are set with Manifest.
type Builder struct {
	m      Manifest
	params []*Param
	handle Handler
}

// Define starts a tool declaration. The defaults are the target-scan class
// and tier T1 (active, non-intrusive); Class and Tier change them.
func Define(name, version string) *Builder {
	return &Builder{m: Manifest{Name: name, Version: version, Class: TargetScan}}
}

// Describe sets the tool's description.
func (b *Builder) Describe(s string) *Builder { b.m.Description = s; return b }

// Class sets the execution class.
func (b *Builder) Class(c Class) *Builder { b.m.Class = c; return b }

// Tier sets the intrusiveness tier.
func (b *Builder) Tier(t Tier) *Builder { b.m.Tier = t; return b }

// Targets declares the target types the tool works on (CTIS asset types,
// the manifest's consumes).
func (b *Builder) Targets(types ...string) *Builder {
	b.m.Consumes = append(b.m.Consumes, types...)
	return b
}

// Produces declares the output types ("finding:<type>", "asset:<type>",
// "dependency"). A record of any other type is refused.
func (b *Builder) Produces(kinds ...string) *Builder {
	b.m.Produces = append(b.m.Produces, kinds...)
	return b
}

// Capabilities declares the platform capability ids the tool provides.
func (b *Builder) Capabilities(ids ...string) *Builder {
	b.m.Capabilities = append(b.m.Capabilities, ids...)
	return b
}

// Timeout bounds one task of the tool.
func (b *Builder) Timeout(d time.Duration) *Builder { b.m.Resources.Timeout = Duration(d); return b }

// Params declares the tool's parameters: they become the manifest's
// configuration schema, which the platform renders as a form and the
// runtime enforces.
func (b *Builder) Params(ps ...*Param) *Builder {
	b.params = append(b.params, ps...)
	return b
}

// Manifest edits the manifest directly, for the fields the builder has no
// method for (permissions, credentials, resources, self-tests, modes).
func (b *Builder) Manifest(edit func(m *Manifest)) *Builder {
	if edit != nil {
		edit(&b.m)
	}
	return b
}

// Handle sets the function that runs a task.
func (b *Builder) Handle(h Handler) *Builder { b.handle = h; return b }

// Build checks the declaration and returns the tool.
func (b *Builder) Build() (Tool, error) {
	if b.handle == nil {
		return nil, errors.New("tool " + b.m.Name + ": no handler (Handle)")
	}
	m := b.m
	if m.Tier == "" {
		m.Tier = T1
		if m.Class != TargetScan {
			m.Tier = T0
		}
	}
	if len(b.params) > 0 {
		if len(m.Config) > 0 {
			return nil, fmt.Errorf("tool %s: declare parameters with Params or a config schema, not both", m.Name)
		}
		raw, err := paramSchema(b.params)
		if err != nil {
			return nil, fmt.Errorf("tool %s: %w", m.Name, err)
		}
		m.Config = raw
	}
	m = m.withDefaults()
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("tool %s: %w", m.Name, err)
	}
	schema, err := m.ConfigSchema()
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", m.Name, err)
	}
	return &builtTool{m: m, schema: schema, handle: b.handle}, nil
}

// MustBuild is Build for a package-level declaration: an invalid tool
// compiled into a sensor must stop it at start, not run.
func (b *Builder) MustBuild() Tool {
	t, err := b.Build()
	if err != nil {
		panic(err)
	}
	return t
}

type builtTool struct {
	m      Manifest
	schema *core.SettingsSchema
	handle Handler
}

func (t *builtTool) Manifest() Manifest { return t.m }

func (t *builtTool) Run(ctx Context, task Task) error {
	job, err := newJob(t.schema, task)
	if err != nil {
		return err
	}
	return t.handle(ctx, job, Emit{e: ctx.Emit()})
}

func newJob(schema *core.SettingsSchema, task Task) (*Job, error) {
	values, err := DecodeConfig[map[string]any](schema, task.Config)
	if err != nil {
		return nil, err
	}
	return &Job{Task: task, values: values}, nil
}

// Param is one parameter of a tool declared with Define. Its methods set
// what the platform shows (Label, Help) and what the runtime enforces
// (Default, Range, OneOf, Pattern, MaxLength, MaxItems, Required).
type Param struct {
	key      string
	prop     map[string]any
	required bool
	err      error
}

func newParam(key, typ string) *Param {
	return &Param{key: key, prop: map[string]any{"type": typ}}
}

// StringParam declares a string parameter.
func StringParam(key string) *Param { return newParam(key, "string") }

// IntParam declares an integer parameter.
func IntParam(key string) *Param { return newParam(key, "integer") }

// NumberParam declares a number parameter.
func NumberParam(key string) *Param { return newParam(key, "number") }

// BoolParam declares a boolean parameter.
func BoolParam(key string) *Param { return newParam(key, "boolean") }

// ListParam declares a list of strings.
func ListParam(key string) *Param {
	p := newParam(key, "array")
	p.prop["items"] = map[string]any{"type": "string"}
	return p
}

// Label is the short name the platform shows.
func (p *Param) Label(s string) *Param { p.prop["title"] = s; return p }

// Help is the longer explanation the platform shows.
func (p *Param) Help(s string) *Param { p.prop["description"] = s; return p }

// Default is the value used when the task does not set one.
func (p *Param) Default(v any) *Param {
	p.prop["default"] = v
	return p
}

// Range bounds a number or integer parameter (inclusive).
func (p *Param) Range(lo, hi float64) *Param {
	p.prop["minimum"], p.prop["maximum"] = lo, hi
	return p
}

// OneOf limits the parameter to these values.
func (p *Param) OneOf(vals ...any) *Param { p.prop["enum"] = vals; return p }

// Pattern is a regular expression a string parameter must match.
func (p *Param) Pattern(re string) *Param { p.prop["pattern"] = re; return p }

// MaxLength bounds a string parameter.
func (p *Param) MaxLength(n int) *Param { p.prop["maxLength"] = n; return p }

// MaxItems bounds a list parameter.
func (p *Param) MaxItems(n int) *Param { p.prop["maxItems"] = n; return p }

// Required makes the task fail validation when the parameter is not set.
func (p *Param) Required() *Param { p.required = true; return p }

// PerScan lets a scan set the parameter (otherwise only the tool's
// settings on the sensor or platform do).
func (p *Param) PerScan() *Param { p.prop["x-octm-scope"] = "scan"; return p }

// paramSchema builds the configuration schema of a parameter list.
func paramSchema(ps []*Param) (json.RawMessage, error) {
	props := map[string]any{}
	var required []string
	for _, p := range ps {
		if p == nil {
			continue
		}
		if p.key == "" {
			return nil, errors.New("a parameter needs a key")
		}
		if _, dup := props[p.key]; dup {
			return nil, fmt.Errorf("parameter %q declared twice", p.key)
		}
		if secretNameRE.MatchString(p.key) {
			return nil, fmt.Errorf("parameter %q looks like a secret: declare a credential (permissions.credentials) instead", p.key)
		}
		props[p.key] = p.prop
		if p.required {
			required = append(required, p.key)
		}
	}
	root := map[string]any{
		"type": "object", "additionalProperties": false, "properties": props, "x-octm-schema-version": 1,
	}
	if len(required) > 0 {
		slices.Sort(required)
		root["required"] = required
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	out := json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
	if _, err := core.ParseSettingsSchema(out); err != nil {
		return nil, fmt.Errorf("parameters: %w", err)
	}
	return out, nil
}

// Job is one task of a tool declared with Define, with typed access to its
// targets and parameters.
type Job struct {
	Task
	values map[string]any
}

// Targets returns the task's targets, only those of the given types when
// any are given.
func (j *Job) Targets(types ...string) []Target {
	if len(types) == 0 {
		return j.Task.Targets
	}
	var out []Target
	for _, t := range j.Task.Targets {
		if slices.Contains(types, t.Type) {
			out = append(out, t)
		}
	}
	return out
}

// Param returns a parameter's value (its default when the task did not
// set it).
func (j *Job) Param(key string) Value {
	v, ok := j.values[key]
	return Value{v: v, ok: ok && v != nil}
}

// Value is a parameter's value. The runtime validated it against the
// parameter's declaration, so the typed accessors only fall back when the
// parameter is unset (no default) or of another type.
type Value struct {
	v  any
	ok bool
}

// IsSet reports whether the parameter has a value (given or default).
func (v Value) IsSet() bool { return v.ok }

// String returns the value as a string ("" when unset).
func (v Value) String() string { return v.StringOr("") }

// StringOr returns the value, or d when it is unset or not a string.
func (v Value) StringOr(d string) string {
	if s, ok := v.v.(string); ok {
		return s
	}
	return d
}

// Int returns the value as an int (0 when unset).
func (v Value) Int() int { return v.IntOr(0) }

// IntOr returns the value, or d when it is unset or not a number.
func (v Value) IntOr(d int) int {
	if f, ok := v.v.(float64); ok {
		return int(f)
	}
	return d
}

// Float returns the value as a float64 (0 when unset).
func (v Value) Float() float64 { return v.FloatOr(0) }

// FloatOr returns the value, or d when it is unset or not a number.
func (v Value) FloatOr(d float64) float64 {
	if f, ok := v.v.(float64); ok {
		return f
	}
	return d
}

// Bool returns the value as a bool (false when unset).
func (v Value) Bool() bool { return v.BoolOr(false) }

// BoolOr returns the value, or d when it is unset or not a bool.
func (v Value) BoolOr(d bool) bool {
	if b, ok := v.v.(bool); ok {
		return b
	}
	return d
}

// Strings returns a list value (nil when unset).
func (v Value) Strings() []string {
	list, ok := v.v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Emit builds CTIS records for the common cases and sends them through the
// task's emitter, which checks each one (CTIS validity, declared output
// types, limits). CTIS returns the emitter for anything else.
type Emit struct{ e Emitter }

// Issue is a finding in a few fields. Severity is critical, high, medium,
// low or info.
type Issue struct {
	RuleID      string
	Title       string
	Severity    ctis.Severity
	Description string
	// Evidence is the proof (a response excerpt, a banner); never a
	// secret value.
	Evidence string
	// CVE is the vulnerability's CVE id (Vulnerability only).
	CVE string
}

func (i Issue) finding(typ ctis.FindingType) ctis.Finding {
	f := ctis.Finding{Type: typ, RuleID: i.RuleID, Title: i.Title, Severity: i.Severity,
		Description: i.Description, Evidence: i.Evidence}
	if i.CVE != "" {
		f.Vulnerability = &ctis.VulnerabilityDetails{CVEID: i.CVE}
	}
	return f
}

// Vulnerability emits a vulnerability finding on target t.
func (e Emit) Vulnerability(t Target, i Issue) error {
	return e.e.Finding(t, i.finding(ctis.FindingTypeVulnerability))
}

// Misconfiguration emits a misconfiguration finding on target t.
func (e Emit) Misconfiguration(t Target, i Issue) error {
	return e.e.Finding(t, i.finding(ctis.FindingTypeMisconfiguration))
}

// Asset emits a discovered asset of a CTIS type ("domain", "ip_address",
// "http_service", ...).
func (e Emit) Asset(typ, value string) error {
	return e.e.Asset(ctis.Asset{Type: ctis.AssetType(typ), Value: value})
}

// CTIS returns the task's emitter, for records the helpers do not cover.
func (e Emit) CTIS() Emitter { return e.e }
