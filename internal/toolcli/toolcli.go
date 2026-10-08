// Package toolcli is the "openctem tool" command: scaffold, validate, run,
// test, diff and describe a tool. cmd/openctem and the older
// cmd/openctem-conformance call it.
package toolcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

const usage = `usage: openctem tool <command> [flags]

commands:
  init      --kind exec-sarif|exec-ctis|exec-json|go|python --capability <id@major> [--name n] [dir]
  validate  [dir|tool.yaml]
  run       [dir|tool.yaml] --target value[@type] [--capability id@major] [--param k=json] [--config k=v] [--format table|ctis] [--sandbox auto]
  test      [dir|tool.yaml] [--update] [--capability] [--scope] [--fuzz 30s] [--timeout 30s] [--sandbox auto]
  diff      <old tool.yaml> <new tool.yaml>
  describe  [--json] [dir|tool.yaml]
`

// Main runs "openctem tool <args>".
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest, stdout, stderr)
	case "validate":
		return cmdValidate(rest, stdout, stderr)
	case "run":
		return cmdRun(rest, stdout, stderr)
	case "test":
		return cmdTest(rest, stdout, stderr)
	case "diff":
		return cmdDiff(rest, stdout, stderr)
	case "describe":
		return cmdDescribe(rest, stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n%s", cmd, usage)
	return ExitUsage
}

// manifestPath is the tool.yaml of a directory or the file itself.
func manifestPath(arg string) string {
	if arg == "" {
		arg = "."
	}
	if st, err := os.Stat(arg); err == nil && st.IsDir() {
		arg = filepath.Join(arg, "tool.yaml")
	}
	// Absolute: a relative program in run.argv is resolved against the
	// manifest's directory, and the task runs in its own directory.
	if abs, err := filepath.Abs(arg); err == nil {
		return abs
	}
	return arg
}

func flags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseInterspersed parses flags that may come after the positional
// argument ("validate dir --x").
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flags("validate", stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	path := manifestPath(first(pos))
	m, err := tool.LoadManifestFile(path)
	if err != nil {
		var me tool.ManifestErrors
		if errors.As(err, &me) {
			for _, e := range me {
				_, _ = fmt.Fprintf(stdout, "%s: %s\n", path, e.Error())
			}
		} else {
			_, _ = fmt.Fprintf(stdout, "%s: %v\n", path, err)
		}
		_, _ = fmt.Fprintln(stdout, "INVALID")
		return ExitFail
	}
	for _, l := range conformance.LintDescriptor(m) {
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", path, l)
	}
	_, _ = fmt.Fprintf(stdout, "%s %s: valid (%s)\n", m.Name, m.Version, m.Digest())
	return ExitOK
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// multi is a repeatable flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := flags("run", stderr)
	var targets, params, configs multi
	fs.Var(&targets, "target", "a target, value[@type] (repeatable)")
	fs.Var(&params, "param", "a standard param of the capability, key=json (repeatable)")
	fs.Var(&configs, "config", "a config key, key=value; the value is read as JSON when it parses, else as a string (repeatable)")
	capRef := fs.String("capability", "", "run the task as this capability (id@major)")
	format := fs.String("format", "table", "table or ctis")
	timeout := fs.Duration("timeout", 10*time.Minute, "task timeout")
	sandbox := fs.String("sandbox", "", "off, auto or required (default: $"+EnvSandbox+", else auto)")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 || (*format != "table" && *format != "ctis") {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	if err := InstallSandbox(*sandbox, stderr); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	path := manifestPath(first(pos))
	m, err := tool.LoadManifestFile(path)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	task := tool.Task{ID: "cli-run", Capability: *capRef}
	for i, t := range targets {
		value, typ, _ := strings.Cut(t, "@")
		if typ == "" && len(m.Consumes) > 0 {
			typ = m.Consumes[0]
		}
		task.Targets = append(task.Targets, tool.Target{Ref: fmt.Sprintf("t%d", i+1), Type: typ, Value: value})
	}
	if len(params) > 0 {
		task.Params = map[string]json.RawMessage{}
		for _, p := range params {
			k, v, _ := strings.Cut(p, "=")
			if !json.Valid([]byte(v)) {
				v = jsonString(v)
			}
			task.Params[k] = json.RawMessage(v)
		}
	}
	if len(configs) > 0 {
		cfg := map[string]json.RawMessage{}
		for _, c := range configs {
			k, v, _ := strings.Cut(c, "=")
			if !json.Valid([]byte(v)) {
				v = jsonString(v)
			}
			cfg[k] = json.RawMessage(v)
		}
		task.Config, _ = json.Marshal(cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	host := &toolhost.Host{Sensor: "openctem-cli", RuntimeName: "openctem-cli"}
	out, err := host.RunManifest(ctx, m, task, toolhost.RunOptions{Trusted: true, Dir: filepath.Dir(path)})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	if *format == "ctis" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out.Report)
	} else {
		printOutcome(stdout, out)
	}
	if out.Status == tool.StatusFailed {
		return ExitFail
	}
	return ExitOK
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func printOutcome(w io.Writer, out *toolhost.Outcome) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "status\t%s\n", out.Status)
	if out.Err != nil {
		_, _ = fmt.Fprintf(tw, "error\t%s: %s\n", out.Err.Class, out.Err.Detail)
	}
	_, _ = fmt.Fprintf(tw, "sandbox\t%s\n", out.Sandbox.Mode)
	_, _ = fmt.Fprintf(tw, "records\t%d (assets %d, findings %d, dependencies %d)\n", out.Stats.Records,
		len(out.Report.Assets), len(out.Report.Findings), len(out.Report.Dependencies))
	if out.Stats.ContractViolations > 0 {
		_, _ = fmt.Fprintf(tw, "contract violations\t%d\n", out.Stats.ContractViolations)
	}
	if len(out.Stats.Quarantined) > 0 {
		keys := make([]string, 0, len(out.Stats.Quarantined))
		for k := range out.Stats.Quarantined {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = fmt.Fprintf(tw, "quarantined\t%s: %d\n", k, out.Stats.Quarantined[k])
		}
	}
	for _, t := range out.Targets {
		_, _ = fmt.Fprintf(tw, "target %s\t%s %s %s\n", t.Value, t.State, t.Class, t.Detail)
	}
	for _, a := range out.Report.Assets {
		_, _ = fmt.Fprintf(tw, "asset\t%s %s\n", a.Type, a.Value)
	}
	for _, f := range out.Report.Findings {
		_, _ = fmt.Fprintf(tw, "finding\t%s %s %s\n", f.Severity, f.RuleID, f.Title)
	}
	for _, l := range out.Logs {
		_, _ = fmt.Fprintf(tw, "log %s\t%s\n", l.Level, l.Msg)
	}
	_ = tw.Flush()
}

// printer is a conformance.T that prints.
type printer struct {
	out    io.Writer
	failed bool
}

var errFatal = errors.New("fatal")

func (p *printer) Helper() {}
func (p *printer) Logf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.out, "  note: "+format+"\n", args...)
}
func (p *printer) Errorf(format string, args ...any) {
	p.failed = true
	_, _ = fmt.Fprintf(p.out, "  FAIL: "+format+"\n", args...)
}
func (p *printer) Fatalf(format string, args ...any) {
	p.Errorf(format, args...)
	panic(errFatal)
}

// guarded runs a suite and stops it at a Fatalf.
func guarded(fn func()) {
	defer func() {
		if v := recover(); v != nil && v != errFatal { //nolint:errorlint // the sentinel itself is the panic value
			panic(v)
		}
	}()
	fn()
}

// Test runs the protocol and fixture suite and the contract suite of one
// tool: the "test" command, and the older "openctem-conformance tool".
func Test(path string, opts conformance.ContractOptions, update bool, stdout io.Writer) int {
	p := &printer{out: stdout}
	guarded(func() {
		conformance.RunToolSuite(p, path, conformance.ToolSuiteOptions{Timeout: opts.Timeout, Update: update, Credentials: opts.Credentials})
	})
	if !p.failed && !update {
		guarded(func() { conformance.RunContractSuite(p, path, opts) })
	}
	if p.failed {
		_, _ = fmt.Fprintln(stdout, "FAIL")
		return ExitFail
	}
	_, _ = fmt.Fprintln(stdout, "PASS")
	return ExitOK
}

func cmdTest(args []string, stdout, stderr io.Writer) int {
	fs := flags("test", stderr)
	update := fs.Bool("update", false, "rewrite each fixture's expect file with what the tool produced")
	capSuites := fs.Bool("capability", false, "run the per-capability suites on loopback fixtures")
	scope := fs.Bool("scope", false, "run the scope check (no connection to an address the tool was not given)")
	fuzz := fs.Duration("fuzz", 0, "fuzz the output parser for this long (0: off)")
	timeout := fs.Duration("timeout", 30*time.Second, "bound of each check")
	sandbox := fs.String("sandbox", "", "off, auto or required (default: $"+EnvSandbox+", else auto)")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	if err := InstallSandbox(*sandbox, stderr); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	return Test(manifestPath(first(pos)), conformance.ContractOptions{Timeout: *timeout, Capability: *capSuites, Scope: *scope, Fuzz: *fuzz}, *update, stdout)
}

func cmdDiff(args []string, stdout, stderr io.Writer) int {
	fs := flags("diff", stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 2 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	oldM, err := tool.LoadManifestFile(manifestPath(pos[0]))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "old: %v\n", err)
		return ExitFail
	}
	newM, err := tool.LoadManifestFile(manifestPath(pos[1]))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "new: %v\n", err)
		return ExitFail
	}
	d := conformance.DiffManifests(oldM, newM)
	for _, b := range d.Breaking {
		_, _ = fmt.Fprintf(stdout, "breaking: %s\n", b)
	}
	for _, a := range d.Additions {
		_, _ = fmt.Fprintf(stdout, "added: %s\n", a)
	}
	_, _ = fmt.Fprintf(stdout, "needs: %s bump (%s to %s)\n", d.Required, oldM.Version, newM.Version)
	for _, p := range d.Problems {
		_, _ = fmt.Fprintf(stdout, "problem: %s\n", p)
	}
	if !d.OK() {
		_, _ = fmt.Fprintln(stdout, "FAIL")
		return ExitFail
	}
	_, _ = fmt.Fprintln(stdout, "OK")
	return ExitOK
}

func cmdDescribe(args []string, stdout, stderr io.Writer) int {
	fs := flags("describe", stderr)
	asJSON := fs.Bool("json", false, "print the canonical descriptor and its digest as JSON")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	m, err := tool.LoadManifestFile(manifestPath(first(pos)))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	canon, err := m.Canonical()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	if *asJSON {
		out, _ := json.Marshal(map[string]any{"digest": m.Digest(), "descriptor": json.RawMessage(canon)})
		_, _ = fmt.Fprintln(stdout, string(out))
		return ExitOK
	}
	_, _ = fmt.Fprintf(stdout, "%s %s (%s, %s)\ndigest %s\n", m.Name, m.Version, m.Class, m.MinimumTier(), m.Digest())
	for _, im := range m.Implements {
		_, _ = fmt.Fprintf(stdout, "implements %s\n", im.Capability)
	}
	_, _ = fmt.Fprintf(stdout, "consumes %s\nproduces %s\n", strings.Join(m.Consumes, ", "), strings.Join(m.Produces, ", "))
	return ExitOK
}
