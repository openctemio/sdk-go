package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ContractOptions configure RunContractSuite.
type ContractOptions struct {
	// Timeout bounds each run (zero: 30s).
	Timeout time.Duration
	// Credentials are what an operator would store for the tool.
	Credentials map[string]string
	// Capability runs the per-capability suites: fixture targets on
	// loopback (open and closed ports, an HTTP app with known issues, a
	// repository with a fake secret, ...) and the capability's checks.
	Capability bool
	// Scope runs the scope check: the tool is given target A while an
	// address B listens; any connection to B fails.
	Scope bool
	// Fuzz, when positive, fuzzes the parser of the tool's output format
	// for this long (see FuzzOutput).
	Fuzz time.Duration
	// Env is extra environment for the tool (tests).
	Env map[string]string
	// ScopeListenAddr is the address B listens on ("": 127.0.0.2:0).
	ScopeListenAddr string
}

// LintIssue is one descriptor lint finding.
type LintIssue struct {
	// Level is "error" or "warning".
	Level   string
	Path    string
	Message string
}

func (l LintIssue) String() string { return l.Level + ": " + l.Path + ": " + l.Message }

// LintDescriptor checks what Validate accepts but a good descriptor should
// not leave out: the contract (implements), self-test fixtures, a display
// name, an engine version probe for a wrapped program, a rate key for a
// capability with a rate param, and the deprecated keys.
func LintDescriptor(m tool.Manifest) []LintIssue {
	var out []LintIssue
	warn := func(p, msg string) { out = append(out, LintIssue{Level: "warning", Path: p, Message: msg}) }
	if len(m.Implements) == 0 && m.Class == tool.TargetScan {
		warn("/implements", "no capability implemented: the platform can route the tool only by its name")
	}
	if len(m.Capabilities) > 0 {
		warn("/capabilities", "deprecated: use implements")
	}
	if m.Retest {
		warn("/retest", "deprecated spelling: use features.retest")
	}
	if len(m.Selftest) == 0 {
		warn("/selftest", "no self-test fixture: add one, it is how the sensor and the platform prove the tool works")
	}
	if m.Presentation == nil || m.Presentation.DisplayName == "" {
		warn("/presentation/display_name", "no display name: the platform shows the tool name")
	}
	if m.Run != nil && m.Run.Profile == tool.ProfileExec && (m.Engine == nil || len(m.Engine.VersionProbe) == 0) {
		warn("/engine/version_probe", "the wrapped program's version is not probed: the platform cannot report it as outdated")
	}
	for _, c := range m.ImplementedCapabilities() {
		if _, ok := c.Param("rate"); ok && (m.Safety == nil || m.Safety.RateParam == "") {
			warn("/safety/rate_param", c.Ref()+" has a rate param but the tool names no rate key: the sensor policy cannot cap it")
		}
	}
	return out
}

// RunContractSuite checks a tool against the contract of the capabilities
// it implements, the way the sensor runs it (every task through the
// runtime's host and sandbox):
//
//   - Lint: LintDescriptor (warnings are notes).
//   - FixtureContract: every self-test fixture, run as a task of each
//     implemented capability, has no contract violation (required output
//     paths, allowed outputs).
//   - Capability suites (opts.Capability): per capability, fixture
//     targets on loopback and checks of what the tool found.
//   - Scope (opts.Scope): no connection to an address it was not given.
//   - Fuzz (opts.Fuzz): FuzzOutput.
func RunContractSuite(t T, manifestPath string, opts ContractOptions) {
	t.Helper()
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if abs, err := filepath.Abs(manifestPath); err == nil {
		manifestPath = abs
	}
	m, err := tool.LoadManifestFile(manifestPath)
	if err != nil {
		t.Fatalf("Manifest: %v", err)
		return
	}
	m = m.Normalized()
	r := &contractRun{t: t, m: m, dir: filepath.Dir(manifestPath), opts: opts}
	for _, l := range LintDescriptor(m) {
		t.Logf("Lint: %s", l)
	}
	if m.Run == nil {
		t.Logf("%s has no run section: a tool compiled into a sensor is tested with pkg/testkit", m.Name)
		return
	}
	r.fixtureContract()
	if opts.Capability {
		for _, c := range m.ImplementedCapabilities() {
			r.capabilitySuite(c)
		}
	}
	if opts.Scope {
		r.scope()
	}
	if opts.Fuzz > 0 {
		FuzzOutput(t, m, r.dir, opts.Fuzz)
	}
}

type contractRun struct {
	t    T
	m    tool.Manifest
	dir  string
	opts ContractOptions
}

func (r *contractRun) run(task tool.Task) (*toolhost.Outcome, error) {
	return r.runEnv(task, nil)
}

// runEnv runs a task with extra environment on top of opts.Env.
func (r *contractRun) runEnv(task tool.Task, extra map[string]string) (*toolhost.Outcome, error) {
	if task.ID == "" {
		task.ID = fmt.Sprintf("conformance-%d", time.Now().UnixNano())
	}
	env := maps.Clone(r.opts.Env)
	if len(extra) > 0 && env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, extra)
	ctx, cancel := context.WithTimeout(context.Background(), r.opts.Timeout)
	defer cancel()
	host := &toolhost.Host{Sensor: "conformance", RuntimeName: conformanceRuntime}
	return host.RunManifest(ctx, r.m, task, toolhost.RunOptions{Trusted: true, Dir: r.dir, Credentials: r.opts.Credentials, Env: env})
}

func (r *contractRun) fixtureContract() {
	caps := r.m.ImplementedCapabilities()
	if len(caps) == 0 || len(r.m.Selftest) == 0 {
		return
	}
	for _, f := range r.m.Selftest {
		task, err := loadFixtureTask(r.dir, f)
		if err != nil {
			r.t.Errorf("FixtureContract/%s: %v", f.Name, err)
			continue
		}
		for _, c := range caps {
			if task.Capability != "" && task.Capability != c.Ref() {
				continue
			}
			tk := task
			tk.Capability = c.Ref()
			out, err := r.run(tk)
			if err != nil {
				r.t.Errorf("FixtureContract/%s/%s: %v", f.Name, c.Ref(), err)
				continue
			}
			if out.Status == tool.StatusFailed {
				r.t.Errorf("FixtureContract/%s/%s: the task failed: %v", f.Name, c.Ref(), out.Err)
				continue
			}
			if v, _ := c.Check(out.Report, capability.CheckOptions{Shape: outputShape(r.m, c)}); len(v) > 0 {
				r.t.Errorf("FixtureContract/%s/%s: %d record(s) miss the contract, first: %s", f.Name, c.Ref(), len(v), v[0])
			}
		}
	}
}

func outputShape(m tool.Manifest, c capability.Capability) string {
	im, _ := m.Implementation(c.Ref())
	return im.OutputShape
}

// target picks the first type the tool consumes from candidates (in the
// suite's order of preference) and returns a target of it.
func (r *contractRun) target(candidates [][2]string) (tool.Target, bool) {
	for _, c := range candidates {
		if len(r.m.Consumes) == 0 || slices.Contains(r.m.Consumes, c[0]) {
			return tool.Target{Ref: "a", Type: c[0], Value: c[1]}, true
		}
	}
	return tool.Target{}, false
}

// takes reports whether the tool maps the capability's standard param.
func (r *contractRun) takes(c capability.Capability, param string) bool {
	im, _ := r.m.Implementation(c.Ref())
	_, ok := im.Params[param]
	return ok
}

// listener accepts and closes connections and counts them.
type listener struct {
	ln    net.Listener
	mu    sync.Mutex
	count int
}

func listen(addr string) (*listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &listener{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			l.count++
			l.mu.Unlock()
			_ = c.Close()
		}
	}()
	return l, nil
}

func (l *listener) port() int     { return l.ln.Addr().(*net.TCPAddr).Port }
func (l *listener) close()        { _ = l.ln.Close() }
func (l *listener) accepted() int { l.mu.Lock(); defer l.mu.Unlock(); return l.count }

// closedPort is a loopback port nothing listens on.
func closedPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 1
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// reportJSON is the report as generic JSON.
func reportJSON(r *ctis.Report) map[string]any {
	raw, _ := json.Marshal(r)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	return doc
}

// openPorts are the ports a report says are open, in either shape of
// scan.ports.
func openPorts(r *ctis.Report) []int {
	var out []int
	addPort := func(v any) {
		if f, ok := v.(float64); ok && !slices.Contains(out, int(f)) {
			out = append(out, int(f))
		}
	}
	assets, _ := reportJSON(r)["assets"].([]any)
	for _, a := range assets {
		am, _ := a.(map[string]any)
		if am["type"] == "open_port" {
			props, _ := am["properties"].(map[string]any)
			addPort(props["port"])
		}
		if tech, ok := am["technical"].(map[string]any); ok {
			if ip, ok := tech["ip_address"].(map[string]any); ok {
				ports, _ := ip["ports"].([]any)
				for _, p := range ports {
					pm, _ := p.(map[string]any)
					addPort(pm["port"])
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func strParam(v string) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ",")
}
