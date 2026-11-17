package toolhost

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// testBudget is the per-host budget the package's tests run a tool under.
func testBudget() *adapt.HostBudget {
	b := adapt.DefaultBudget()
	return &b
}

// offHost is a host whose tools run without a sandbox.
func offHost(t *testing.T) *Host {
	t.Helper()
	h := testHost(t)
	off, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	h.Backend = off
	return h
}

// SECURITY: the tool host refuses to start a tool whose manifest says it
// connects to its targets when its caller gave no per-host budget, or one
// that names no numbers. No process starts and the target is never
// contacted. It holds for every way a tool is started.
func TestToolThatConnectsToItsTargetsNeedsABudget(t *testing.T) {
	srv, hits := recorder(t)
	task := tool.Task{ID: "guard-1", Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: srv.URL}}}
	for name, o := range map[string]RunOptions{
		"no budget":                       {},
		"a budget without numbers":        {HostBudget: &adapt.HostBudget{}},
		"a port prober without a budget":  {PortProbes: true},
		"a budget with a rate of zero":    {HostBudget: &adapt.HostBudget{RPS: 0, Inflight: 8}},
		"a budget with nothing in flight": {HostBudget: &adapt.HostBudget{RPS: 20}},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := offHost(t).RunBuiltin(context.Background(), dialTool, task, o)
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tool.RefusedByPolicy || !strings.Contains(out.Err.Detail, ErrNoHostBudget.Error()) {
				t.Fatalf("outcome %s %+v", out.Status, out.Err)
			}
			if out.ExitCode != -1 {
				t.Fatalf("a process ran: exit code %d", out.ExitCode)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("the target was contacted %d time(s) by a tool that had no budget", hits.Load())
	}
	// With one, the same tool runs.
	out, err := offHost(t).RunBuiltin(context.Background(), dialTool, task, RunOptions{HostBudget: testBudget()})
	if err != nil || out.Err != nil || hits.Load() == 0 {
		t.Fatalf("with a budget: %v %+v, %d connection(s)", err, out.Err, hits.Load())
	}
	// A tool that sends nothing to its targets needs none.
	for _, n := range []tool.Network{tool.NetNone, tool.NetResolver, tool.NetVendor} {
		m := tool.Manifest{Name: "other", Permissions: tool.Permissions{Network: n}}
		if e := requireBudget(m, task, RunOptions{}); e != nil {
			t.Fatalf("network %s: %+v", n, e)
		}
	}
	// A tool that reaches the internet through the sensor's egress reaches
	// its targets too: it needs one like a tool of network targets.
	proxied := tool.Manifest{Name: "proxied", Permissions: tool.Permissions{Network: tool.NetEgressProxy}}
	if e := requireBudget(proxied, task, RunOptions{}); e == nil || e.Class != tool.RefusedByPolicy {
		t.Fatalf("an egress-proxy tool without a budget: %+v", e)
	}
}

// SECURITY: a target-scan tool that declares network egress-proxy (it may
// reach any public host, its targets included) is refused without a
// per-host budget, whatever path starts it, and with one its forwarder
// holds each host to the budget like a tool of network targets: no process
// starts without one, and the budget's slots and rate reach the forwarder.
func TestEgressProxyToolNeedsABudget(t *testing.T) {
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "proxied-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"web_origin"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetEgressProxy},
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe, "-rate=1"},
			Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	srv, hits := recorder(t)
	task := tool.Task{Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: srv.URL}}}
	env := map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}
	for name, o := range map[string]RunOptions{
		"no budget":                {Trusted: true, Env: env},
		"a budget without numbers": {Trusted: true, Env: env, HostBudget: &adapt.HostBudget{}},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := offHost(t).RunManifest(context.Background(), m, task, o)
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tool.RefusedByPolicy || !strings.Contains(out.Err.Detail, ErrNoHostBudget.Error()) {
				t.Fatalf("outcome %s %+v", out.Status, out.Err)
			}
			if out.ExitCode != -1 {
				t.Fatalf("a process ran: exit code %d", out.ExitCode)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("the target was contacted %d time(s)", hits.Load())
	}
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	b := budgetOf(m, task, RunOptions{HostBudget: &gentle})
	if b == nil || b.RPS != gentle.RPS || b.Inflight != gentle.Inflight {
		t.Fatalf("budget of an egress-proxy tool %+v", b)
	}
	confined := statusBackend{st: executor.Status{NetworkEnforced: true}}
	h := &Host{Backend: confined}
	eg, err := h.startEgress(context.Background(), confined, &prepared{m: m, task: task, targetRate: 160, budget: b})
	if err != nil {
		t.Fatal(err)
	}
	defer eg.stop()
	if rate, conns := eg.fw.PerHostLimits(); rate != float64(gentle.RPS) || conns != gentle.Inflight {
		t.Fatalf("an egress-proxy task's forwarder holds each host to %v/s and %d connections, want %d and %d", rate, conns, gentle.RPS, gentle.Inflight)
	}
	if s := eg.fw.TargetRate().Summary(); s.Budget == nil || s.Budget.Level != "gentle" {
		t.Fatalf("summary budget %+v", s.Budget)
	}
}

// SECURITY: a vendor tool whose vendor hosts (read from the task's
// configuration) name one of its targets reaches that target: it needs a
// budget and is held to it like a tool of network targets. A signed
// configuration cannot name a target as a vendor host to take the
// connections to it out of the budget. Vendor hosts that are no target
// change nothing.
func TestVendorHostThatIsATargetNeedsABudget(t *testing.T) {
	m := tool.Manifest{Name: "lookup", Permissions: tool.Permissions{Network: tool.NetVendor, VendorHosts: []string{"api.vendor.example", "${config.server}"}}}
	cases := []struct {
		name    string
		targets []tool.Target
		config  string
		want    bool
	}{
		{"vendor hosts only", []tool.Target{{Value: "https://a.example.com/"}}, `{"server":"https://intel.example.org/v1"}`, false},
		{"no configuration", []tool.Target{{Value: "a.example.com"}}, ``, false},
		{"the configuration names a target", []tool.Target{{Value: "https://a.example.com/"}}, `{"server":"https://A.Example.COM./v1"}`, true},
		{"a target with a port", []tool.Target{{Value: "a.example.com:8443"}}, `{"server":"a.example.com:8443"}`, true},
		{"an address in a target range", []tool.Target{{Value: "192.0.2.0/24"}}, `{"server":"https://192.0.2.7/"}`, true},
		{"an address outside it", []tool.Target{{Value: "192.0.2.0/24"}}, `{"server":"https://198.51.100.7/"}`, false},
		{"the manifest's own host is a target", []tool.Target{{Value: "https://api.vendor.example/"}}, `{}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task := tool.Task{Targets: tc.targets, Config: json.RawMessage(tc.config)}
			refused := requireBudget(m, task, RunOptions{}) != nil
			if refused != tc.want {
				t.Fatalf("refused without a budget: %t, want %t", refused, tc.want)
			}
			if got := budgetOf(m, task, RunOptions{HostBudget: testBudget()}) != nil; got != tc.want {
				t.Fatalf("held to the budget: %t, want %t", got, tc.want)
			}
			if requireBudget(m, task, RunOptions{HostBudget: testBudget()}) != nil {
				t.Fatal("refused with a budget")
			}
		})
	}
}

// An adapter tool (described by its manifest alone, run as its own
// program) that connects to its targets is refused without a budget, and
// with one it runs under it: its rate setting is the budget's, whatever
// the job asked for.
func TestAdapterToolRunsUnderTheBudget(t *testing.T) {
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "argv-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"web_origin"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetTargets},
		Safety:      &tool.Safety{RateParam: "rate"},
		Config: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
			"rate":{"type":"integer","minimum":1,"maximum":1000,"default":150}}}`),
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe, "-rate={{config.rate}}"},
			Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}
	task := func(cfg string) tool.Task {
		return tool.Task{Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: "https://a.example.com/"}}, Config: json.RawMessage(cfg)}
	}
	out, err := offHost(t).RunManifest(context.Background(), m, task(`{"rate":500}`), RunOptions{Trusted: true, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tool.RefusedByPolicy || !strings.Contains(out.Err.Detail, ErrNoHostBudget.Error()) {
		t.Fatalf("without a budget: %s %+v", out.Status, out.Err)
	}
	if out.Report != nil && len(out.Report.Findings) != 0 {
		t.Fatalf("the adapter ran without a budget: %+v", out.Report.Findings)
	}
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	for cfg, want := range map[string]string{
		`{"rate":500}`: "-rate=5", // asked above the budget
		`{}`:           "-rate=5", // the tool's default (150) is above it too
		`{"rate":2}`:   "-rate=2", // a lower rate stays
	} {
		out, err := offHost(t).RunManifest(context.Background(), m, task(cfg), RunOptions{Trusted: true, Env: env, HostBudget: &gentle})
		if err != nil {
			t.Fatal(err)
		}
		if out.Err != nil || len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != want {
			t.Fatalf("config %s: %+v (status %s, error %+v), want %q", cfg, out.Report.Findings, out.Status, out.Err, want)
		}
		s := out.TargetRate
		if s == nil || s.Budget == nil || s.Budget.Level != "gentle" || s.Budget.RPS != 5 || s.Budget.Inflight != 2 {
			t.Fatalf("config %s: the outcome does not state the budget: %+v", cfg, s)
		}
	}
}

// A port prober is paced in packets per second by its caller: the budget
// is still required, and the forwarder is not held to the budget's
// requests per second.
func TestPortProberKeepsTheTaskRate(t *testing.T) {
	m := tool.Manifest{Name: "prober", Permissions: tool.Permissions{Network: tool.NetTargets}}
	if e := requireBudget(m, tool.Task{}, RunOptions{PortProbes: true, HostBudget: testBudget()}); e != nil {
		t.Fatalf("%+v", e)
	}
	if b := budgetOf(m, tool.Task{}, RunOptions{PortProbes: true, HostBudget: testBudget()}); b != nil {
		t.Fatalf("a port prober's forwarder is held to requests per second: %+v", b)
	}
	if b := budgetOf(m, tool.Task{}, RunOptions{HostBudget: testBudget()}); b == nil {
		t.Fatal("a tool that connects to its targets has no budget")
	}
}

// SECURITY: a value under the tool's rate key that is not a rate of at
// least one a second (zero, negative, a fraction, a string, null, true)
// never stays in the configuration, where a tool could read it as "no
// limit": it is replaced by the tool's default or the budget, whichever is
// lower.
func TestCapBudgetRateReplacesAValueThatIsNotARate(t *testing.T) {
	std := adapt.DefaultBudget()
	one := []tool.Target{{Ref: "a", Value: "https://a.example.com/"}}
	withDefault := func(def int) tool.Manifest {
		cfg := `{"type":"object","additionalProperties":false,"properties":{"rate":{"type":"integer","minimum":1,"maximum":1000}}}`
		if def > 0 {
			cfg = `{"type":"object","additionalProperties":false,"properties":{"rate":{"type":"integer","minimum":1,"maximum":1000,"default":` + jsonInt(def) + `}}}`
		}
		return tool.Manifest{Name: "prober", Safety: &tool.Safety{RateParam: "rate"}, Permissions: tool.Permissions{Network: tool.NetTargets},
			Config: json.RawMessage(cfg)}
	}
	for _, bad := range []string{`0`, `-1`, `0.5`, `"fast"`, `"0"`, `null`, `true`, `[]`, `{}`} {
		for def, want := range map[int]float64{0: 20, 150: 20, 7: 7} {
			b := ptr(std)
			out, line, err := capBudgetRate(withDefault(def), json.RawMessage(`{"rate":`+bad+`}`), b, one, true)
			if err != nil {
				t.Fatalf("rate %s: %v", bad, err)
			}
			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			if got["rate"] != want || line == nil {
				t.Fatalf("rate %s with default %d: got %v (line %+v), want %v", bad, def, got["rate"], line, want)
			}
		}
	}
	// A configuration a decoder cannot read is an error, never passed on.
	if _, _, err := capBudgetRate(withDefault(0), json.RawMessage(`{"rate":1e400}`), ptr(std), one, true); err == nil {
		t.Fatal("an unreadable configuration was accepted")
	}
	// A very large rate is lowered like any rate above the budget.
	out, _, err := capBudgetRate(withDefault(0), json.RawMessage(`{"rate":1e300}`), ptr(std), one, true)
	if err != nil || string(out) != `{"rate":20}` {
		t.Fatalf("%s %v", out, err)
	}
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
