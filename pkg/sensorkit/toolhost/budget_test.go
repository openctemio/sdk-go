package toolhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// hammerTool requests its first target over and over until it is canceled
// (compiled in; see TestMain): a scanner that would never slow down by
// itself. It emits one finding for the first answer it gets.
var hammerTool = tool.New(tool.Manifest{
	Name: "hammer-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	tg := task.Targets[0]
	emitted := false
	for ctx.Err() == nil {
		resp, err := c.Get(tg.Value)
		if err == nil {
			_ = resp.Body.Close()
			if !emitted {
				emitted = true
				if err := ctx.Emit().Finding(tg, ctis.Finding{Type: "misconfiguration", RuleID: "seen", Title: "answered " + tg.Ref, Severity: "info"}); err != nil {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	return ctx.Err()
})

// quickPacing shortens the controller's windows and the canary's intervals
// for a test and restores them after.
func quickPacing(t *testing.T) {
	t.Helper()
	oldR, oldC := adapt.TargetRate, adapt.CanaryPace
	adapt.TargetRate.Window = 100 * time.Millisecond
	adapt.TargetRate.ThrottleSpacing = 50 * time.Millisecond
	adapt.CanaryPace.Interval, adapt.CanaryPace.FailInterval = 100*time.Millisecond, 60*time.Millisecond
	t.Cleanup(func() { adapt.TargetRate, adapt.CanaryPace = oldR, oldC })
}

// A tool that runs without network confinement cannot be paced from
// outside. When its only host answers nothing but 429 to the canary, the
// tool is stopped; what it delivered before is kept (the run is partial),
// the target is unfinished and the host is a throttled gap with counts.
func TestUnconfinedToolIsStoppedWhenItsHostThrottles(t *testing.T) {
	quickPacing(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= 3 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	h := testHost(t)
	off, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	h.Backend = off
	b := adapt.DefaultBudget()
	task := tool.Task{ID: "throttle-1", Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: srv.URL + "/app"}}}
	start := time.Now()
	out, err := h.RunBuiltin(context.Background(), hammerTool, task, RunOptions{HostBudget: &b})
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 20*time.Second {
		t.Fatalf("the tool ran %v: it was not stopped", el)
	}
	if out.Status != tool.StatusPartial || out.Err == nil || out.Err.Class != tool.RateLimited {
		t.Fatalf("status %s, error %+v (stderr %s)", out.Status, out.Err, out.Stderr)
	}
	// Nothing the tool obtained is dropped.
	if out.Report == nil || len(out.Report.Findings) != 1 {
		t.Fatalf("the finding delivered before the stop was lost: %+v", out.Report)
	}
	if len(out.Unfinished) != 1 || out.Unfinished[0] != task.Targets[0].Value {
		t.Fatalf("unfinished %v", out.Unfinished)
	}
	s := out.TargetRate
	if s == nil || s.Budget == nil || s.Budget.RPS != 20 || s.Budget.Inflight != 8 || s.Budget.Source != adapt.BudgetFromSensor {
		t.Fatalf("target rate %+v", s)
	}
	if s.Backoffs == 0 || s.CircuitOpens == 0 || len(s.Gaps) != 1 || s.Gaps[0].Reason != adapt.GapThrottled || !strings.Contains(s.Gaps[0].Detail, "429=") {
		t.Fatalf("target rate %+v", s)
	}
	if s.Canary == nil || s.Canary.Hosts != 1 || s.Canary.Pushback < adapt.TargetRate.ThrottleRun {
		t.Fatalf("canary %+v", s.Canary)
	}
	var stopLine, budgetLine bool
	for _, l := range out.Logs {
		if l.Fields["host_budget"] == "throttle_stop" {
			stopLine = true
		}
		if l.Fields["host_budget_level"] == "standard" && l.Fields["circuit_opens"] != nil {
			budgetLine = true
		}
		// The log lines carry counts and host names, nothing the host sent.
		if strings.Contains(l.Msg, "/app") {
			t.Fatalf("a log line carries the target's path: %s", l.Msg)
		}
	}
	if !stopLine || !budgetLine {
		t.Fatalf("log lines: stop %t budget %t in %+v", stopLine, budgetLine, out.Logs)
	}
}

// A healthy host: the canary changes nothing about the run, and the
// outcome states the budget with zero back-offs.
func TestUnconfinedToolOnAHealthyHostRunsToItsEnd(t *testing.T) {
	quickPacing(t)
	srv, hits := recorder(t)
	h := testHost(t)
	off, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	h.Backend = off
	b := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	task := tool.Task{ID: "healthy-1", Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: srv.URL}}}
	out, err := h.RunBuiltin(context.Background(), dialTool, task, RunOptions{HostBudget: &b})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err != nil || out.Status != tool.StatusOK {
		t.Fatalf("status %s, error %+v", out.Status, out.Err)
	}
	if hits.Load() == 0 {
		t.Fatal("the target was never contacted")
	}
	s := out.TargetRate
	if s == nil || s.Budget == nil || s.Budget.Level != "gentle" || s.Budget.Source != adapt.BudgetFromJob || s.Backoffs != 0 || s.CircuitOpens != 0 || len(s.Gaps) != 0 {
		t.Fatalf("target rate %+v", s)
	}
}

// A confined task's forwarder holds each host to the budget: the host's
// rate ceiling is the budget's (not the job's rate over all its hosts) and
// its connections in flight are bounded.
func TestBudgetReachesTheForwarder(t *testing.T) {
	m := tool.Manifest{Name: "scanner", Tier: tool.T1, Permissions: tool.Permissions{Network: tool.NetTargets}}
	targets := []tool.Target{{Ref: "a", Value: "https://192.0.2.10/"}, {Ref: "b", Value: "https://192.0.2.11/"}}
	confined := statusBackend{st: executor.Status{NetworkEnforced: true}}
	cases := []struct {
		name      string
		budget    *adapt.HostBudget
		jobRate   float64
		rate      float64
		conns     int
		hasBudget bool
	}{
		{"no budget: the job's rate, as before", nil, 160, 160, 0, false},
		{"Standard under a job rate of 160", ptr(adapt.DefaultBudget()), 160, 20, 8, true},
		{"a job rate below the budget stays the ceiling", ptr(adapt.DefaultBudget()), 7, 7, 8, true},
		{"signed Gentle", ptr(adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})), 160, 5, 2, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{Backend: confined}
			p := &prepared{m: m, task: tool.Task{Targets: targets}, targetRate: tc.jobRate, budget: tc.budget}
			eg, err := h.startEgress(context.Background(), confined, p)
			if err != nil {
				t.Fatal(err)
			}
			defer eg.stop()
			rate, conns := eg.fw.PerHostLimits()
			if rate != tc.rate || conns != tc.conns {
				t.Fatalf("per host %v/s and %d connections, want %v and %d", rate, conns, tc.rate, tc.conns)
			}
			if got := eg.fw.TargetRate().Summary().Budget; (got != nil) != tc.hasBudget {
				t.Fatalf("summary budget %+v", got)
			}
		})
	}
	// A tool that does not connect to its targets has no budget.
	vendor := tool.Manifest{Name: "lookup", Permissions: tool.Permissions{Network: tool.NetVendor}}
	if b := budgetOf(vendor, RunOptions{HostBudget: ptr(adapt.DefaultBudget())}); b != nil {
		t.Fatalf("a vendor tool got a budget: %+v", b)
	}
	if b := budgetOf(m, RunOptions{HostBudget: &adapt.HostBudget{}}); b != nil {
		t.Fatalf("a zero budget was read: %+v", b)
	}
}

// The tool's rate key is lowered to the budget of the task's hosts (and set
// when the task left it unset): a manifest-only tool runs under the budget
// through its own flag. It is never raised.
func TestCapBudgetRate(t *testing.T) {
	m := tool.Manifest{Name: "prober", Safety: &tool.Safety{RateParam: "rate"}, Permissions: tool.Permissions{Network: tool.NetTargets}}
	one := []tool.Target{{Ref: "a", Value: "https://a.example.com/x"}, {Ref: "b", Value: "http://a.example.com:8080/y"}}
	three := []tool.Target{{Ref: "a", Value: "https://a.example.com/"}, {Ref: "b", Value: "https://b.example.com/"}, {Ref: "c", Value: "https://c.example.com/"}}
	std := adapt.DefaultBudget()
	cases := []struct {
		name     string
		cfg      string
		budget   *adapt.HostBudget
		targets  []tool.Target
		enforced bool
		want     float64
		changed  bool
	}{
		{"no budget: unchanged", `{"rate":500}`, nil, one, true, 500, false},
		{"one host (two targets): the budget", `{"rate":500}`, &std, one, true, 20, true},
		{"three hosts, enforced: three budgets", `{"rate":500}`, &std, three, true, 60, true},
		{"three hosts, not enforced: one budget", `{"rate":500}`, &std, three, false, 20, true},
		{"a lower rate stays", `{"rate":5}`, &std, three, true, 5, false},
		{"unset: set to the budget", `{}`, &std, one, true, 20, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, line, err := capBudgetRate(m, json.RawMessage(tc.cfg), tc.budget, tc.targets, tc.enforced)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			_ = json.Unmarshal(out, &got)
			if got["rate"] != tc.want || (line != nil) != tc.changed {
				t.Fatalf("rate %v (line %+v), want %v", got["rate"], line, tc.want)
			}
		})
	}
	// A tool without a rate key is left alone.
	if out, line, _ := capBudgetRate(tool.Manifest{Name: "x"}, json.RawMessage(`{"rate":500}`), &std, one, true); string(out) != `{"rate":500}` || line != nil {
		t.Fatalf("a tool without a rate key was changed: %s", out)
	}
}
