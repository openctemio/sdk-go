package toolhost

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

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

// SECURITY: a tool that runs without network confinement gets no canary.
// There is no way out the runtime shares with the tool there: a request of
// the runtime's own would leave by another route than the tool's (past a
// proxy the operator routes the tool through, by a name it resolved
// itself) and could slow nothing. So nothing but the tool contacts the
// target, a target that answers nothing but 429 cannot have the tool
// stopped, and the outcome says the pacing is limited.
func TestUnconfinedToolGetsNoCanaryAndIsNotStopped(t *testing.T) {
	quickPacing(t)
	var canary, other atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == useragent.String() {
			canary.Add(1)
		} else {
			other.Add(1)
		}
		w.Header().Set("Retry-After", "300")
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
	task := tool.Task{ID: "unconfined-1", Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: srv.URL + "/app"}}}
	out, err := h.RunBuiltin(context.Background(), dialTool, task, RunOptions{HostBudget: &b})
	if err != nil {
		t.Fatal(err)
	}
	// A canary sends its first request when the task starts: had there
	// been one, the target would have seen it.
	if out.Err != nil || out.Status != tool.StatusOK {
		t.Fatalf("status %s, error %+v (stderr %s)", out.Status, out.Err, out.Stderr)
	}
	if canary.Load() != 0 {
		t.Fatalf("%d canary request(s) left the sensor without a forwarder", canary.Load())
	}
	if other.Load() == 0 {
		t.Fatal("the tool never contacted its target")
	}
	s := out.TargetRate
	if s == nil || s.Budget == nil || s.Budget.RPS != 20 || s.Budget.Inflight != 8 || s.Budget.WonBy.RPS != adapt.LimitSensorLevel {
		t.Fatalf("target rate %+v", s)
	}
	if s.Limited != adapt.PacingLimitedNoForwarder || s.Canary != nil || s.CircuitOpens != 0 || len(s.Gaps) != 0 {
		t.Fatalf("target rate %+v", s)
	}
	var limitedLine, budgetLine bool
	for _, l := range out.Logs {
		if l.Fields["pacing_limited"] == adapt.PacingLimitedNoForwarder {
			limitedLine = true
		}
		if l.Fields["host_budget_level"] == "standard" && l.Fields["host_budget_rps_won_by"] == adapt.LimitSensorLevel {
			budgetLine = true
		}
		// The log lines carry counts and host names, nothing the host sent.
		if strings.Contains(l.Msg, "/app") {
			t.Fatalf("a log line carries the target's path: %s", l.Msg)
		}
	}
	if !limitedLine || !budgetLine {
		t.Fatalf("log lines: limited %t budget %t in %+v", limitedLine, budgetLine, out.Logs)
	}
	if got := Pacing(); got.Limited == 0 {
		t.Fatalf("pacing totals %+v", got)
	}
}

// A confined task's canary travels the forwarder's own dial path, sends
// the canary's fixed request (nothing of the job's identification: no
// header, no User-Agent of the rotation, no query marker), and the names
// of one address get one canary between them.
func TestConfinedCanaryIsFixedAndOnePerAddress(t *testing.T) {
	quickPacing(t)
	type seen struct {
		host, ua, uri string
		headers       int
	}
	var mu sync.Mutex
	var reqs []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, seen{host: r.Host, ua: r.Header.Get("User-Agent"), uri: r.RequestURI, headers: len(r.Header)})
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	stubLookup(t, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	m := tool.Manifest{Name: "scanner", Tier: tool.T1, Permissions: tool.Permissions{Network: tool.NetTargets}}
	confined := statusBackend{st: executor.Status{NetworkEnforced: true}}
	h := &Host{Backend: confined}
	task := tool.Task{
		Targets: []tool.Target{
			{Ref: "a", Value: "http://a.example.com:" + port + "/login?next=/admin"},
			{Ref: "b", Value: "http://b.example.com:" + port + "/"},
			{Ref: "c", Value: "http://A.EXAMPLE.COM.:" + port + "/other"},
		},
		Identity: &tool.Identity{UserAgent: "job-agent/1", Headers: map[string]string{"X-Scan-Id": "job-1"},
			Query: &core.HTTPQuery{Name: "scan", Value: "job-1"}, UserAgents: []string{"rotated/1", "rotated/2"}, UserAgentKey: "k"},
	}
	p := &prepared{m: m, task: task, targetRate: 160, budget: ptr(adapt.DefaultBudget())}
	eg, err := h.startEgress(context.Background(), confined, p)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.stop()
	c := h.startCanary(context.Background(), p, eg)
	if c == nil {
		t.Fatal("a confined task with a budget and URL targets got no canary")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(reqs)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d canary request(s) arrived", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.end()
	mu.Lock()
	defer mu.Unlock()
	hosts := map[string]bool{}
	for _, r := range reqs {
		hosts[r.host] = true
		if r.ua != useragent.String() || r.uri != "/" || r.headers != 1 {
			t.Fatalf("canary request %+v: want GET / with the sensor's own User-Agent and no other header", r)
		}
	}
	// a.example.com, b.example.com and a second spelling of the first are
	// one address: one canary.
	if len(hosts) != 1 {
		t.Fatalf("canary requests went to %v: want one host for one address", hosts)
	}
	s := eg.fw.TargetRate().Summary()
	if s.Canary == nil || s.Canary.Hosts != 1 || s.Canary.Unwatched != 1 {
		t.Fatalf("canary %+v", s.Canary)
	}
	for _, r := range eg.fw.Refusals() {
		t.Fatalf("a canary connection was refused: %+v", r)
	}
	// Without a forwarder there is no canary, whatever the task.
	if got := h.startCanary(context.Background(), p, nil); got != nil {
		t.Fatal("a canary started without a forwarder")
	}
}

// An unconfined run states the budget its flags were derived from, the
// limit that set it, and that nothing else enforced it.
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
	if s == nil || s.Budget == nil || s.Budget.Level != "gentle" || s.Budget.WonBy.RPS != adapt.LimitJob || s.Backoffs != 0 || s.CircuitOpens != 0 || len(s.Gaps) != 0 ||
		s.Limited != adapt.PacingLimitedNoForwarder {
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
	if b := budgetOf(vendor, tool.Task{}, RunOptions{HostBudget: ptr(adapt.DefaultBudget())}); b != nil {
		t.Fatalf("a vendor tool got a budget: %+v", b)
	}
	if b := budgetOf(m, tool.Task{}, RunOptions{HostBudget: &adapt.HostBudget{}}); b != nil {
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
			var b *adapt.HostBudget
			if tc.budget != nil {
				b = ptr(*tc.budget)
			}
			out, line, err := capBudgetRate(m, json.RawMessage(tc.cfg), b, tc.targets, tc.enforced)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			_ = json.Unmarshal(out, &got)
			if got["rate"] != tc.want || (line != nil) != tc.changed {
				t.Fatalf("rate %v (line %+v), want %v", got["rate"], line, tc.want)
			}
			// A rate the task asked for above the budget is recorded with
			// what was asked and what applies; an unset rate is not a clamp.
			var asked map[string]float64
			_ = json.Unmarshal([]byte(tc.cfg), &asked)
			wantClamp := b != nil && tc.changed && asked["rate"] > 0
			if b != nil && (len(b.Clamped) == 1) != wantClamp {
				t.Fatalf("clamped %+v", b.Clamped)
			}
			if wantClamp {
				c := b.Clamped[0]
				if c.Key != "rate" || c.Asked != int(asked["rate"]) || float64(c.To) != tc.want || c.By != adapt.LimitHostBudget {
					t.Fatalf("clamp %+v", c)
				}
			}
		})
	}
	// A tool without a rate key is left alone.
	if out, line, _ := capBudgetRate(tool.Manifest{Name: "x"}, json.RawMessage(`{"rate":500}`), &std, one, true); string(out) != `{"rate":500}` || line != nil {
		t.Fatalf("a tool without a rate key was changed: %s", out)
	}
	// The caller's budget is never written to: the task works on a copy.
	mine := adapt.DefaultBudget()
	got := budgetOf(m, tool.Task{}, RunOptions{HostBudget: &mine})
	got.Clamp("rate", 500, 20)
	if len(mine.Clamped) != 0 {
		t.Fatalf("the caller's budget was changed: %+v", mine.Clamped)
	}
}
