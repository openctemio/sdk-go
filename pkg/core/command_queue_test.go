package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/resource"
)

// queueClient is a platform with a pending list: a poll returns up to the
// limit, claim moves a command to acknowledged, release back to pending.
type queueClient struct {
	mu       sync.Mutex
	order    []string
	cmds     map[string]*Command
	state    map[string]string
	acks     []string
	released map[string]string
	results  map[string]string
	errs     map[string]string
	refusals map[string]*Refusal
	limits   []int
}

func newQueueClient(cmds ...*Command) *queueClient {
	c := &queueClient{cmds: map[string]*Command{}, state: map[string]string{}, released: map[string]string{}, results: map[string]string{}}
	for _, cmd := range cmds {
		c.order = append(c.order, cmd.ID)
		c.cmds[cmd.ID] = cmd
		c.state[cmd.ID] = "pending"
	}
	return c
}

func (c *queueClient) GetCommands(ctx context.Context) (*GetCommandsResponse, error) {
	return c.GetCommandsLimit(ctx, 1000)
}

func (c *queueClient) GetCommandsLimit(_ context.Context, limit int) (*GetCommandsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.limits = append(c.limits, limit)
	var out []*Command
	for _, id := range c.order {
		if c.state[id] == "pending" && len(out) < limit {
			out = append(out, c.cmds[id])
		}
	}
	return &GetCommandsResponse{Commands: out}, nil
}

func (c *queueClient) AcknowledgeCommand(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state[id] != "pending" {
		return fmt.Errorf("409: %s is %s", id, c.state[id])
	}
	c.state[id] = "acknowledged"
	c.acks = append(c.acks, id)
	return nil
}

func (c *queueClient) StartCommand(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state[id] != "acknowledged" {
		return fmt.Errorf("409: %s is %s", id, c.state[id])
	}
	c.state[id] = "running"
	return nil
}

func (c *queueClient) ReportCommandResult(_ context.Context, id string, r *CommandResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state[id] = r.Status
	c.results[id] = r.Status
	if c.errs == nil {
		c.errs = map[string]string{}
	}
	c.errs[id] = r.Error
	if c.refusals == nil {
		c.refusals = map[string]*Refusal{}
	}
	c.refusals[id] = r.Refusal
	return nil
}

func (c *queueClient) ReportCommandProgress(context.Context, string, int, string) error { return nil }

func (c *queueClient) ReleaseCommand(_ context.Context, id, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state[id] = "pending"
	c.released[id] = reason
	return nil
}

func (c *queueClient) snapshot() (acks []string, state map[string]string, released map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := map[string]string{}
	for k, v := range c.state {
		st[k] = v
	}
	rel := map[string]string{}
	for k, v := range c.released {
		rel[k] = v
	}
	return append([]string(nil), c.acks...), st, rel
}

func scanCmd(id, priority string, payload map[string]any) *Command {
	b, _ := json.Marshal(payload)
	return &Command{ID: id, Type: "scan", Priority: priority, Payload: b}
}

// ctxExecutor runs until its context ends or it is released.
type ctxExecutor struct {
	started  chan string
	release  chan struct{}
	mu       sync.Mutex
	runs     map[string]int
	running  atomic.Int32
	maxSeen  atomic.Int32
	duration func(id string) time.Duration
}

func newCtxExecutor() *ctxExecutor {
	return &ctxExecutor{started: make(chan string, 1000), release: make(chan struct{}), runs: map[string]int{}}
}

func (e *ctxExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	n := e.running.Add(1)
	defer e.running.Add(-1)
	for m := e.maxSeen.Load(); n > m && !e.maxSeen.CompareAndSwap(m, n); m = e.maxSeen.Load() {
	}
	e.mu.Lock()
	e.runs[cmd.ID]++
	e.mu.Unlock()
	e.started <- cmd.ID
	if e.duration != nil {
		select {
		case <-time.After(e.duration(cmd.ID)):
			return &CommandExecutionResult{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case <-e.release:
		return &CommandExecutionResult{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *ctxExecutor) runCounts() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]int{}
	for k, v := range e.runs {
		out[k] = v
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// One slot, a batch in platform order low, critical, normal (and a verify
// class): the verify command is claimed first, then critical.
func TestQueue_LocalPriorityOrder(t *testing.T) {
	c := newQueueClient(
		scanCmd("low", "low", map[string]any{"target": "a.example.com"}),
		scanCmd("crit", "critical", map[string]any{"target": "b.example.com"}),
		scanCmd("norm", "normal", map[string]any{"target": "c.example.com"}),
		scanCmd("verify", "low", map[string]any{"target": "d.example.com", "class": "verify"}),
	)
	resp, _ := c.GetCommands(context.Background())
	orderCommands(resp.Commands)
	var got []string
	for _, cmd := range resp.Commands {
		got = append(got, cmd.ID)
	}
	if fmt.Sprint(got) != "[verify crit norm low]" {
		t.Fatalf("order %v", got)
	}

	// Through the poller, against a client that returns the whole batch.
	e := newCtxExecutor()
	p := NewCommandPoller(&legacyBatch{c}, e, &CommandPollerConfig{MaxConcurrent: 1})
	p.pollAndExecute(context.Background())
	if id := <-e.started; id != "verify" {
		t.Fatalf("first run %s, want verify", id)
	}
	close(e.release)
	p.activeCmds.Wait()
}

// legacyBatch hides GetCommandsLimit: the poller gets every pending command.
type legacyBatch struct{ c *queueClient }

func (l *legacyBatch) GetCommands(ctx context.Context) (*GetCommandsResponse, error) {
	return l.c.GetCommandsLimit(ctx, 1000)
}
func (l *legacyBatch) AcknowledgeCommand(ctx context.Context, id string) error {
	return l.c.AcknowledgeCommand(ctx, id)
}
func (l *legacyBatch) StartCommand(ctx context.Context, id string) error {
	return l.c.StartCommand(ctx, id)
}
func (l *legacyBatch) ReportCommandResult(ctx context.Context, id string, r *CommandResult) error {
	return l.c.ReportCommandResult(ctx, id, r)
}
func (l *legacyBatch) ReportCommandProgress(context.Context, string, int, string) error { return nil }

var _ CommandClient = (*legacyBatch)(nil)

// At most per_host_concurrency held commands touch one host (default 1);
// a command over it is not claimed (stays pending on the platform).
func TestQueue_PerHostPoliteness(t *testing.T) {
	c := newQueueClient(
		scanCmd("a1", "normal", map[string]any{"target": "https://a.example.com/x"}),
		scanCmd("a2", "normal", map[string]any{"targets": []string{"a.example.com:443"}}),
		scanCmd("b1", "normal", map[string]any{"target": "b.example.com"}),
		scanCmd("c1", "normal", map[string]any{"target": "https://c.example.com", "limits": map[string]any{"per_host_concurrency": 2}}),
		scanCmd("c2", "normal", map[string]any{"target": "c.example.com", "limits": map[string]any{"per_host_concurrency": 2}}),
	)
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 10})
	p.pollAndExecute(context.Background())
	for range 4 {
		<-e.started
	}
	_, st, _ := c.snapshot()
	if st["a2"] != "pending" || st["a1"] != "running" || st["b1"] != "running" || st["c1"] != "running" || st["c2"] != "running" {
		t.Fatalf("states %v: want a2 left pending (a.example.com busy), c1+c2 running (limit 2)", st)
	}
	qs := p.QueueStats()
	if qs.Claimed != 4 || qs.Running != 4 || qs.QueuedLocal != 0 {
		t.Fatalf("queue %+v", qs)
	}
	close(e.release)
	p.activeCmds.Wait()
	// The host is free again: a2 is claimed on the next poll.
	p.pollAndExecute(context.Background())
	if id := <-e.started; id != "a2" {
		t.Fatalf("next run %s, want a2", id)
	}
	p.activeCmds.Wait()
}

func TestHostKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://App.Example.com:8443/login":     "app.example.com",
		"example.com":                            "example.com",
		"10.0.0.5:22":                            "10.0.0.5",
		"10.0.0.0/24":                            "10.0.0.0/24",
		"https://github.com/Acme/api.git":        "github.com/acme",
		"github.com/acme/web":                    "github.com/acme",
		"git@gitlab.com:team/repo.git":           "gitlab.com/team",
		"/srv/checkouts/repo":                    "/srv/checkouts/repo",
		"":                                       "",
		"https://github.com/acme":                "github.com",
		"https://scanme.example.org/path/to/one": "scanme.example.org/path",
	} {
		if got := HostKey(in); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// The platform cancels a running command through the heartbeat: its
// context is canceled, it is released ("canceled"), not reported.
func TestQueue_CancelFromHeartbeat(t *testing.T) {
	c := newQueueClient(scanCmd("x", "normal", map[string]any{"target": "x.example.com"}))
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2})
	d := NewDoorbell(nil)
	p.SetDoorbell(d)
	p.pollAndExecute(context.Background())
	<-e.started

	d.Handle(ParseHeartbeatHints([]byte(`{"pending_jobs":0,"actions":["cancel"],"cancel_command_ids":["x","not-held"]}`)))
	p.activeCmds.Wait()
	_, st, rel := c.snapshot()
	if rel["x"] != ReleaseReasonCanceled || st["x"] != "pending" {
		t.Fatalf("released %v states %v", rel, st)
	}
	if _, reported := c.results["x"]; reported {
		t.Fatal("a canceled command was also reported")
	}
	if p.ActiveJobs() != 0 || p.QueueStats().Claimed != 0 {
		t.Fatalf("slot or queue entry leaked: %d %+v", p.ActiveJobs(), p.QueueStats())
	}
}

// Stopping drains: running commands get the grace period, then are
// canceled and released ("shutdown"); none runs twice and nothing more is
// claimed.
func TestQueue_DrainReleasesUnfinished(t *testing.T) {
	c := newQueueClient(
		scanCmd("fast", "normal", map[string]any{"target": "f.example.com"}),
		scanCmd("slow", "normal", map[string]any{"target": "s.example.com"}),
		scanCmd("later", "normal", map[string]any{"target": "l.example.com"}),
	)
	e := newCtxExecutor()
	e.duration = func(id string) time.Duration {
		if id == "fast" {
			return 10 * time.Millisecond // finishes inside the grace
		}
		return time.Hour
	}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2, PollInterval: time.Hour, DrainGrace: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	<-e.started
	<-e.started
	waitFor(t, "fast to complete", func() bool { _, st, _ := c.snapshot(); return st["fast"] == "completed" })
	// "later" is claimed into fast's freed slot; drain only after that, or
	// the test races the poller and sees two claims.
	<-e.started
	cancel()
	<-done

	_, st, rel := c.snapshot()
	if rel["slow"] != ReleaseReasonShutdown || st["slow"] != "pending" {
		t.Fatalf("slow: released %v state %v", rel, st)
	}
	// "later" took fast's slot; drained with it, it is back on the platform.
	if st["later"] != "pending" {
		t.Fatalf("later: state %v released %v", st, rel)
	}
	// Nothing is claimed once draining began.
	acks, _, _ := c.snapshot()
	if len(acks) != 3 {
		t.Fatalf("claims %v", acks)
	}
	for id, n := range e.runCounts() {
		if n != 1 {
			t.Fatalf("%s ran %d times", id, n)
		}
	}
}

// A command claimed while the poller is already draining is released
// unstarted.
func TestQueue_ClaimedDuringDrainIsReleasedUnstarted(t *testing.T) {
	c := newQueueClient(scanCmd("x", "normal", map[string]any{"target": "x.example.com"}))
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 1})
	if !p.queue.admit("x", nil, 1, time.Now()) {
		t.Fatal("admit")
	}
	p.sem <- struct{}{}
	_ = c.AcknowledgeCommand(context.Background(), "x")
	p.draining.Store(true)
	p.activeCmds.Add(1)
	p.executeCommand(context.Background(), c.cmds["x"])
	_, st, rel := c.snapshot()
	if rel["x"] != ReleaseReasonDraining || st["x"] != "pending" || len(e.runCounts()) != 0 {
		t.Fatalf("state %v released %v runs %v", st, rel, e.runCounts())
	}
}

// Under load with random durations, a resource manager that allows 3 slots
// (3 cores, generic 1-core jobs) is never exceeded, the poll limit never
// asks for more than the free slots, and every command runs exactly once.
func TestQueue_NoOverClaimUnderLoad(t *testing.T) {
	const n = 60
	var cmds []*Command
	for i := range n {
		cmds = append(cmds, scanCmd(fmt.Sprintf("c%02d", i), "normal", map[string]any{"target": fmt.Sprintf("h%02d.example.com", i)}))
	}
	c := newQueueClient(cmds...)
	e := newCtxExecutor()
	e.duration = func(string) time.Duration { return time.Duration(rand.IntN(15)+1) * time.Millisecond }
	p := NewCommandPoller(c, e, &CommandPollerConfig{PollInterval: 5 * time.Millisecond})
	m := resource.NewManager(resource.ManagerConfig{Cap: 16, Prober: &resource.Prober{Root: t.TempDir(), NumCPU: func() int { return 3 }}})
	p.SetResourceManager(m)
	if p.MaxJobs() != 16 {
		t.Fatalf("MaxJobs %d, want the cap 16", p.MaxJobs())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	waitFor(t, "all commands", func() bool {
		_, st, _ := c.snapshot()
		for _, s := range st {
			if s != "completed" {
				return false
			}
		}
		return true
	})
	cancel()
	<-done
	if got := e.maxSeen.Load(); got > 3 {
		t.Fatalf("ran %d at once with 3 slots", got)
	}
	for id, k := range e.runCounts() {
		if k != 1 {
			t.Fatalf("%s ran %d times", id, k)
		}
	}
	if len(e.runCounts()) != n {
		t.Fatalf("ran %d of %d", len(e.runCounts()), n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.limits {
		if l > 3 || l < 1 {
			t.Fatalf("poll limit %d with 3 slots", l)
		}
	}
	if st := p.QueueStats(); st.Claimed != 0 {
		t.Fatalf("queue not empty after: %+v", st)
	}
}

func TestParseHeartbeatHints_CancelIDs(t *testing.T) {
	h := ParseHeartbeatHints([]byte(`{"cancel_command_ids":["a","","` + string(make([]byte, 0)) + `b"]}`))
	if fmt.Sprint(h.CancelCommandIDs) != "[a b]" {
		t.Fatalf("ids %v", h.CancelCommandIDs)
	}
}

// ReportStatus fills the heartbeat; the JSON names are the api's contract.
func TestReportStatus_JSON(t *testing.T) {
	c := newQueueClient(scanCmd("x", "normal", map[string]any{"target": "x.example.com"}))
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4})
	p.SetResourceManager(resource.NewManager(resource.ManagerConfig{Cap: 4, Tools: []string{"nuclei"}, Prober: &resource.Prober{Root: t.TempDir(), NumCPU: func() int { return 2 }}}))
	p.pollAndExecute(context.Background())
	<-e.started

	s := NewBaseSensor(&BaseSensorConfig{Name: "s"}, nil)
	s.SetLoadReporter(p)
	st := s.withCapabilities(context.Background(), &SensorStatus{Name: "s"})
	b, _ := json.Marshal(st)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	q, _ := got["queue"].(map[string]any)
	if q["claimed"] != float64(1) || q["running"] != float64(1) || q["queued_local"] != float64(0) {
		t.Fatalf("queue %v in %s", q, b)
	}
	if _, ok := q["oldest_age_seconds"]; !ok {
		t.Fatalf("oldest_age_seconds missing: %s", b)
	}
	if fmt.Sprint(got["running"]) != "[x]" {
		t.Fatalf("running %v", got["running"])
	}
	capa, _ := got["capacity"].(map[string]any)
	if capa["slots_total"] != float64(2) || capa["slots_free"] != float64(1) || capa["active_jobs"] != float64(1) {
		t.Fatalf("capacity %v", capa)
	}
	if _, ok := capa["per_tool"].(map[string]any)["nuclei"].(map[string]any)["est_mem_bytes"]; !ok {
		t.Fatalf("per_tool %v", capa["per_tool"])
	}
	res, _ := got["resources"].(map[string]any)
	for _, k := range []string{"cpu_cores", "cpu_used_pct", "mem_total_bytes", "mem_available_bytes", "load1", "disk_free_bytes"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("resources.%s missing: %s", k, b)
		}
	}
	if got["max_concurrent_jobs"] != float64(4) || got["active_jobs"] != float64(1) {
		t.Fatalf("cap/active: %s", b)
	}
	close(e.release)
	p.activeCmds.Wait()
}

// The heartbeat's max_concurrent_jobs is the operator's ceiling: with a
// resource manager and no cap, the manager's HardMax (64) is a safety bound,
// not a capacity, and is not reported; the platform goes by the slots.
// Live: a 4-core sensor reported 64 next to slots_total 4.
func TestReportStatus_CeilingNotHardMax(t *testing.T) {
	prober := &resource.Prober{Root: t.TempDir(), NumCPU: func() int { return 4 }}
	for _, tt := range []struct {
		name          string
		maxConcurrent int
		cap           int
		want          int
	}{
		{"no operator cap (sensorkit default)", 0, 0, 0},
		{"poller bound is the manager's HardMax", resource.DefaultHardMaxSlots, 0, 0},
		{"operator cap", 0, 3, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := resource.NewManager(resource.ManagerConfig{Cap: tt.cap, Prober: prober})
			maxC := tt.maxConcurrent
			if maxC == 0 {
				maxC = m.MaxSlots()
			}
			p := NewCommandPoller(newQueueClient(), newCtxExecutor(), &CommandPollerConfig{MaxConcurrent: maxC})
			p.SetResourceManager(m)
			s := NewBaseSensor(&BaseSensorConfig{Name: "s"}, nil)
			s.SetLoadReporter(p)
			st := s.withCapabilities(context.Background(), &SensorStatus{Name: "s"})
			if st.MaxConcurrentJobs != tt.want {
				t.Fatalf("max_concurrent_jobs = %d, want %d", st.MaxConcurrentJobs, tt.want)
			}
			if st.Capacity == nil || st.Capacity.SlotsTotal < 1 || st.Capacity.SlotsTotal > 4 {
				t.Fatalf("capacity = %+v, want 1..4 slots on 4 cores", st.Capacity)
			}
		})
	}
}
