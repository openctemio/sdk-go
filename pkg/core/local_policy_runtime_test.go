package core

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The poller refuses a job outside the local policy after claiming it and
// before any executor runs it, reports it failed with the rule, and the
// platform's own gate (which allows everything here) cannot let it through.
func TestCommandPoller_LocalPolicyRefuses(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	c := newQueueClient(
		scanCmd("outside", "normal", map[string]any{"scanner": "nuclei", "target": "192.0.2.1"}),
		scanCmd("rebind", "normal", map[string]any{"scanner": "nuclei", "target": "rebind.corp.example.com"}),
		scanCmd("callbacks", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.11", "config": map[string]any{"allow_interactsh": true}}),
		// A host of its own: per-host politeness would hold it back otherwise.
		scanCmd("ok", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.10"}),
	)
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 8})
	p.SetLocalPolicy(lp)
	p.SetCommandGate(func(*Command) error { return nil }) // a platform policy that allows everything
	p.pollAndExecute(context.Background())
	select {
	case id := <-e.started:
		if id != "ok" {
			t.Fatalf("ran %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the allowed command did not run")
	}
	close(e.release)
	p.activeCmds.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	for id, rule := range map[string]string{"outside": "targets.allow", "rebind": "targets.deny", "callbacks": "allow_interactsh"} {
		if c.results[id] != "failed" || !strings.HasPrefix(c.errs[id], "refused by local policy: "+rule+": ") {
			t.Errorf("%s: result %q, error %q", id, c.results[id], c.errs[id])
		}
		// The structured refusal (research/25 D8) goes along.
		if r := c.refusals[id]; r == nil || r.Layer != RefusalLayerLocal || r.Rule != rule {
			t.Errorf("%s: refusal %+v, want local/%s", id, r, rule)
		}
	}
	if c.results["ok"] != "completed" || c.refusals["ok"] != nil {
		t.Errorf("ok: %q, refusal %+v", c.results["ok"], c.refusals["ok"])
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.runs) != 1 {
		t.Fatalf("refused commands reached the executor: %v", e.runs)
	}
}

// The kill switch: nothing is claimed while it is engaged, and running jobs
// are stopped and reported failed with the reason.
func TestCommandPoller_KillSwitch(t *testing.T) {
	dir := t.TempDir()
	stop := filepath.Join(dir, "STOP")
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(dir, "none.yaml"),
		LookupEnv: env(map[string]string{EnvKillSwitchFile: stop})})
	if err != nil {
		t.Fatal(err)
	}
	c := newQueueClient(scanCmd("running", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.9"}))
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4})
	p.SetLocalPolicy(lp)
	p.pollAndExecute(context.Background())
	select {
	case <-e.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the command did not start")
	}

	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !p.checkKillSwitch() || !p.LocalKillSwitch() {
		t.Fatal("kill switch not seen")
	}
	p.activeCmds.Wait()
	c.mu.Lock()
	if c.results["running"] != "failed" || !strings.HasPrefix(c.errs["running"], "refused by local policy: kill_switch") {
		t.Fatalf("running command: %q %q", c.results["running"], c.errs["running"])
	}
	if r := c.refusals["running"]; r == nil || r.Rule != "kill_switch" {
		t.Fatalf("running command refusal: %+v", r)
	}
	c.cmds["later"] = scanCmd("later", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.9"})
	c.order = append(c.order, "later")
	c.state["later"] = "pending"
	polls := len(c.limits)
	c.mu.Unlock()

	p.pollAndExecute(context.Background())
	c.mu.Lock()
	if len(c.limits) != polls || c.state["later"] != "pending" {
		t.Fatalf("polled or claimed under the kill switch: polls %d -> %d, later %q", polls, len(c.limits), c.state["later"])
	}
	c.mu.Unlock()

	// Released: polling resumes.
	if err := os.Remove(stop); err != nil {
		t.Fatal(err)
	}
	p.pollAndExecute(context.Background())
	select {
	case id := <-e.started:
		if id != "later" {
			t.Fatalf("ran %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("polling did not resume")
	}
	close(e.release)
	p.activeCmds.Wait()
}

// limitScanner records what the executor hands a scanner.
type limitScanner struct {
	mu       sync.Mutex
	calls    int
	opts     *ScanOptions
	deadline time.Time
}

func (s *limitScanner) Name() string           { return "nuclei" }
func (s *limitScanner) Version() string        { return "1" }
func (s *limitScanner) Capabilities() []string { return nil }
func (s *limitScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "1", nil
}
func (s *limitScanner) Scan(ctx context.Context, _ string, opts *ScanOptions) (*ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.opts = opts
	s.deadline, _ = ctx.Deadline()
	return &ScanResult{ScannerName: "nuclei"}, nil
}

// Nothing a command carries loosens the local policy at the executor
// either (a second line behind admission): rate and run time are capped,
// callbacks, custom templates and out-of-policy targets are refused before
// the scanner runs.
func TestDefaultCommandExecutor_LocalPolicyCannotBeLoosened(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	newExec := func() (*DefaultCommandExecutor, *limitScanner) {
		sc := &limitScanner{}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(sc)
		e.SetScanTargetPolicy(&ScanTargetPolicy{AllowPrivate: true, LookupIP: policyDNS})
		e.SetLocalPolicy(lp)
		return e, sc
	}
	ctx := context.Background()

	e, sc := newExec()
	start := time.Now()
	_, err := e.Execute(ctx, scanCommand(t, ScanCommandPayload{Scanner: "nuclei", Target: "203.0.113.9",
		TimeoutSeconds: 7 * 24 * 3600, Config: map[string]any{"rate_limit": float64(100000)}}))
	if err != nil {
		t.Fatal(err)
	}
	if sc.opts.RateLimit != 50 {
		t.Errorf("rate %d, want the policy's 50", sc.opts.RateLimit)
	}
	if sc.deadline.IsZero() || sc.deadline.After(start.Add(time.Hour+time.Minute)) {
		t.Errorf("deadline %v, want at most an hour (rate.max_job_seconds)", sc.deadline)
	}

	for name, payload := range map[string]ScanCommandPayload{
		"callbacks": {Scanner: "nuclei", Target: "203.0.113.9", Config: map[string]any{"allow_interactsh": true}},
		"templates": {Scanner: "nuclei", Target: "203.0.113.9", CustomTemplates: []EmbeddedTemplate{{ID: "t", Name: "t.yaml",
			TemplateType: "nuclei", Content: base64.StdEncoding.EncodeToString([]byte("id: t"))}}},
		"outside range":  {Scanner: "nuclei", Target: "192.0.2.1"},
		"denied range":   {Scanner: "nuclei", Targets: []string{"203.0.113.9", "10.20.5.1"}},
		"denied name":    {Scanner: "nuclei", Target: "https://secret.corp.example.com/"},
		"rebinding name": {Scanner: "nuclei", Target: "rebind.corp.example.com"},
		"port":           {Scanner: "nuclei", Target: "https://203.0.113.9:9443/"},
		"cidr too broad": {Scanner: "nuclei", Target: "203.0.0.0/16"},
	} {
		e, sc := newExec()
		_, err := e.Execute(ctx, scanCommand(t, payload))
		if err == nil || !strings.Contains(err.Error(), "refused by local policy") {
			t.Errorf("%s: err %v", name, err)
		}
		if sc.calls != 0 {
			t.Errorf("%s: the scanner ran", name)
		}
	}

	// Without a policy only MaxScanTimeout caps the run time.
	sc2 := &limitScanner{}
	e2 := NewDefaultCommandExecutor(nil)
	e2.AddScanner(sc2)
	start = time.Now()
	if _, err := e2.Execute(ctx, scanCommand(t, ScanCommandPayload{Scanner: "nuclei", Target: "203.0.113.9", TimeoutSeconds: 30 * 24 * 3600})); err != nil {
		t.Fatal(err)
	}
	if sc2.deadline.After(start.Add(MaxScanTimeout + time.Minute)) {
		t.Errorf("deadline %v beyond MaxScanTimeout", sc2.deadline)
	}
}

// Heartbeats and the manifest report the policy (digest and summary); the
// manifest leaves out the live kill switch, the heartbeat carries it and
// says "paused by local policy".
func TestBaseSensor_ReportsLocalPolicy(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{}
	s := newManifestSensor(t, p)
	stop := filepath.Join(t.TempDir(), "STOP")
	lp := mustPolicy(t, fullPolicy)
	lp.killSwitchFiles = []string{stop}
	s.SetLocalPolicy(lp)

	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	if len(p.puts) != 1 || p.puts[0].LocalPolicy == nil || p.puts[0].LocalPolicy.Digest != lp.Digest() ||
		p.puts[0].LocalPolicy.Summary == nil || p.puts[0].LocalPolicy.State != LocalPolicyStateEnforced {
		t.Fatalf("manifest local policy %+v", p.puts)
	}
	beat := p.statuses[0]
	if beat.LocalPolicy == nil || beat.LocalPolicy.KillSwitch || beat.Message == LocalPolicyPausedMessage {
		t.Fatalf("heartbeat %+v", beat.LocalPolicy)
	}
	p.mu.Unlock()

	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.sendHeartbeat(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	beat = p.statuses[len(p.statuses)-1]
	if !beat.LocalPolicy.KillSwitch || beat.Message != LocalPolicyPausedMessage {
		t.Fatalf("kill switch not reported: %+v %q", beat.LocalPolicy, beat.Message)
	}
	if len(p.puts) != 1 {
		t.Fatalf("the kill switch re-registered the manifest (%d puts)", len(p.puts))
	}
}

// A sensor without a policy reports local_policy "absent" (owner decision
// Q3 (a)).
func TestBaseSensor_ReportsAbsentPolicy(t *testing.T) {
	p := &manifestPusher{}
	s := newManifestSensor(t, p)
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"), LookupEnv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	s.SetLocalPolicy(lp)
	if _, err := s.FirstHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r := p.statuses[0].LocalPolicy; r == nil || r.State != LocalPolicyStateAbsent || r.Digest != "" || len(r.Warnings) == 0 {
		t.Fatalf("absent report %+v", r)
	}
	if r := p.puts[0].LocalPolicy; r == nil || r.State != LocalPolicyStateAbsent {
		t.Fatalf("manifest %+v", r)
	}
}
