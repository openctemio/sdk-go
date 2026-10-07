package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// partialPolicy allows example.com and its subdomains and one test range,
// with half of the range denied.
const partialPolicy = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["example.com", "*.example.com", "203.0.113.0/24"]
  deny: ["203.0.113.128/25"]
tools:
  allow: [nuclei]
checks:
  allow: [scan, retest]
`

// partialDNS: example.com resolves; api.example.com does not (NXDOMAIN).
var partialDNS = fakeDNS(map[string][]string{
	"example.com":     {"203.0.113.5"},
	"www.example.com": {"203.0.113.6"},
})

func partialLP(t *testing.T, lookup func(context.Context, string) ([]net.IP, error)) *LocalPolicy {
	t.Helper()
	lp, err := ParseLocalPolicy([]byte(partialPolicy), LocalPolicyOptions{LookupEnv: env(nil), LookupIP: lookup})
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

func payloadTargets(t *testing.T, cmd *Command) []string {
	t.Helper()
	var p struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p.Targets
}

func TestAdmitCommandTargets(t *testing.T) {
	lp := partialLP(t, partialDNS)
	ctx := context.Background()

	t.Run("an unresolvable target is removed and the rest runs", func(t *testing.T) {
		// The live case: one of two targets is NXDOMAIN.
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"example.com", "api.example.com"}, "config": map[string]any{"severity": "high"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if !adm.Partial() || adm.Total != 2 || len(adm.Refused) != 1 {
			t.Fatalf("admission %+v", adm)
		}
		r := adm.Refused[0]
		if r.Target != "api.example.com" || r.Reason != RefusedTargetUnresolvable || r.Rule != "targets" || !strings.Contains(r.Detail, "cannot resolve") {
			t.Fatalf("refused %+v", r)
		}
		if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"example.com"}) {
			t.Fatalf("payload targets %v: a refused target must not reach the executor", got)
		}
		// The rest of the payload is kept.
		var p map[string]any
		_ = json.Unmarshal(cmd.Payload, &p)
		if p["scanner"] != "nuclei" || p["config"].(map[string]any)["severity"] != "high" {
			t.Fatalf("payload %s", cmd.Payload)
		}
	})

	t.Run("every target refused fails the command with the list", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"api.example.com", "*.example.com"}})
		before := string(cmd.Payload)
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if !isRule(err, "targets") {
			t.Fatalf("err %v", err)
		}
		for _, want := range []string{`"api.example.com" (unresolvable)`, `"*.example.com" (wildcard_pattern)`, "2 target(s) refused"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		}
		if len(adm.Refused) != 2 || string(cmd.Payload) != before {
			t.Fatalf("admission %+v, payload %s", adm, cmd.Payload)
		}
	})

	t.Run("a wildcard pattern is refused as such", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"*.example.com", "203.0.113.9", "https://*.example.com/x"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if len(adm.Refused) != 2 || adm.Refused[0].Reason != RefusedTargetWildcard || adm.Refused[1].Reason != RefusedTargetWildcard {
			t.Fatalf("refused %+v", adm.Refused)
		}
		if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"203.0.113.9"}) {
			t.Fatalf("payload targets %v", got)
		}
	})

	t.Run("a policy-denied range is removed", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.128/26", "203.0.113.0/26", "203.0.113.200", "198.51.100.0/24"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"203.0.113.128/26": "targets.deny", "203.0.113.200": "targets.deny", "198.51.100.0/24": "targets.allow"}
		if len(adm.Refused) != len(want) {
			t.Fatalf("refused %+v", adm.Refused)
		}
		for _, r := range adm.Refused {
			if r.Reason != RefusedTargetDenied || want[r.Target] != r.Rule {
				t.Errorf("refused %+v", r)
			}
		}
		if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"203.0.113.0/26"}) {
			t.Fatalf("payload targets %v", got)
		}
	})

	t.Run("the single job target refused refuses the job", func(t *testing.T) {
		// "target" is the whole job (a single-target scanner): nothing is left.
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "target": "api.example.com", "targets": []string{"api.example.com", "example.com"}})
		if _, err := lp.AdmitCommandTargets(ctx, cmd); !isRule(err, "targets") {
			t.Fatalf("err %v", err)
		}
		// Admitted single target, a refused list entry: runs, list cleaned.
		cmd = cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "target": "example.com", "targets": []string{"example.com", "api.example.com"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil || len(adm.Refused) != 1 {
			t.Fatalf("admission %+v, err %v", adm, err)
		}
		if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"example.com"}) {
			t.Fatalf("payload targets %v", got)
		}
	})

	t.Run("other command types still refuse the whole job", func(t *testing.T) {
		// A retest names its targets in items too: it is not rewritten.
		cmd := cmdWith("r", "retest", map[string]any{"scanner": "nuclei", "targets": []string{"example.com", "api.example.com"},
			"items": []map[string]any{{"ref": "f", "target": "api.example.com", "kind": "finding"}}})
		before := string(cmd.Payload)
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if !isRule(err, "targets") || len(adm.Refused) != 1 || string(cmd.Payload) != before {
			t.Fatalf("admission %+v, err %v", adm, err)
		}
	})

	t.Run("job-wide rules refuse before any target", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "naabu", "targets": []string{"example.com"}})
		if _, err := lp.AdmitCommandTargets(ctx, cmd); !isRule(err, "tools.allow") {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("no policy: nothing removed", func(t *testing.T) {
		var none *LocalPolicy
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"api.example.com"}})
		adm, err := none.AdmitCommandTargets(ctx, cmd)
		if err != nil || adm.Partial() {
			t.Fatalf("admission %+v, err %v", adm, err)
		}
	})
}

// recordSink is a CommandLogSink that records lines and finishes in the
// order they happen, beside the results the client records.
type recordSink struct {
	mu     sync.Mutex
	lines  map[string][]string
	fields map[string][]map[string]any
	events *[]string
	direct map[string]bool
}

func (s *recordSink) CommandLog(_ context.Context, id, level, msg string, fields map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lines == nil {
		s.lines, s.fields = map[string][]string{}, map[string][]map[string]any{}
	}
	s.lines[id] = append(s.lines[id], level+": "+msg)
	s.fields[id] = append(s.fields[id], fields)
}

func (s *recordSink) FinishCommandLog(_ context.Context, id string, direct bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.events = append(*s.events, "logs:"+id)
	if s.direct == nil {
		s.direct = map[string]bool{}
	}
	s.direct[id] = direct
}

// orderedClient records when each result is reported.
type orderedClient struct {
	*queueClient
	mu     *sync.Mutex
	events *[]string
}

func (c *orderedClient) ReportCommandResult(ctx context.Context, id string, r *CommandResult) error {
	c.mu.Lock()
	*c.events = append(*c.events, "result:"+id)
	c.mu.Unlock()
	return c.queueClient.ReportCommandResult(ctx, id, r)
}

// payloadExecutor records the payload each command reached it with.
type payloadExecutor struct {
	mu       sync.Mutex
	payloads map[string]json.RawMessage
}

func (e *payloadExecutor) Execute(_ context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.payloads == nil {
		e.payloads = map[string]json.RawMessage{}
	}
	e.payloads[cmd.ID] = cmd.Payload
	return &CommandExecutionResult{FindingsCount: 1, Metadata: map[string]any{"scanner_name": "nuclei"}}, nil
}

// The poller runs a job on its admitted targets and completes it as
// partial with the refused targets in the result; a job with every target
// refused fails with the list and never reaches the executor. Both leave
// the policy decision in the command's log, sent ahead of the result.
func TestCommandPoller_PartialAdmission(t *testing.T) {
	lp := partialLP(t, partialDNS)
	qc := newQueueClient(
		scanCmd("mixed", "normal", map[string]any{"scanner": "nuclei", "targets": []string{"example.com", "api.example.com"}}),
		// Hosts of its own: per-host politeness would hold it back otherwise.
		scanCmd("none", "normal", map[string]any{"scanner": "nuclei", "targets": []string{"gone.example.com", "*.example.com"}}),
	)
	var (
		evMu   sync.Mutex
		events []string
	)
	c := &orderedClient{queueClient: qc, mu: &evMu, events: &events}
	sink := &recordSink{events: &events}
	e := &payloadExecutor{}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4})
	p.SetLocalPolicy(lp)
	p.SetCommandLogSink(lockedSink{sink, &evMu})
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()

	qc.mu.Lock()
	defer qc.mu.Unlock()
	mixed := qc.full["mixed"]
	if mixed == nil || mixed.Status != "completed" || mixed.Error != "" {
		t.Fatalf("mixed: %+v", mixed)
	}
	refused, _ := mixed.Metadata[MetaRefusedTargets].([]RefusedTarget)
	if len(refused) != 1 || refused[0].Target != "api.example.com" || refused[0].Reason != RefusedTargetUnresolvable ||
		mixed.Metadata[MetaRefusedTargetsTotal] != 1 || mixed.Metadata[MetaPartial] != true || mixed.Metadata["scanner_name"] != "nuclei" {
		t.Fatalf("mixed metadata %+v", mixed.Metadata)
	}
	var got struct {
		Targets []string `json:"targets"`
	}
	_ = json.Unmarshal(e.payloads["mixed"], &got)
	if !slices.Equal(got.Targets, []string{"example.com"}) {
		t.Fatalf("the executor got %v: a refused target reached it", got.Targets)
	}

	none := qc.full["none"]
	if none == nil || none.Status != "failed" || !strings.HasPrefix(none.Error, "refused by local policy: targets: 2 target(s) refused") {
		t.Fatalf("none: %+v", none)
	}
	if r := none.Refusal; r == nil || r.Layer != RefusalLayerLocal || r.Rule != "targets" {
		t.Fatalf("none refusal %+v", none.Refusal)
	}
	if _, ran := e.payloads["none"]; ran {
		t.Fatal("a command with every target refused reached the executor")
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	wantNone := []string{"info: Received by the sensor", "info: Local policy check",
		"warn: Target refused by the local policy: gone.example.com", "warn: Target refused by the local policy: *.example.com"}
	if l := sink.lines["none"]; len(l) != 5 || !slices.Equal(l[:4], wantNone) || !strings.HasPrefix(l[4], "error: Refused before running: refused by local policy: targets") {
		t.Fatalf("none log %q", sink.lines["none"])
	}
	if f := sink.fields["none"][2]; f["reason"] != RefusedTargetUnresolvable || f["target"] != "gone.example.com" {
		t.Fatalf("refused-target fields %+v", f)
	}
	ml := sink.lines["mixed"]
	if len(ml) < 4 || !slices.Contains(ml, "info: Running on 1 of 2 target(s); 1 skipped") ||
		!strings.HasPrefix(ml[len(ml)-1], `warn: Completed with 1 target(s) refused: "api.example.com" (unresolvable)`) {
		t.Fatalf("mixed log %q", ml)
	}
	// The logs are finished (queued) before each result is reported.
	evMu.Lock()
	defer evMu.Unlock()
	for _, id := range []string{"mixed", "none"} {
		li, ri := slices.Index(events, "logs:"+id), slices.Index(events, "result:"+id)
		if li < 0 || ri < 0 || li > ri || sink.direct[id] {
			t.Fatalf("%s: events %v (logs must be queued before the result)", id, events)
		}
	}
}

// lockedSink serializes the record sink with the client's event list.
type lockedSink struct {
	s  *recordSink
	mu *sync.Mutex
}

func (l lockedSink) CommandLog(ctx context.Context, id, level, msg string, fields map[string]any) {
	l.s.CommandLog(ctx, id, level, msg, fields)
}

func (l lockedSink) FinishCommandLog(ctx context.Context, id string, direct bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.s.FinishCommandLog(ctx, id, direct)
}

// listRecorder is a list-capable nuclei that records what it was given.
type listRecorder struct {
	mu   sync.Mutex
	list []string
}

func (s *listRecorder) Name() string           { return "nuclei" }
func (s *listRecorder) Version() string        { return "1" }
func (s *listRecorder) Capabilities() []string { return nil }
func (s *listRecorder) IsInstalled(context.Context) (bool, string, error) {
	return true, "1", nil
}
func (s *listRecorder) Scan(ctx context.Context, target string, opts *ScanOptions) (*ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}
func (s *listRecorder) ScanTargets(_ context.Context, targets []string, _ *ScanOptions) (*ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append([]string(nil), targets...)
	return &ScanResult{ScannerName: "nuclei"}, nil
}

// The rebinding guard: a name that passed admission but resolves to a
// denied address by the time the scanner starts is refused by the
// executor's own check (it is never scanned), and the command completes on
// the rest with that target listed.
func TestCommandPoller_RebindingGuard(t *testing.T) {
	var flips atomic.Int32
	lookup := func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "flip.example.com" {
			if flips.Add(1) == 1 {
				return []net.IP{net.ParseIP("203.0.113.20")}, nil // allowed at admission
			}
			return []net.IP{net.ParseIP("203.0.113.200")}, nil // denied range afterwards
		}
		return partialDNS(ctx, host)
	}
	lp := partialLP(t, lookup)
	qc := newQueueClient(scanCmd("job", "normal", map[string]any{"scanner": "nuclei",
		"targets": []string{"example.com", "flip.example.com", "api.example.com"}}))
	sc := &listRecorder{}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetLocalPolicy(lp)
	p := NewCommandPoller(qc, e, &CommandPollerConfig{MaxConcurrent: 2})
	p.SetLocalPolicy(lp)
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()

	if flips.Load() < 2 {
		t.Fatalf("the executor did not check the name again (%d lookups)", flips.Load())
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if !slices.Equal(sc.list, []string{"example.com"}) {
		t.Fatalf("scanned %v: the rebound name reached the scanner", sc.list)
	}
	qc.mu.Lock()
	defer qc.mu.Unlock()
	res := qc.full["job"]
	if res == nil || res.Status != "completed" {
		t.Fatalf("result %+v", res)
	}
	refused, _ := res.Metadata[MetaRefusedTargets].([]RefusedTarget)
	if len(refused) != 2 || res.Metadata[MetaRefusedTargetsTotal] != 2 {
		t.Fatalf("refused %+v", res.Metadata)
	}
	if refused[0].Target != "api.example.com" || refused[0].Reason != RefusedTargetUnresolvable {
		t.Errorf("admission refusal %+v", refused[0])
	}
	if refused[1].Target != "flip.example.com" || refused[1].Reason != RefusedTargetDenied || refused[1].Rule != "targets.deny" {
		t.Errorf("rebinding refusal %+v", refused[1])
	}
}

// A command handed back without running (no free slot) says so in its log,
// sent directly before the release, once per reason.
func TestCommandPoller_HandBackLogged(t *testing.T) {
	var events []string
	sink := &recordSink{events: &events}
	qc := newQueueClient()
	p := NewCommandPoller(qc, &payloadExecutor{}, &CommandPollerConfig{MaxConcurrent: 1})
	p.SetCommandLogSink(sink)
	p.handBack("c1", "no free slot")
	p.handBack("c1", "no free slot")
	p.handBack("c1", "its hosts are busy on this sensor")
	sink.mu.Lock()
	defer sink.mu.Unlock()
	want := []string{"info: Not run on this sensor now: no free slot; handed back to the platform",
		"info: Not run on this sensor now: its hosts are busy on this sensor; handed back to the platform"}
	if !slices.Equal(sink.lines["c1"], want) || !sink.direct["c1"] {
		t.Fatalf("lines %q direct %v", sink.lines["c1"], sink.direct)
	}
	qc.mu.Lock()
	defer qc.mu.Unlock()
	if qc.released["c1"] == "" {
		t.Fatal("not released")
	}
}

// A timeout is named in the command's log.
func TestCommandPoller_TimeoutLogged(t *testing.T) {
	var events []string
	sink := &recordSink{events: &events}
	qc := newQueueClient(scanCmd("slow", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.9"}))
	p := NewCommandPoller(qc, timeoutExecutor{}, &CommandPollerConfig{MaxConcurrent: 1})
	p.SetCommandLogSink(sink)
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	l := sink.lines["slow"]
	if len(l) == 0 || !strings.HasPrefix(l[len(l)-1], "error: Timed out after") {
		t.Fatalf("log %q", l)
	}
}

type timeoutExecutor struct{}

func (timeoutExecutor) Execute(ctx context.Context, _ *Command) (*CommandExecutionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	<-ctx.Done()
	return nil, errors.Join(errors.New("scan failed"), ctx.Err())
}

func TestRefusedTargetsMetadataIsBounded(t *testing.T) {
	var many []RefusedTarget
	for range MaxRefusedTargetsReported + 5 {
		many = append(many, RefusedTarget{Target: "x", Reason: RefusedTargetUnresolvable})
	}
	m := RefusedTargetsMetadata(many)
	if l := m[MetaRefusedTargets].([]RefusedTarget); len(l) != MaxRefusedTargetsReported || m[MetaRefusedTargetsTotal] != len(many) {
		t.Fatalf("metadata %d listed, total %v", len(l), m[MetaRefusedTargetsTotal])
	}
	if RefusedTargetsMetadata(nil) != nil {
		t.Fatal("no refusals: no metadata")
	}
	// Decoded from JSON (an executor's metadata after a round trip).
	raw, _ := json.Marshal(m)
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	if got := refusedTargetsFrom(back); len(got) != MaxRefusedTargetsReported || got[0].Reason != RefusedTargetUnresolvable {
		t.Fatalf("decoded %+v", got)
	}
	// A refused value is bounded and cleaned.
	rt := refusedTargetOf(strings.Repeat("a", 2000)+"\u202e", errors.New("x"))
	if len(rt.Target) > maxRefusedTargetValue || strings.ContainsRune(rt.Target, '\u202e') || rt.Reason != RefusedTargetInvalid {
		t.Fatalf("refused target %d bytes, %+v", len(rt.Target), rt.Reason)
	}
}
