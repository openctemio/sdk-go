package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

// egressScanner is a scanner whose tools run behind the task forwarder.
type egressScanner struct {
	recordingScanner
	dialer EgressDialer
}

func (s *egressScanner) RoutesEgress() bool { return true }

func (s *egressScanner) Scan(ctx context.Context, target string, opts *ScanOptions) (*ScanResult, error) {
	s.mu.Lock()
	s.dialer = EgressDialerFrom(ctx)
	s.mu.Unlock()
	return s.recordingScanner.Scan(ctx, target, opts)
}

func (s *egressScanner) Name() string { return "rec" }

// fakeSecrets answers a job's secret fetches (client.Secrets).
type fakeSecrets struct {
	mu    sync.Mutex
	calls []string
	err   error
	// missing answers every ref as missing (disabled).
	missing bool
}

func (f *fakeSecrets) Secrets(_ context.Context, cmdID, task string, set secretref.Set, refs []string) (*secretref.Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmdID+"/"+task+"/"+strings.Join(refs, ","))
	if f.err != nil {
		return nil, f.err
	}
	ans := &secretref.Answer{CommandID: cmdID, LeaseEpoch: 1}
	for _, id := range refs {
		if f.missing {
			ans.Missing = append(ans.Missing, secretref.Missing{ID: id, Reason: secretref.MissingDisabled})
			continue
		}
		ref, _ := set.Lookup(id)
		v := json.RawMessage(`{"endpoints":[{"id":"e1","username":"u","password":"p"}]}`)
		if ref.Kind == secretref.KindProviderKey {
			v = json.RawMessage(`{"key":"` + fakeKey(ref.Ref) + `"}`)
		}
		ans.Secrets = append(ans.Secrets, secretref.Secret{ID: id, Kind: ref.Kind, Value: v, Provenance: secretref.ProvenanceTenant})
	}
	return ans, nil
}

// fakeKey is a provider key the fake platform holds for provider id.
func fakeKey(id string) string { return "platform-key-" + id + "-0123456789" }

// poolRef is the job's egress proxy ref for pool id.
func poolRef(id string) secretref.Ref {
	return secretref.Ref{ID: "p1", Kind: secretref.KindEgressProxy, Class: secretref.ClassProvider, Ref: id,
		Audience: []string{secretref.AudiencePool}, Consumer: secretref.ConsumerForwarder, Required: true, Local: secretref.LocalNever}
}

func poolSecrets(poolID string, f SecretsFetcher) *JobSecrets {
	return NewJobSecrets("c1", &secretref.Set{V: 1, Local: secretref.LocalAllow, Refs: []secretref.Ref{poolRef(poolID)}}, false, f)
}

func testEgress(auth bool) *upstream.Config {
	return &upstream.Config{Mode: upstream.ModePool, PoolID: "pool-1", Revision: 3, Strategy: upstream.StrategySticky,
		AppliesTo: upstream.AppliesPublic, Endpoints: []upstream.Endpoint{
			{ID: "e1", Scheme: upstream.SchemeSOCKS5, Host: "10.0.0.5", Port: 1080, Weight: 1, Auth: auth},
			{ID: "e2", Scheme: upstream.SchemeHTTP, Host: "proxy.corp.example", Port: 3128, Weight: 0.5},
		}}
}

func runEgressScan(t *testing.T, e *DefaultCommandExecutor, sc Scanner, egress *upstream.Config, js ...*JobSecrets) error {
	t.Helper()
	e.AddScanner(sc)
	e.SetScanTargetPolicy(newTestPolicy())
	ctx := context.Background()
	if len(js) > 0 {
		ctx = WithJobSecrets(ctx, js[0])
	}
	_, err := e.Execute(ctx, scanCommand(t, ScanCommandPayload{Scanner: "rec", Target: "example.com", Egress: egress}))
	return err
}

func egressRefusalRule(t *testing.T, err error) string {
	t.Helper()
	r := RefusalOf(err)
	if r == nil {
		t.Fatalf("not a refusal: %v", err)
	}
	if r.Layer != RefusalLayerLocal {
		t.Fatalf("layer %s", r.Layer)
	}
	return r.Rule
}

// A pooled job reaches the scanner with the pool (options and context);
// credentials are fetched once, only when an endpoint has some, through
// the job's egress_proxy ref for exactly this pool.
func TestEgressJobHandsThePoolToTheScanner(t *testing.T) {
	for _, auth := range []bool{false, true} {
		sc := &egressScanner{}
		creds := &fakeSecrets{}
		e := NewDefaultCommandExecutor(nil)
		if err := runEgressScan(t, e, sc, testEgress(auth), poolSecrets("pool-1", creds)); err != nil {
			t.Fatal(err)
		}
		pool, ok := sc.options.Egress.(*upstream.Pool)
		if !ok || pool.PoolID() != "pool-1" || sc.dialer == nil {
			t.Fatalf("the scanner got no pool: %+v %v", sc.options.Egress, sc.dialer)
		}
		want := 0
		if auth {
			want = 1
		}
		if len(creds.calls) != want || (auth && creds.calls[0] != "c1/egress/p1") {
			t.Fatalf("auth=%v: credential fetches %v", auth, creds.calls)
		}
	}
}

// Old platforms send no egress block: nothing changes.
func TestNoEgressBlockIsDirect(t *testing.T) {
	sc := &egressScanner{}
	e := NewDefaultCommandExecutor(nil)
	if err := runEgressScan(t, e, sc, nil); err != nil {
		t.Fatal(err)
	}
	if sc.options.Egress != nil || sc.dialer != nil {
		t.Fatal("a job without egress got a pool")
	}
}

// SECURITY: a pooled job never runs direct: a scanner that does not route
// its tools through the forwarder, a direct-only sensor, an empty pool, an
// endpoint outside the allow list, missing credentials each refuse it
// before the scanner runs.
func TestEgressJobRefusals(t *testing.T) {
	allow, err := upstream.ParseAllow("10.0.0.5:1080")
	if err != nil {
		t.Fatal(err)
	}
	empty := testEgress(false)
	empty.Endpoints = nil
	cases := []struct {
		name  string
		setup func(*DefaultCommandExecutor)
		sc    func() Scanner
		cfg   *upstream.Config
		rule  string
		js    *JobSecrets
	}{
		{"not routed", nil, func() Scanner { return &recordingScanner{} }, testEgress(false), RefusalEgressUnavailable, nil},
		{"direct only", func(e *DefaultCommandExecutor) { e.SetEgressPolicy(EgressPolicy{DirectOnly: true}) }, nil, testEgress(false), RefusalEgressRefusedByHost, nil},
		{"empty pool", nil, nil, empty, RefusalEgressUnavailable, nil},
		{"allow list", func(e *DefaultCommandExecutor) { e.SetEgressPolicy(EgressPolicy{Allow: allow}) }, nil, testEgress(false), RefusalEgressRefusedByHost, nil},
		{"no secret list", nil, nil, testEgress(true), RefusalEgressUnavailable, nil},
		{"no fetcher", nil, nil, testEgress(true), RefusalEgressUnavailable, poolSecrets("pool-1", nil)},
		{"credential fetch fails", nil, nil, testEgress(true), RefusalEgressUnavailable,
			poolSecrets("pool-1", &fakeSecrets{err: errors.New("404 command_not_found")})},
		{"the list names another pool", nil, nil, testEgress(true), RefusalEgressUnavailable,
			poolSecrets("pool-2", &fakeSecrets{})},
		{"the platform holds no value", nil, nil, testEgress(true), RefusalEgressUnavailable,
			poolSecrets("pool-1", &fakeSecrets{missing: true})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewDefaultCommandExecutor(nil)
			if tc.setup != nil {
				tc.setup(e)
			}
			var sc Scanner = &egressScanner{}
			if tc.sc != nil {
				sc = tc.sc()
			}
			var js []*JobSecrets
			if tc.js != nil {
				js = append(js, tc.js)
			}
			err := runEgressScan(t, e, sc, tc.cfg, js...)
			if got := egressRefusalRule(t, err); got != tc.rule {
				t.Fatalf("rule %s, want %s (%v)", got, tc.rule, err)
			}
			switch s := sc.(type) {
			case *egressScanner:
				if s.calls != 0 {
					t.Fatal("the scanner ran")
				}
			case *recordingScanner:
				if s.calls != 0 {
					t.Fatal("the scanner ran")
				}
			}
		})
	}
	// A malformed block fails the job (not a refusal of this sensor).
	bad := testEgress(false)
	bad.Endpoints[0].Host = "169.254.169.254"
	err = runEgressScan(t, NewDefaultCommandExecutor(nil), &egressScanner{}, bad)
	if err == nil || !strings.Contains(err.Error(), "egress") {
		t.Fatalf("metadata endpoint accepted: %v", err)
	}
}

type recordingEgressReporter struct {
	mu      *sync.Mutex
	events  *[]string
	reports map[string]upstream.Report
}

func (r *recordingEgressReporter) EgressReport(_ context.Context, cmdID string, rep upstream.Report) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.events = append(*r.events, "egress:"+cmdID)
	r.reports[cmdID] = rep
	return nil
}

// poolExecutor prepares the command's pool through a DefaultCommandExecutor,
// makes one connection attempt (every endpoint is down) and completes or
// fails as the command's payload says.
type poolExecutor struct{ e *DefaultCommandExecutor }

func (x *poolExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	cfg := testEgress(false)
	// Names that never resolve: each attempt fails at once (proxy_down).
	cfg.Endpoints[0].Host, cfg.Endpoints[1].Host = "proxy-a.invalid", "proxy-b.invalid"
	pool, err := x.e.PrepareEgress(ctx, cmd.ID, cfg)
	if err != nil {
		return nil, err
	}
	_, _ = pool.Dial(ctx, "tcp", "203.0.113.7:443")
	if cmd.ID == "fails" {
		return nil, errors.New("scan failed")
	}
	return &CommandExecutionResult{}, nil
}

// The egress report goes before the result, for a completed and a failed
// job; a job without a pool sends none.
func TestEgressReportBeforeResult(t *testing.T) {
	qc := newQueueClient(
		scanCmd("ok", "normal", map[string]any{"scanner": "rec", "target": "a.example"}),
		scanCmd("fails", "normal", map[string]any{"scanner": "rec", "target": "b.example"}),
	)
	var (
		mu     sync.Mutex
		events []string
	)
	c := &orderedClient{queueClient: qc, mu: &mu, events: &events}
	rep := &recordingEgressReporter{mu: &mu, events: &events, reports: map[string]upstream.Report{}}
	p := NewCommandPoller(c, &poolExecutor{e: NewDefaultCommandExecutor(nil)}, &CommandPollerConfig{MaxConcurrent: 4})
	p.SetEgressReporter(rep)
	p.pollAndExecute(context.Background())
	p.waitForActiveCommands()

	mu.Lock()
	defer mu.Unlock()
	for _, id := range []string{"ok", "fails"} {
		ei, ri := -1, -1
		for i, ev := range events {
			switch ev {
			case "egress:" + id:
				ei = i
			case "result:" + id:
				ri = i
			}
		}
		if ei < 0 || ri < 0 || ei > ri {
			t.Fatalf("%s: events %v", id, events)
		}
		r := rep.reports[id]
		if r.PoolID != "pool-1" || !r.Used() {
			t.Fatalf("%s: report %+v", id, r)
		}
	}
	if qc.full["fails"] == nil || qc.full["fails"].Status != "failed" {
		t.Fatalf("fails: %+v", qc.full["fails"])
	}
}
