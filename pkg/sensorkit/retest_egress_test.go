package sensorkit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func retestEgressCommand(t *testing.T) *core.Command {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"scanner": "nuclei", "targets": []string{"a.example"},
		"items": []map[string]string{{"ref": "i1", "target": "a.example", "rule_id": "r"}},
		"egress": upstream.Config{Mode: upstream.ModePool, PoolID: "pool-1", AppliesTo: upstream.AppliesAll,
			Endpoints: []upstream.Endpoint{{ID: "e1", Scheme: upstream.SchemeHTTP, Host: "10.0.0.5", Port: 3128, Weight: 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "r1", Type: RetestCommandType, Payload: raw}
}

// SECURITY: a retest that carries a proxy pool runs its tool with the pool
// (task and context), so the tool host dials through it or refuses the
// task; a direct-only sensor refuses it, and an executor that cannot
// prepare pools refuses it. It never runs direct.
func TestRetestWithEgress(t *testing.T) {
	var got tool.Task
	var ctxPool core.EgressDialer
	run := func(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
		got, ctxPool = task, core.EgressDialerFrom(ctx)
		return &toolhost.Outcome{Status: tool.StatusOK}, nil
	}
	exec := core.NewDefaultCommandExecutor(nil)
	x := newRetestExecutor(nil, map[string]RetestFunc{"nuclei": run}, nil, exec, func() *core.LocalPolicy { return nil }, exec)
	if _, err := x.Execute(context.Background(), retestEgressCommand(t)); err != nil {
		t.Fatal(err)
	}
	if p, ok := got.Egress.(*upstream.Pool); !ok || p.PoolID() != "pool-1" || ctxPool == nil {
		t.Fatalf("the retest ran without its pool: %+v %v", got.Egress, ctxPool)
	}

	got = tool.Task{}
	exec.SetEgressPolicy(core.EgressPolicy{DirectOnly: true})
	_, err := x.Execute(context.Background(), retestEgressCommand(t))
	if r := core.RefusalOf(err); r == nil || r.Rule != core.RefusalEgressRefusedByHost || got.ID != "" {
		t.Fatalf("direct-only: %v (ran: %v)", err, got.ID != "")
	}

	noPrep := newRetestExecutor(nil, map[string]RetestFunc{"nuclei": run}, nil, exec, func() *core.LocalPolicy { return nil }, nil)
	_, err = noPrep.Execute(context.Background(), retestEgressCommand(t))
	if r := core.RefusalOf(err); r == nil || r.Rule != core.RefusalEgressUnavailable || got.ID != "" {
		t.Fatalf("no preparer: %v", err)
	}
}

func TestResolveScanEgress(t *testing.T) {
	for _, c := range []struct {
		mode, allow string
		ok, accepts bool
	}{
		{"", "", true, true}, {"platform", "", true, true}, {"Direct-Only", "", true, false},
		{"proxy", "", false, false}, {"", "10.0.0.5:3128,proxy.corp.example", true, true}, {"", "127.0.0.1:1080", false, false},
	} {
		t.Setenv(EnvScanEgress, c.mode)
		t.Setenv(EnvScanEgressAllow, c.allow)
		s, err := ResolveScanEgress()
		if (err == nil) != c.ok {
			t.Fatalf("%q %q: %v", c.mode, c.allow, err)
		}
		if err == nil && s.AcceptsPools() != c.accepts {
			t.Fatalf("%q: accepts %v", c.mode, s.AcceptsPools())
		}
	}
	if p := (ScanEgress{Mode: ScanEgressPlatform}).policy(true); !p.DirectOnly {
		t.Fatal("a shared sensor accepts pools")
	}
	if p := (ScanEgress{Mode: ScanEgressDirectOnly}).policy(false); !p.DirectOnly {
		t.Fatal("direct-only accepts pools")
	}
}
