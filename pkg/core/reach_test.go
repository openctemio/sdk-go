package core

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// reachExecutor records what its scanner saw into the job's recorder, as
// an in-process scanner or an output parser does.
type reachExecutor struct{ own bool }

func (e reachExecutor) Execute(ctx context.Context, _ *Command) (*CommandExecutionResult, error) {
	rec := reach.FromContext(ctx)
	rec.Record(reach.Observation{Target: "192.0.2.10", Port: 443, Class: reach.Reached})
	rec.RecordErr("198.51.100.20", netip.Addr{}, 22, syscall.ENETUNREACH)
	res := &CommandExecutionResult{Metadata: map[string]any{"scanner_name": "naabu"}}
	if e.own {
		res.Metadata[reach.MetaReach] = "the executor's own"
	}
	return res, nil
}

// The poller gives every job a recorder and puts its summary in the result:
// an unreachable target is listed, not read as "nothing found".
func TestCommandPoller_ReachMetadata(t *testing.T) {
	qc := newQueueClient(scanCmd("job", "normal", map[string]any{"scanner": "naabu", "targets": []string{"192.0.2.10", "198.51.100.20"}}))
	p := NewCommandPoller(qc, reachExecutor{}, &CommandPollerConfig{MaxConcurrent: 1})
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()

	qc.mu.Lock()
	defer qc.mu.Unlock()
	res := qc.full["job"]
	if res == nil || res.Status != "completed" {
		t.Fatalf("result %+v", res)
	}
	sum, ok := res.Metadata[reach.MetaReach].(reach.Summary)
	if !ok || sum.Targets != 2 || sum.Reached != 1 || sum.Unreached != 1 || sum.Classes[reach.NoRoute] != 1 {
		t.Fatalf("reach summary %#v", res.Metadata[reach.MetaReach])
	}
	list, _ := res.Metadata[reach.MetaUnreachedTargets].([]reach.UnreachedTarget)
	if len(list) != 1 || list[0].Target != "198.51.100.20" || list[0].Class != reach.NoRoute ||
		res.Metadata[reach.MetaUnreachedTargetsTotal] != 1 || res.Metadata["scanner_name"] != "naabu" {
		t.Fatalf("metadata %+v", res.Metadata)
	}
}

// An executor that reports its own summary keeps it.
func TestCommandPoller_ReachMetadataExecutorWins(t *testing.T) {
	qc := newQueueClient(scanCmd("job", "normal", map[string]any{"scanner": "naabu", "targets": []string{"192.0.2.10"}}))
	p := NewCommandPoller(qc, reachExecutor{own: true}, &CommandPollerConfig{MaxConcurrent: 1})
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()
	qc.mu.Lock()
	defer qc.mu.Unlock()
	if got := qc.full["job"].Metadata[reach.MetaReach]; got != "the executor's own" {
		t.Fatalf("reach = %#v", got)
	}
}

func TestAddReachMetadata(t *testing.T) {
	res := &CommandResult{}
	addReachMetadata(res, reach.NewRecorder())
	if res.Metadata != nil {
		t.Fatal("nothing recorded: no metadata")
	}
	rec := reach.NewRecorder()
	rec.Record(reach.Observation{Target: "192.0.2.1", Class: reach.Timeout})
	addReachMetadata(res, rec)
	if _, ok := res.Metadata[reach.MetaReach]; !ok || res.Metadata[reach.MetaUnreachedTargetsTotal] != 1 {
		t.Fatalf("metadata %+v", res.Metadata)
	}
}

func TestReachCoverageType(t *testing.T) {
	rec := reach.NewRecorder()
	ctx := reach.WithRecorder(context.Background(), rec)
	rec.Record(reach.Observation{Target: "192.0.2.1", Class: reach.Reached})
	if got := reachCoverageType(ctx, coverageTypeFull); got != coverageTypeFull {
		t.Fatalf("all reached: %s", got)
	}
	rec.Record(reach.Observation{Target: "192.0.2.2", Class: reach.Timeout})
	if got := reachCoverageType(ctx, coverageTypeFull); got != coverageTypePartial {
		t.Fatalf("one unreached: %s", got)
	}
	if got := reachCoverageType(ctx, coverageTypeIncremental); got != coverageTypeIncremental {
		t.Fatalf("incremental kept: %s", got)
	}
	if got := reachCoverageType(context.Background(), coverageTypeFull); got != coverageTypeFull {
		t.Fatalf("no recorder: %s", got)
	}
}

// The guarded dialer records the outcome of every dial it makes for an
// allowed target, and nothing for a dial the policy refused.
func TestLocalPolicy_DialContextRecordsReach(t *testing.T) {
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = open.Close() }()
	go func() {
		for {
			c, err := open.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()
	_, openPort, _ := net.SplitHostPort(open.Addr().String())
	_, closedPort, _ := net.SplitHostPort(closedAddr)

	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [\"*.corp.example.com\"], deny: [\"192.0.2.0/24\"]}\nports: {allow: \""+openPort+","+closedPort+"\"}\n")
	lp.allowLoopback = true
	answers := map[string][]string{"open.corp.example.com": {"127.0.0.1"}, "closed.corp.example.com": {"127.0.0.1"},
		"denied.corp.example.com": {"192.0.2.9"}}
	lp.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) { return fakeDNS(answers)(ctx, host) }
	rec := reach.NewRecorder()
	ctx := reach.WithRecorder(context.Background(), rec)
	dial := lp.DialContext(nil)

	conn, err := dial(ctx, "tcp", net.JoinHostPort("open.corp.example.com", openPort))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = conn.Close()
	if _, err := dial(ctx, "tcp", net.JoinHostPort("closed.corp.example.com", closedPort)); err == nil {
		t.Skip("the closed port was reused")
	}
	// Refused by the policy: never dialed, never recorded.
	if _, err := dial(ctx, "tcp", net.JoinHostPort("denied.corp.example.com", openPort)); err == nil {
		t.Fatal("denied target dialed")
	}
	rep := rec.Report()
	if rep.Targets != 2 || rep.Classes[reach.Reached] != 1 || rep.Classes[reach.PortClosed] != 1 {
		t.Fatalf("report %+v", rep.Summary)
	}
	for _, b := range rep.Blocks {
		if b.Block != "127.0.0.0/24" {
			t.Fatalf("a refused target was recorded: %+v", b)
		}
	}
}
