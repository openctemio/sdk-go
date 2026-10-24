package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// decodedReport is a report as the executor sees it after the tool host's
// JSON went through the parser: list properties are []any.
func decodedReport(t *testing.T, props map[string]any) *ctis.Report {
	t.Helper()
	raw, err := json.Marshal(props)
	if err != nil {
		t.Fatal(err)
	}
	r := ctis.NewReport()
	if err := json.Unmarshal(raw, &r.Properties); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTargetOutcomes_FromReport(t *testing.T) {
	targets := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	report := decodedReport(t, map[string]any{
		outcome.ResultKey: []outcome.Target{
			{Target: "a.example", State: outcome.Done},
			{Target: "b.example", State: outcome.Failed, Class: outcome.Timeout},
			{Target: "x.example", State: outcome.Done}, // not a job target
		},
		"unfinished_targets": []string{"c.example"},
		"failed_targets":     []map[string]string{{"target": "d.example", "error": "exit 2"}},
	})
	got := TargetOutcomes(targets, report)
	want := []outcome.Target{
		{Target: "a.example", State: outcome.Done},
		{Target: "b.example", State: outcome.Failed, Class: outcome.Timeout},
		{Target: "c.example", State: outcome.Unfinished},
		{Target: "d.example", State: outcome.Failed, Class: outcome.ToolError},
		{Target: "e.example", State: outcome.Done},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %+v\nwant %+v", got, want)
	}
}

func TestTargetOutcomes_NoReportIsAllDone(t *testing.T) {
	got := TargetOutcomes([]string{"a", "b"}, nil)
	if c := outcome.Count(got); c != (outcome.Counts{Done: 2}) {
		t.Fatalf("counts = %+v", c)
	}
	if TargetOutcomes(nil, nil) != nil {
		t.Fatal("outcomes without targets")
	}
}

// Outcomes name the payload's own values, and targets the executor's
// policy refused are skipped, so the platform never reads them as
// unfinished.
func TestPayloadOutcomes_AliasesAndRefused(t *testing.T) {
	p := &ScanCommandPayload{aliases: map[string]string{"/real/repo": "/link/repo"}}
	got := p.outcomes([]outcome.Target{{Target: "/real/repo", State: outcome.Done}},
		[]RefusedTarget{{Target: "10.0.0.1", Reason: RefusedTargetDenied}})
	want := []outcome.Target{
		{Target: "10.0.0.1", State: outcome.Skipped, Class: outcome.Refused},
		{Target: "/link/repo", State: outcome.Done},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %+v", got)
	}
}

func rev2(extra ...func(*OutcomeEvidence)) OutcomeEvidence {
	ev := OutcomeEvidence{Revision: 2}
	for _, f := range extra {
		f(&ev)
	}
	return ev
}

func TestTargetOutcomesFor_NothingCoveredIsNeverDone(t *testing.T) {
	targets := []string{"https://shop.example.com/", "gone.example", "sick.example", "down.example", "ok.example", "quiet.example"}
	rec := reach.NewRecorder()
	rec.RecordErr("gone.example", netip.Addr{}, 443, &net.DNSError{Err: "no such host", IsNotFound: true})
	rec.RecordErr("sick.example", netip.Addr{}, 443, &net.DNSError{Err: "server misbehaving"})
	rec.Record(reach.Observation{Target: "down.example", Class: reach.Timeout})
	rec.Record(reach.Observation{Target: "ok.example", Class: reach.PortClosed}) // the path works
	gaps := []adapt.Gap{{Host: "shop.example.com", Reason: adapt.GapBlocked, Edge: "challenged", Vendor: "cloudflare"}}

	got := TargetOutcomesFor(context.Background(), targets, rev2(func(e *OutcomeEvidence) { e.Reach, e.Gaps = rec, gaps }))
	want := []outcome.Target{
		{Target: "https://shop.example.com/", State: outcome.Failed, Class: outcome.EdgeChallenged, Cause: outcome.CauseTarget, Vendor: "cloudflare"},
		{Target: "gone.example", State: outcome.Failed, Class: outcome.NameGone, Cause: outcome.CauseTarget},
		{Target: "sick.example", State: outcome.Failed, Class: outcome.ResolverFailed, Cause: outcome.CauseTarget},
		{Target: "down.example", State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget, Reason: "no_answer"},
		{Target: "ok.example", State: outcome.Done},
		{Target: "quiet.example", State: outcome.Done},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %+v\nwant %+v", got, want)
	}
	for _, o := range got {
		if !o.Valid() {
			t.Errorf("invalid outcome %+v", o)
		}
	}
	// The same evidence, without the pre-fix behavior: the report alone
	// would have called every one of them done.
	for _, o := range TargetOutcomes(targets, nil) {
		if o.State != outcome.Done {
			t.Fatalf("report-only outcomes changed: %+v", o)
		}
	}
}

func TestTargetOutcomesFor_GapKinds(t *testing.T) {
	targets := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	gaps := []adapt.Gap{
		{Host: "a.example", Reason: adapt.GapBlocked},                                                   // a run of plain 403s
		{Host: "b.example", Reason: adapt.GapBlocked, Edge: "blocked", Vendor: "akamai"},                // vendor block page
		{Host: "c.example", Reason: adapt.GapRateFloor},                                                 // pushed back at the floor
		{Host: "d.example", Reason: adapt.GapBreakerOpen},                                               // stopped answering
		{Host: "e.example", Reason: adapt.GapBlocked, Edge: "blocked", Vendor: "Not A Token\n<script>"}, // hostile vendor text
	}
	got := TargetOutcomesFor(context.Background(), targets, rev2(func(e *OutcomeEvidence) { e.Gaps = gaps }))
	want := []outcome.Target{
		{Target: "a.example", State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseTarget},
		{Target: "b.example", State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseTarget, Vendor: "akamai"},
		{Target: "c.example", State: outcome.Failed, Class: outcome.RateLimited, Cause: outcome.CauseTarget},
		{Target: "d.example", State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget, Reason: "stopped_answering"},
		{Target: "e.example", State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseTarget},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %+v\nwant %+v", got, want)
	}
}

func TestTargetOutcomesFor_SensorFaultWinsOverTargetFacts(t *testing.T) {
	targets := []string{"a.example", "b.example", "c.example"}
	rec := reach.NewRecorder()
	rec.Record(reach.Observation{Target: "a.example", Class: reach.Timeout})
	rec.Record(reach.Observation{Target: "b.example", Class: reach.NoRoute})
	rec.RecordErr("c.example", netip.Addr{}, 443, &net.DNSError{Err: "no such host", IsNotFound: true})
	down := &reach.Control{Endpoint: "echo.example:443",
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("network is unreachable")
		}}
	got := TargetOutcomesFor(context.Background(), targets, rev2(func(e *OutcomeEvidence) { e.Reach, e.Control = rec, down }))
	// The path probe failed: the network classes are the sensor's. The DNS
	// probe was not configured, so a gone name stays the target's.
	if got[0].Class != outcome.SensorNetworkFault || got[0].Cause != outcome.CauseSensor ||
		got[1].Class != outcome.SensorNetworkFault || got[2].Class != outcome.NameGone {
		t.Fatalf("outcomes = %+v", got)
	}
	for _, o := range got {
		if !o.Settled() || (o.Class == outcome.SensorNetworkFault && !o.Fault()) {
			t.Errorf("outcome %+v", o)
		}
	}

	// A working control check leaves the same evidence as the targets' own.
	up := &reach.Control{Endpoint: "echo.example:443",
		Dial: func(context.Context, string, string) (net.Conn, error) {
			c, s := net.Pipe()
			_ = s.Close()
			return c, nil
		}}
	got = TargetOutcomesFor(context.Background(), targets, rev2(func(e *OutcomeEvidence) { e.Reach, e.Control = rec, up }))
	if got[0].Class != outcome.Unreachable || got[1].Reason != "no_route" || got[0].Cause != outcome.CauseTarget {
		t.Fatalf("outcomes with a passing check = %+v", got)
	}
}

func TestTargetOutcomesFor_ControlRunsOnlyWhenSomethingWasUnreached(t *testing.T) {
	calls := 0
	ctl := &reach.Control{Endpoint: "echo.example:443",
		Dial: func(context.Context, string, string) (net.Conn, error) { calls++; return nil, errors.New("x") }}
	rec := reach.NewRecorder()
	rec.Record(reach.Observation{Target: "a.example", Class: reach.Reached})
	TargetOutcomesFor(context.Background(), []string{"a.example"}, rev2(func(e *OutcomeEvidence) { e.Reach, e.Control = rec, ctl }))
	if calls != 0 {
		t.Fatalf("the control probe ran for a task whose targets all answered")
	}
	rec.Record(reach.Observation{Target: "b.example", Class: reach.Timeout})
	rec.Record(reach.Observation{Target: "c.example", Class: reach.Timeout})
	TargetOutcomesFor(context.Background(), []string{"b.example", "c.example"}, rev2(func(e *OutcomeEvidence) { e.Reach, e.Control = rec, ctl }))
	if calls != 1 {
		t.Fatalf("control probes = %d, want one for the whole task", calls)
	}
}

func TestTargetOutcomesFor_RevisionOneGetsKnownClassesAndNeverDone(t *testing.T) {
	targets := []string{"https://shop.example.com/", "gone.example", "slow.example"}
	rec := reach.NewRecorder()
	rec.RecordErr("gone.example", netip.Addr{}, 443, &net.DNSError{Err: "no such host", IsNotFound: true})
	gaps := []adapt.Gap{
		{Host: "shop.example.com", Reason: adapt.GapBlocked, Edge: "blocked", Vendor: "cloudflare"},
		{Host: "slow.example", Reason: adapt.GapRateFloor},
	}
	for _, rev := range []int{0, 1} {
		got := TargetOutcomesFor(context.Background(), targets, OutcomeEvidence{Reach: rec, Gaps: gaps, Revision: rev})
		want := []outcome.Target{
			{Target: "https://shop.example.com/", State: outcome.Failed, Class: outcome.ToolError},
			{Target: "gone.example", State: outcome.Failed, Class: outcome.Unreachable},
			{Target: "slow.example", State: outcome.Failed, Class: outcome.ToolError},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("revision %d: outcomes = %+v\nwant %+v", rev, got, want)
		}
		// An old platform's Normalize accepts every one of them.
		if n := outcome.Normalize(got, targets); !reflect.DeepEqual(n, got) {
			t.Fatalf("revision 1 receiver dropped an entry: %+v", n)
		}
	}
}

func TestTargetOutcomesFor_ReportMarksWinOverEvidence(t *testing.T) {
	report := decodedReport(t, map[string]any{
		outcome.ResultKey: []outcome.Target{{Target: "a.example", State: outcome.Failed, Class: outcome.EdgeChallenged, Vendor: "imperva"}},
	})
	rec := reach.NewRecorder()
	rec.Record(reach.Observation{Target: "a.example", Class: reach.Timeout})
	got := TargetOutcomesFor(context.Background(), []string{"a.example"}, OutcomeEvidence{Report: report, Reach: rec, Revision: 2})
	if got[0].Class != outcome.EdgeChallenged || got[0].Vendor != "imperva" {
		t.Fatalf("outcome = %+v", got[0])
	}
}

func TestSkippedOutcomes_UnresolvableByRevision(t *testing.T) {
	refused := []RefusedTarget{
		{Target: "gone.example", Reason: RefusedTargetUnresolvable, DNS: "name_gone"},
		{Target: "sick.example", Reason: RefusedTargetUnresolvable, DNS: "resolver_failed"},
		{Target: "old.example", Reason: RefusedTargetUnresolvable}, // a sensor build without the split
		{Target: "10.0.0.1", Reason: RefusedTargetDenied},
	}
	if got := skippedOutcomes(refused, 1); !allSkippedRefused(got) {
		t.Fatalf("revision 1 changed: %+v", got)
	}
	got := skippedOutcomes(refused, 2)
	if got[0].Class != outcome.NameGone || got[0].State != outcome.Failed || got[1].Class != outcome.ResolverFailed ||
		got[2].Class != outcome.Refused || got[3].Class != outcome.Refused {
		t.Fatalf("revision 2: %+v", got)
	}
}

func allSkippedRefused(os []outcome.Target) bool {
	for _, o := range os {
		if o.State != outcome.Skipped || o.Class != outcome.Refused {
			return false
		}
	}
	return true
}

func TestRefusedTargetNamesTheKindOfLookupFailure(t *testing.T) {
	lp := &LocalPolicy{}
	lp.lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "gone.example.com":
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		case "empty.example.com":
			return nil, nil
		}
		return nil, &net.DNSError{Err: "server misbehaving", Name: host}
	}
	for host, want := range map[string]string{"gone.example.com": "name_gone", "empty.example.com": "name_gone", "sick.example.com": "resolver_failed"} {
		_, err := lp.checkHost(context.Background(), host, true)
		rt := refusedTargetOf(host, err)
		if rt.Reason != RefusedTargetUnresolvable || rt.DNS != want {
			t.Errorf("%s: %+v, want unresolvable/%s", host, rt, want)
		}
	}
}

func TestOutcomeRevisionOf(t *testing.T) {
	for in, want := range map[string]int{`{"outcome_revision":2}`: 2, `{}`: 1, `{"outcome_revision":0}`: 1, `{"outcome_revision":-3}`: 1, `not json`: 1, ``: 1} {
		if got := outcomeRevisionOf([]byte(in)); got != want {
			t.Errorf("outcomeRevisionOf(%q) = %d, want %d", in, got, want)
		}
	}
}
