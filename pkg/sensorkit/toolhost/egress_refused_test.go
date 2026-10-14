package toolhost

import (
	"testing"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// A target the scope refused every connection toward is failed
// (egress_refused), not done; a target with an allowed connection, or none
// at all, stays as the tool reported it; the task is partial and its
// report carries the outcomes.
func TestMarkEgressRefused(t *testing.T) {
	targets := []tool.Target{
		{Ref: "a", Value: "a.example"},
		{Ref: "b", Value: "https://B.example:8443/x"},
		{Ref: "c", Value: "198.51.100.0/24"},
		{Ref: "d", Value: "192.0.2.4"},
		{Ref: "e", Value: "quiet.example"},
		{Ref: "f", Value: "failed.example"},
	}
	newOut := func() *Outcome {
		out := &Outcome{Status: tool.StatusOK, Report: ctis.NewReport()}
		for _, tg := range targets {
			st := tool.StateDone
			if tg.Ref == "f" {
				st = tool.StateFailed
			}
			out.Targets = append(out.Targets, TargetOutcome{Ref: tg.Ref, Value: tg.Value, State: st, Class: map[bool]tool.ErrorClass{true: tool.Timeout}[st == tool.StateFailed]})
		}
		return out
	}
	tally := egress.Tally{Allowed: 2, Refused: 5, Targets: map[string]egress.TargetTally{
		"a.example":       {Allowed: 2, Refused: 1},
		"b.example":       {Refused: 2},
		"198.51.100.0/24": {Refused: 1},
		"192.0.2.4/32":    {Refused: 1},
		"failed.example":  {Refused: 3},
	}}
	out := newOut()
	if n := markEgressRefused(out, targets, tally); n != 3 {
		t.Fatalf("marked %d, want 3", n)
	}
	want := map[string]tool.TargetState{"a": tool.StateDone, "b": tool.StateFailed, "c": tool.StateFailed, "d": tool.StateFailed, "e": tool.StateDone, "f": tool.StateFailed}
	for _, to := range out.Targets {
		if to.State != want[to.Ref] {
			t.Errorf("%s: %s, want %s", to.Ref, to.State, want[to.Ref])
		}
		if (to.Ref == "b" || to.Ref == "c" || to.Ref == "d") && to.Class != tool.EgressRefused {
			t.Errorf("%s: class %s", to.Ref, to.Class)
		}
		if to.Ref == "f" && to.Class != tool.Timeout {
			t.Errorf("a target the tool failed keeps its class: %s", to.Class)
		}
	}
	if out.Status != tool.StatusPartial {
		t.Fatalf("status %s", out.Status)
	}
	list, _ := out.Report.Properties[outcome.ResultKey].([]outcome.Target)
	got := map[string]outcome.Target{}
	for _, o := range list {
		got[o.Target] = o
	}
	if o := got["https://B.example:8443/x"]; o.State != outcome.Failed || o.Class != outcome.EgressRefused {
		t.Fatalf("report outcome %+v (all %+v)", o, list)
	}

	// Every connection of the task refused, none traced to a target (the
	// tool dialed addresses no target is pinned to): every done target is
	// unreached.
	out = newOut()
	if n := markEgressRefused(out, targets, egress.Tally{Refused: 40}); n != 5 {
		t.Fatalf("all refused: marked %d, want 5", n)
	}
	// Nothing refused: nothing changes.
	out = newOut()
	if n := markEgressRefused(out, targets, egress.Tally{Allowed: 9}); n != 0 || out.Status != tool.StatusOK {
		t.Fatalf("nothing refused: %d %s", n, out.Status)
	}
}

// The forwarder counts a target under the key scopeKey gives it.
func TestScopeKeyMatchesTaskScope(t *testing.T) {
	for v, want := range map[string]string{
		"a.example":                "a.example",
		"https://A.Example.:443/x": "a.example",
		"192.0.2.4":                "192.0.2.4/32",
		"198.51.100.9/24":          "198.51.100.0/24",
		"[2001:db8::1]:443":        "2001:db8::1/128",
	} {
		if got := scopeKey(tool.Target{Value: v}); got != want {
			t.Errorf("%s: %q, want %q", v, got, want)
		}
	}
}
