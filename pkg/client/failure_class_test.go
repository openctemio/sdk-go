package client

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func crashedResult() *core.CommandResult {
	sig := 139
	return &core.CommandResult{
		Status: "failed", Error: "scan failed: tool_crashed: exited without a result", ErrorCode: "TOOL_EXIT",
		Failure: &core.Failure{Class: core.FailureToolCrashed, Scope: core.FailureScopeCommand, Evidence: core.FailureEvidence{
			Tool: "nuclei", Stage: core.StageRun, ExitCode: &sig, Signal: "SIGSEGV",
			Egress: &core.FailureEgress{ProxyDown: 3}}},
		TargetOutcomes: []outcome.Target{
			{Target: "a.example", State: outcome.Done},
			{Target: "b.example", State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor},
			{Target: "c.example", State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget, Reason: "no_route"},
			{Target: "d.example", State: outcome.Unfinished},
		},
	}
}

// A failed command carries its class, evidence and per-target results to a
// platform that lists "failure_class", and the error code always; an older
// platform gets neither the class nor the outcomes.
func TestFail_FailureClassOnlyWhenOffered(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want     bool
	}{
		{"offered", []string{protov2.FeatureCommands, protov2.FeatureFailureClass}, true},
		{"not offered", []string{protov2.FeatureCommands}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, bodies := refusalServer(t, tc.features)
			c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
			if err := c.ReportCommandResult(context.Background(), "c1", crashedResult()); err != nil {
				t.Fatal(err)
			}
			got := bodies()
			if len(got) != 1 {
				t.Fatalf("%d fail calls", len(got))
			}
			if got[0]["error_code"] != "TOOL_EXIT" {
				t.Errorf("error_code = %v: it is sent to every platform", got[0]["error_code"])
			}
			f, has := got[0]["failure"].(map[string]any)
			_, hasOut := got[0]["target_outcomes"]
			if has != tc.want || hasOut != tc.want {
				t.Fatalf("failure sent = %v, outcomes sent = %v, want %v (body %v)", has, hasOut, tc.want, got[0])
			}
			if !tc.want {
				return
			}
			ev, _ := f["evidence"].(map[string]any)
			if f["class"] != "infra.tool_crashed" || f["scope"] != "command" ||
				ev["tool"] != "nuclei" || ev["stage"] != "run" || ev["signal"] != "SIGSEGV" || ev["exit_code"] != float64(139) {
				t.Errorf("failure = %v", f)
			}
			if eg, _ := ev["egress"].(map[string]any); eg["proxy_down"] != float64(3) {
				t.Errorf("egress = %v", ev["egress"])
			}
			outs, _ := got[0]["target_outcomes"].([]any)
			if len(outs) != 4 {
				t.Fatalf("outcomes = %v", outs)
			}
			b, _ := outs[1].(map[string]any)
			if b["target"] != "b.example" || b["state"] != "failed" || b["class"] != "sensor_network_fault" || b["cause"] != "sensor" {
				t.Errorf("sensor-side outcome = %v", b)
			}
			cc, _ := outs[2].(map[string]any)
			if cc["cause"] != "target" || cc["reason"] != "no_route" {
				t.Errorf("target-side outcome = %v", cc)
			}
		})
	}
}

// What goes on the wire is bounded again: a failure whose evidence holds
// anything outside the closed sets (a proxy address with credentials in the
// tool name or the reason, a path in the signal) loses it on the way out.
func TestFail_EvidenceIsBoundedOnTheWire(t *testing.T) {
	srv, bodies := refusalServer(t, []string{protov2.FeatureCommands, protov2.FeatureFailureClass})
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	secret := "http://alice:hunter2@10.0.0.1:3128"
	res := &core.CommandResult{Status: "failed", Error: "boom", Failure: &core.Failure{
		Class: "made.up", Scope: "weird", Evidence: core.FailureEvidence{
			Tool: secret, Reason: secret, Signal: "/etc/passwd", Stage: secret, Errno: secret, ToolDigest: secret, ContentDigest: secret}}}
	if err := c.ReportCommandResult(context.Background(), "c1", res); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bodies()[0])
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "passwd") {
		t.Fatalf("unbounded evidence on the wire: %s", raw)
	}
	f, _ := bodies()[0]["failure"].(map[string]any)
	if f["class"] != "unknown" || f["scope"] != "command" {
		t.Errorf("failure = %v", f)
	}
}

// A refusal never carries a failure class.
func TestFail_RefusalCarriesNoFailureClass(t *testing.T) {
	srv, bodies := refusalServer(t, []string{protov2.FeatureCommands, protov2.FeatureRefusal, protov2.FeatureFailureClass})
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	res := &core.CommandResult{Status: "failed", Error: "refused by local policy: tools.allow: x",
		Refusal: core.RefusalOf(&core.LocalPolicyError{Rule: "tools.allow", Detail: "x"}), Failure: &core.Failure{Class: core.FailureUnknown}}
	if err := c.ReportCommandResult(context.Background(), "c1", res); err != nil {
		t.Fatal(err)
	}
	if _, has := bodies()[0]["failure"]; has {
		t.Fatalf("a refusal was sent with a failure class: %v", bodies()[0])
	}
}
