package core

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

const policyHead = "apiVersion: openctem.io/sensor-policy/v1\n"

// SECURITY: the budget a job runs under comes from the sensor's level, the
// job's verified statement and the operator's ceiling only. A lower signed
// budget wins, a higher one is clamped at the ceiling, and nothing in an
// unsigned command can set one.
// The budget of a command: the lowest of the sensor's level, the job's
// signed budget and the local policy's ceiling. A job can only lower.
func TestHostBudgetOfACommand(t *testing.T) {
	fast := &adapt.JobBudget{Level: "fast"}
	gentle := &adapt.JobBudget{Level: "gentle"}
	huge := &adapt.JobBudget{Level: "custom", RPS: 50000, Inflight: 9000}
	cases := []struct {
		name     string
		cmd      *Command
		policy   string
		level    string
		rps, in  int
		wonBy    string
		clamped  int
		wantName string
	}{
		{name: "no command: Standard", rps: 20, in: 8, wonBy: adapt.LimitSensorLevel, wantName: "standard"},
		{name: "a job without a budget (an older platform): Standard", cmd: &Command{jobVerified: true}, rps: 20, in: 8, wonBy: adapt.LimitSensorLevel, wantName: "standard"},
		{name: "a lower signed budget wins", cmd: &Command{jobVerified: true, signedPacing: gentle}, rps: 5, in: 2, wonBy: adapt.LimitJob, clamped: 2, wantName: "gentle"},
		{name: "a signed Fast on a Standard sensor stays Standard", cmd: &Command{jobVerified: true, signedPacing: fast}, rps: 20, in: 8, wonBy: adapt.LimitSensorLevel, clamped: 2, wantName: "standard"},
		{name: "a signed budget far above everything stays Standard", cmd: &Command{jobVerified: true, signedPacing: huge}, rps: 20, in: 8, wonBy: adapt.LimitSensorLevel, clamped: 2, wantName: "standard"},
		{name: "a signed Fast on a Fast sensor is Fast", level: "fast", cmd: &Command{jobVerified: true, signedPacing: fast}, rps: 100, in: 25, wonBy: adapt.LimitSensorLevel, wantName: "fast"},
		{name: "the operator's ceiling beats a Fast sensor and a signed Fast", level: "fast", cmd: &Command{jobVerified: true, signedPacing: fast},
			policy: policyHead + "rate: {max_host_rps: 10, max_host_inflight: 4}\n", rps: 10, in: 4, wonBy: adapt.LimitOperatorCeiling, clamped: 4, wantName: "custom"},
		{name: "the operator's ceiling lowers the default too", policy: policyHead + "rate: {max_host_rps: 5, max_host_inflight: 2}\n", rps: 5, in: 2, wonBy: adapt.LimitOperatorCeiling, clamped: 2, wantName: "gentle"},
		{name: "a lower signed budget under a ceiling stays", cmd: &Command{jobVerified: true, signedPacing: gentle},
			policy: policyHead + "rate: {max_host_rps: 10, max_host_inflight: 4}\n", rps: 5, in: 2, wonBy: adapt.LimitJob, clamped: 2, wantName: "gentle"},
		{name: "a budget on a command that was not verified is not read", cmd: &Command{signedPacing: gentle}, rps: 20, in: 8, wonBy: adapt.LimitSensorLevel, wantName: "standard"},
		{name: "the operator's own level", level: "gentle", rps: 5, in: 2, wonBy: adapt.LimitSensorLevel, wantName: "gentle"},
		{name: "the operator's Fast, a signed Gentle still wins", level: "fast", cmd: &Command{jobVerified: true, signedPacing: gentle}, rps: 5, in: 2, wonBy: adapt.LimitJob, clamped: 2, wantName: "gentle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewDefaultCommandExecutor(nil)
			if tc.policy != "" {
				e.SetLocalPolicy(mustPolicy(t, tc.policy))
			}
			if tc.level != "" {
				if err := e.SetPacingLevel(tc.level); err != nil {
					t.Fatal(err)
				}
			}
			b := e.HostBudget(tc.cmd)
			if b.RPS != tc.rps || b.Inflight != tc.in || b.WonBy.RPS != tc.wonBy || b.WonBy.Inflight != tc.wonBy || len(b.Clamped) != tc.clamped || b.Level != tc.wantName {
				t.Fatalf("budget %+v", b)
			}
		})
	}
}

// SECURITY: a command decoded from JSON (what the platform's unsigned
// envelope and payload can say) never carries a budget, whatever members it
// names.
func TestUnsignedCommandCannotSetABudget(t *testing.T) {
	for _, doc := range []string{
		`{"id":"c","type":"scan","signedPacing":{"level":"fast"},"signed_pacing":{"level":"fast"},"pacing":{"level":"fast","target_rps":5000}}`,
		`{"id":"c","type":"scan","jobVerified":true,"job_verified":true,"pacing":{"target_rps":5000,"target_inflight":500}}`,
		`{"id":"c","type":"scan","payload":{"scanner":"nuclei","pacing":{"level":"fast"},"config":{"pacing":"fast","host_budget":{"rps":5000},"target_rps":5000}}}`,
		// Nor a lower one: only the signed statement speaks for the job.
		`{"id":"c","type":"scan","signedPacing":{"level":"gentle"},"pacing":{"level":"gentle","target_rps":1}}`,
	} {
		var cmd Command
		if err := json.Unmarshal([]byte(doc), &cmd); err != nil {
			t.Fatal(err)
		}
		if cmd.signedPacing != nil || cmd.jobVerified {
			t.Fatalf("a decoded command carries a budget: %+v", cmd.signedPacing)
		}
		if b := NewDefaultCommandExecutor(nil).HostBudget(&cmd); b.RPS != 20 || b.Inflight != 8 || b.WonBy.RPS != adapt.LimitSensorLevel || len(b.Clamped) != 0 {
			t.Fatalf("budget %+v from %s", b, doc)
		}
	}
}

func TestSetPacingLevelRefusesAnUnknownName(t *testing.T) {
	e := NewDefaultCommandExecutor(nil)
	if err := e.SetPacingLevel("ludicrous"); err == nil {
		t.Fatal("an unknown level was accepted")
	}
	if b := e.HostBudget(nil); b.Level != "standard" {
		t.Fatalf("budget after a refused level: %+v", b)
	}
	if err := e.SetPacingLevel(""); err != nil {
		t.Fatalf("the empty name is the default: %v", err)
	}
}

func TestLocalPolicyHostCeiling(t *testing.T) {
	lp := mustPolicy(t, policyHead+"rate: {max_rps: 50, max_host_rps: 12, max_host_inflight: 3}\n")
	if c := lp.HostCeiling(); c.RPS != 12 || c.Inflight != 3 {
		t.Fatalf("ceiling %+v", c)
	}
	if lp.CapRate(1000) != 50 {
		t.Fatal("max_rps no longer caps the job's rate")
	}
	var none *LocalPolicy
	if c := none.HostCeiling(); c != (adapt.BudgetCeiling{}) {
		t.Fatalf("no policy: %+v", c)
	}
	if c := mustPolicy(t, policyHead+"rate: {max_rps: 50}\n").HostCeiling(); c != (adapt.BudgetCeiling{}) {
		t.Fatalf("a policy without a host ceiling: %+v", c)
	}
	// The operator's ceiling only narrows: nothing above the built-in hard
	// ceiling, nothing below one.
	for name, doc := range map[string]string{
		"host rps zero":          policyHead + "rate: {max_host_rps: 0}\n",
		"host rps above hard":    policyHead + "rate: {max_host_rps: 201}\n",
		"host inflight zero":     policyHead + "rate: {max_host_inflight: 0}\n",
		"host inflight too high": policyHead + "rate: {max_host_inflight: 51}\n",
		"host rps negative":      policyHead + "rate: {max_host_rps: -3}\n",
	} {
		if _, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{LookupEnv: env(nil)}); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
	if r := lp.Report(); r == nil || r.Summary == nil || r.Summary.MaxHostRPS != 12 || r.Summary.MaxHostInflight != 3 {
		t.Fatalf("report %+v", r)
	}
}

// The local policy's per-host ceiling also bounds the budget of a scan or
// retest whose caller handed it none (adapt.FallbackBudget): the executor
// records it with the policy, and removing the policy removes it.
func TestLocalPolicyCeilingBoundsTheFallbackBudget(t *testing.T) {
	e := NewDefaultCommandExecutor(nil)
	t.Cleanup(func() { adapt.SetSensorHostCeiling(adapt.BudgetCeiling{}); adapt.SetSensorPacing(adapt.DefaultPacing) })
	if err := e.SetPacingLevel(adapt.PacingFast.Name); err != nil {
		t.Fatal(err)
	}
	e.SetLocalPolicy(mustPolicy(t, policyHead+"rate: {max_host_rps: 4, max_host_inflight: 2}\n"))
	if b := adapt.FallbackBudget(); b.RPS != 4 || b.Inflight != 2 {
		t.Fatalf("fallback under a 4/s, 2 ceiling: %+v", b)
	}
	e.SetLocalPolicy(nil)
	std := adapt.DefaultBudget()
	if b := adapt.FallbackBudget(); b.RPS != std.RPS || b.Inflight != std.Inflight {
		t.Fatalf("fallback without a policy: %+v, want Standard", b)
	}
}
