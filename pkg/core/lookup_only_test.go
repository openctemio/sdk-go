package core

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strconv"
	"testing"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/contract/outcome"
)

// lookupPolicy allows example.com and its subdomains and one test range, and
// denies one name under the allowed domain.
const lookupPolicy = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["example.com", "*.example.com", "203.0.113.0/24"]
  deny: ["blocked.example.com"]
tools:
  allow: [nuclei, dnsx]
checks:
  allow: [scan]
`

// lookupDNS: example.com resolves; every other name is NXDOMAIN.
func lookupDNS(_ context.Context, host string) ([]net.IP, error) {
	if host == "example.com" {
		return []net.IP{net.ParseIP("203.0.113.5")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func lookupLP(t *testing.T) *LocalPolicy {
	t.Helper()
	lp, err := ParseLocalPolicy([]byte(lookupPolicy), LocalPolicyOptions{LookupEnv: env(nil), LookupIP: lookupDNS})
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

func refusedBy(adm *CommandAdmission) map[string]RefusedTarget {
	out := map[string]RefusedTarget{}
	for _, r := range adm.Refused {
		out[r.Target] = r
	}
	return out
}

// Only resolve.dns is lookup-only; a job naming no capability is connecting.
func TestLookupOnlyCapability(t *testing.T) {
	for _, c := range capability.All() {
		want := c.ID == "resolve.dns"
		if got := LookupOnlyCapability(c.ID + "@" + strconv.Itoa(c.Major)); got != want {
			t.Errorf("%s: lookup-only %v, want %v", c.ID, got, want)
		}
	}
	for _, c := range []string{"", "resolve", "resolve.dns.extra", "scan.ports"} {
		if LookupOnlyCapability(c) {
			t.Errorf("%q must not be lookup-only", c)
		}
	}
	if !LookupOnlyCapability(" Resolve.DNS ") {
		t.Error("the key is matched case-insensitively")
	}
}

// SECURITY: every capability that connects to its targets keeps refusing a
// name that does not resolve: it is removed from the job (never handed to
// the tool) with reason unresolvable, whatever domain it is under. The
// lookup-only capability reports a dead name outside the allowed domains
// as unresolvable too, with rule targets.allow.
func TestAdmitCommandTargets_UnresolvableByCapability(t *testing.T) {
	lp := lookupLP(t)
	ctx := context.Background()
	for _, c := range capability.All() {
		ref := c.ID + "@" + strconv.Itoa(c.Major)
		t.Run(ref, func(t *testing.T) {
			cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "capability": ref,
				"targets": []string{"example.com", "gone.example.com", "dead.other.test"}})
			adm, err := lp.AdmitCommandTargets(ctx, cmd)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if adm.Settled {
				t.Fatal("a job with a target left is not settled")
			}
			if RegistryOnlyCapability(ref) {
				// A registry lookup takes the name that does not resolve
				// under an allowed domain (TestAdmitCommandTargets_RegistryOnly...).
				if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"example.com", "gone.example.com"}) {
					t.Fatalf("registry-only payload targets %v", got)
				}
				return
			}
			if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"example.com"}) {
				t.Fatalf("payload targets %v: a dead name reached the tool", got)
			}
			r := refusedBy(adm)
			if g := r["gone.example.com"]; g.Reason != RefusedTargetUnresolvable || g.DNS != "name_gone" {
				t.Fatalf("gone.example.com %+v", g)
			}
			d := r["dead.other.test"]
			if LookupOnlyCapability(ref) {
				if d.Reason != RefusedTargetUnresolvable || d.Rule != "targets.allow" || d.DNS != "name_gone" {
					t.Fatalf("lookup-only: a dead name outside the allowed domains is unresolvable (rule targets.allow), got %+v", d)
				}
				return
			}
			if d.Reason != RefusedTargetUnresolvable {
				t.Fatalf("connecting: %+v", d)
			}
		})
	}
}

func TestAdmitCommandTargets_LookupOnlyDeadNames(t *testing.T) {
	lp := lookupLP(t)
	ctx := context.Background()

	t.Run("every target dead completes per target", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "dnsx", "capability": "resolve.dns@1",
			"targets": []string{"gone.example.com", "old.example.com"}})
		before := string(cmd.Payload)
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatalf("a job of dead names must not be refused: %v", err)
		}
		if !adm.Settled || len(adm.Refused) != 2 || string(cmd.Payload) != before {
			t.Fatalf("admission %+v payload %s", adm, cmd.Payload)
		}
		for _, r := range adm.Refused {
			if r.Reason != RefusedTargetUnresolvable || r.DNS != "name_gone" {
				t.Fatalf("refused %+v", r)
			}
		}
	})

	t.Run("a single dead target completes too", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "dnsx", "capability": "resolve.dns", "target": "gone.example.com"})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil || !adm.Settled {
			t.Fatalf("admission %+v err %v", adm, err)
		}
	})

	t.Run("a domain-denied dead name stays refused", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "dnsx", "capability": "resolve.dns@1",
			"targets": []string{"example.com", "blocked.example.com"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		r := refusedBy(adm)["blocked.example.com"]
		if r.Reason != RefusedTargetDenied || r.Rule != "targets.deny" {
			t.Fatalf("blocked.example.com %+v", r)
		}
		// Alone it refuses the job: a denial is not a dead name.
		cmd = cmdWith("c", "scan", map[string]any{"scanner": "dnsx", "capability": "resolve.dns@1",
			"targets": []string{"gone.example.com", "blocked.example.com"}})
		adm, err = lp.AdmitCommandTargets(ctx, cmd)
		if err == nil || adm.Settled {
			t.Fatalf("admission %+v err %v: a denied target must refuse the job", adm, err)
		}
	})

	t.Run("a dead name outside the allowed domains settles as unresolvable", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "dnsx", "capability": "resolve.dns@1",
			"targets": []string{"dead.other.test"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil || !adm.Settled || len(adm.Refused) != 1 ||
			adm.Refused[0].Reason != RefusedTargetUnresolvable || adm.Refused[0].Rule != "targets.allow" {
			t.Fatalf("admission %+v err %v", adm, err)
		}
	})
}

// The poller completes a job whose every target is a dead name without
// running it, with each target listed (reason unresolvable, dns name_gone)
// and one outcome per target: skipped/refused for a platform of outcome
// revision 1, failed/name_gone (cause target) for revision 2.
func TestCommandPoller_DeadNamesSettlePerTarget(t *testing.T) {
	lp := lookupLP(t)
	qc := newQueueClient(
		scanCmd("rev1", "normal", map[string]any{"scanner": "dnsx", "capability": "resolve.dns@1",
			"targets": []string{"gone.example.com", "old.example.com"}}),
		scanCmd("rev2", "normal", map[string]any{"scanner": "nuclei", "capability": "scan.ports@1", "outcome_revision": 2,
			"targets": []string{"dead.example.com"}}),
	)
	e := &payloadExecutor{}
	p := NewCommandPoller(qc, e, &CommandPollerConfig{MaxConcurrent: 4})
	p.SetLocalPolicy(lp)
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()

	qc.mu.Lock()
	defer qc.mu.Unlock()
	if len(e.payloads) != 0 {
		t.Fatalf("the executor ran %v", e.payloads)
	}
	r1 := qc.full["rev1"]
	if r1 == nil || r1.Status != "completed" || r1.Refusal != nil {
		t.Fatalf("rev1 %+v", r1)
	}
	listed, _ := r1.Metadata[MetaRefusedTargets].([]RefusedTarget)
	if len(listed) != 2 || listed[0].Reason != RefusedTargetUnresolvable || listed[0].DNS != "name_gone" ||
		r1.Metadata[MetaRefusedTargetsTotal] != 2 {
		t.Fatalf("rev1 metadata %+v", r1.Metadata)
	}
	if len(r1.TargetOutcomes) != 2 || r1.TargetOutcomes[0] != (outcome.Target{Target: "gone.example.com", State: outcome.Skipped, Class: outcome.Refused}) {
		t.Fatalf("rev1 outcomes %+v", r1.TargetOutcomes)
	}
	r2 := qc.full["rev2"]
	if r2 == nil || r2.Status != "completed" || len(r2.TargetOutcomes) != 1 {
		t.Fatalf("rev2 %+v", r2)
	}
	if o := r2.TargetOutcomes[0]; o.State != outcome.Failed || o.Class != outcome.NameGone || o.Cause != outcome.CauseTarget {
		t.Fatalf("rev2 outcome %+v", o)
	}
	raw, _ := json.Marshal(r2)
	if !json.Valid(raw) {
		t.Fatal("result does not marshal")
	}
}

// The executor's own check (right before the tool starts) reads a lookup-only
// job's dead names the same way: a dead name under an allowed domain is
// listed unresolvable, one outside them is denied, and neither reaches the
// tool.
func TestDefaultCommandExecutor_LookupOnlyDeadNames(t *testing.T) {
	sc := &listRecorder{}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(capListRecorder{sc})
	e.SetLocalPolicy(lookupLP(t))
	res, err := e.Execute(context.Background(), scanCommand(t, ScanCommandPayload{Scanner: "nuclei", Capability: "resolve.dns@1",
		Targets: []string{"203.0.113.5", "gone.example.com", "dead.other.test"}}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sc.list, []string{"203.0.113.5"}) {
		t.Fatalf("the tool got %v", sc.list)
	}
	listed, _ := res.Metadata[MetaRefusedTargets].([]RefusedTarget)
	got := map[string]string{}
	for _, r := range listed {
		got[r.Target] = r.Reason
	}
	if got["gone.example.com"] != RefusedTargetUnresolvable || got["dead.other.test"] != RefusedTargetUnresolvable {
		t.Fatalf("refused %+v", listed)
	}
}

// capListRecorder is a listRecorder that runs capability jobs.
type capListRecorder struct{ *listRecorder }

func (capListRecorder) TakesCapabilityJobs() bool { return true }

func TestRegistryOnlyCapability(t *testing.T) {
	for _, c := range capability.All() {
		want := c.ID == "lookup.rdap"
		if got := RegistryOnlyCapability(c.ID + "@" + strconv.Itoa(c.Major)); got != want {
			t.Errorf("%s: registry-only %v, want %v", c.ID, got, want)
		}
		// Never a capability that connects to its targets.
		if RegistryOnlyCapability(c.ID) && c.TierFloor > 0 {
			t.Errorf("%s: a registry-only capability must be passive", c.ID)
		}
	}
	for _, c := range []string{"", "lookup", "lookup.rdap.extra", "scan.ports", "resolve.dns"} {
		if RegistryOnlyCapability(c) {
			t.Errorf("%q must not be registry-only", c)
		}
	}
}

// A registry lookup (RDAP) asks the registry, never the target: a name that
// does not resolve is handed to the tool, not refused as unresolvable. The
// domain deny list and the allowed domains still apply by name.
func TestAdmitCommandTargets_RegistryOnlyTakesNamesThatDoNotResolve(t *testing.T) {
	lp := lookupLP(t)
	cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "capability": "lookup.rdap@1",
		"targets": []string{"example.com", "gone.example.com", "blocked.example.com", "dead.other.test"}})
	adm, err := lp.AdmitCommandTargets(context.Background(), cmd)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"example.com", "gone.example.com"}) {
		t.Fatalf("payload targets %v", got)
	}
	r := refusedBy(adm)
	if len(r) != 2 {
		t.Fatalf("refused %+v", adm.Refused)
	}
	if b := r["blocked.example.com"]; b.Reason != RefusedTargetDenied || b.Rule != "targets.deny" {
		t.Fatalf("blocked.example.com %+v", b)
	}
	// Outside the allowed domains a name needs addresses in the allowed
	// ranges, and has none.
	if d := r["dead.other.test"]; d.Reason != RefusedTargetUnresolvable {
		t.Fatalf("dead.other.test %+v", d)
	}

	// The same names for a capability that connects: the dead one is refused.
	cmd = cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "capability": "scan.ports@1",
		"targets": []string{"example.com", "gone.example.com"}})
	adm, err = lp.AdmitCommandTargets(context.Background(), cmd)
	if err != nil || !slices.Equal(payloadTargets(t, cmd), []string{"example.com"}) || len(adm.Refused) != 1 {
		t.Fatalf("connecting: %+v %v", adm, err)
	}
}

// A policy with no allow list: every name passes by name, a deny still
// refuses, and an address literal is checked as ever (a blocked range stays
// blocked).
func TestAdmitCommandTargets_RegistryOnlyWithoutAllowList(t *testing.T) {
	lp, err := ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  deny: [\"blocked.example.com\"]\nchecks:\n  allow: [scan]\n"),
		LocalPolicyOptions{LookupEnv: env(nil), LookupIP: lookupDNS})
	if err != nil {
		t.Fatal(err)
	}
	cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "capability": "lookup.rdap@1",
		"targets": []string{"anything.test", "blocked.example.com", "127.0.0.1"}})
	adm, err := lp.AdmitCommandTargets(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"anything.test"}) {
		t.Fatalf("payload targets %v (refused %+v)", got, adm.Refused)
	}
}

// The executor's own check right before the tool starts takes the same
// view: a name that does not resolve reaches a registry-only tool, and a
// connecting tool never gets it.
func TestDefaultCommandExecutor_RegistryOnlyTakesDeadNames(t *testing.T) {
	run := func(capability string) ([]string, []RefusedTarget) {
		sc := &listRecorder{}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(capListRecorder{sc})
		e.SetLocalPolicy(lookupLP(t))
		res, err := e.Execute(context.Background(), scanCommand(t, ScanCommandPayload{Scanner: "nuclei", Capability: capability,
			Targets: []string{"203.0.113.5", "gone.example.com", "blocked.example.com"}}))
		if err != nil {
			t.Fatal(err)
		}
		listed, _ := res.Metadata[MetaRefusedTargets].([]RefusedTarget)
		return sc.list, listed
	}
	got, refused := run("lookup.rdap@1")
	if !slices.Equal(got, []string{"203.0.113.5", "gone.example.com"}) {
		t.Fatalf("the tool got %v", got)
	}
	if len(refused) != 1 || refused[0].Target != "blocked.example.com" {
		t.Fatalf("refused %+v", refused)
	}
	got, _ = run("scan.ports@1")
	if !slices.Equal(got, []string{"203.0.113.5"}) {
		t.Fatalf("connecting: the tool got %v", got)
	}
}
