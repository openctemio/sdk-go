package core

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/openctemio/contract/capability"
)

// An allow list of public ranges only (no allowed domains), as a host that
// scans the public internet carries.
const rangesOnlyPolicy = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["198.51.100.0/24", "203.0.113.0/24"]
  deny: ["203.0.113.66"]
tools:
  allow: [nuclei, dnsx, naabu, httpx]
checks:
  allow: [scan]
`

func rangesOnlyDNS(_ context.Context, host string) ([]net.IP, error) {
	switch host {
	case "inside.example.org":
		return []net.IP{net.ParseIP("198.51.100.7")}, nil
	case "outside.example.org":
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	case "denied.example.org":
		return []net.IP{net.ParseIP("203.0.113.66")}, nil
	case "flaky.example.org":
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// A name the allow list cannot match because it does not resolve is
// unresolvable, never denied_by_policy; a name that resolves outside the
// allowed ranges, or to a denied address, stays denied_by_policy. Fail-closed
// is unchanged: every one of these is removed from the job.
func TestRefusalReason_UnresolvableVersusDenied(t *testing.T) {
	lp, err := ParseLocalPolicy([]byte(rangesOnlyPolicy), LocalPolicyOptions{LookupEnv: env(nil), LookupIP: rangesOnlyDNS})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		target, reason, rule string
	}{
		{"pop.pti.example", RefusedTargetUnresolvable, ""},
		{"flaky.example.org", RefusedTargetUnresolvable, ""},
		{"https://portal.pti.example/login", RefusedTargetUnresolvable, ""},
		{"outside.example.org", RefusedTargetDenied, "targets.allow"},
		{"192.0.2.9", RefusedTargetDenied, "targets.allow"},
		{"denied.example.org", RefusedTargetDenied, "targets.deny"},
		{"203.0.113.66", RefusedTargetDenied, "targets.deny"},
	}
	for _, c := range capability.All() {
		ref := c.ID + "@" + strconv.Itoa(c.Major)
		for _, tc := range cases {
			t.Run(ref+"/"+tc.target, func(t *testing.T) {
				cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "capability": ref,
					"targets": []string{"inside.example.org", tc.target}})
				adm, err := lp.AdmitCommandTargets(context.Background(), cmd)
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				r, ok := refusedBy(adm)[tc.target]
				if !ok {
					t.Fatalf("%s was admitted: %+v", tc.target, adm.Refused)
				}
				if r.Reason != tc.reason || (tc.rule != "" && r.Rule != tc.rule) {
					t.Fatalf("%s: reason %q rule %q, want %q %q", tc.target, r.Reason, r.Rule, tc.reason, tc.rule)
				}
				for _, got := range payloadTargets(t, cmd) {
					if got == tc.target {
						t.Fatalf("%s reached the tool", got)
					}
				}
			})
		}
	}
}

// A job whose every name is dead settles per target (reason unresolvable)
// for the lookup-only capability even when no allowed domain matches.
func TestRefusalReason_AllDeadSettles(t *testing.T) {
	lp, err := ParseLocalPolicy([]byte(rangesOnlyPolicy), LocalPolicyOptions{LookupEnv: env(nil), LookupIP: rangesOnlyDNS})
	if err != nil {
		t.Fatal(err)
	}
	cmd := cmdWith("c", "scan", map[string]any{"scanner": "dnsx", "capability": "resolve.dns@1",
		"targets": []string{"pop.pti.example", "portal.pti.example"}})
	adm, err := lp.AdmitCommandTargets(context.Background(), cmd)
	if err != nil {
		t.Fatalf("a job of dead names must not be refused: %v", err)
	}
	if !adm.Settled || len(adm.Refused) != 2 {
		t.Fatalf("admission %+v", adm)
	}
	for _, r := range adm.Refused {
		if r.Reason != RefusedTargetUnresolvable {
			t.Fatalf("%+v", r)
		}
	}
}
