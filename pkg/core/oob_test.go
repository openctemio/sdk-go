package core

import (
	"testing"
)

// A job's request for callbacks: on unless the policy turns them off, and
// then off with the reason instead of a refusal.
func TestApplyJobConfigOOB(t *testing.T) {
	ask := map[string]interface{}{"allow_interactsh": true}
	cases := []struct {
		name       string
		policy     func(t *testing.T) *LocalPolicy
		config     map[string]interface{}
		wantOn     bool
		wantReason string
	}{
		{name: "no policy object", policy: func(*testing.T) *LocalPolicy { return nil }, config: ask, wantOn: true},
		{name: "legacy install without a policy", policy: func(t *testing.T) *LocalPolicy { return absentPolicyFor(t, false, nil) }, config: ask, wantOn: true},
		{name: "policy without the key follows the platform", policy: func(t *testing.T) *LocalPolicy {
			return mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n")
		}, config: ask, wantOn: true},
		{name: "explicit true", policy: func(t *testing.T) *LocalPolicy {
			return mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nallow_interactsh: true\n")
		}, config: ask, wantOn: true},
		{name: "explicit false narrows", policy: func(t *testing.T) *LocalPolicy {
			return mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nallow_interactsh: false\n")
		}, config: ask, wantReason: OOBReasonLocalPolicy},
		{name: "required and absent narrows", policy: func(t *testing.T) *LocalPolicy { return absentPolicyFor(t, true, nil) }, config: ask, wantReason: OOBReasonLocalPolicy},
		{name: "job does not ask", policy: func(t *testing.T) *LocalPolicy {
			return mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nallow_interactsh: false\n")
		}, config: map[string]interface{}{"allow_interactsh": false}},
		{name: "only a boolean asks", policy: func(*testing.T) *LocalPolicy { return nil }, config: map[string]interface{}{"allow_interactsh": "true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &ScanOptions{}
			if err := applyJobConfig(opts, tc.config, tc.policy(t)); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if opts.AllowInteractsh != tc.wantOn || opts.OOBOffReason != tc.wantReason {
				t.Fatalf("allow %t reason %q, want %t %q", opts.AllowInteractsh, opts.OOBOffReason, tc.wantOn, tc.wantReason)
			}
		})
	}
}

func TestOOBMetadata(t *testing.T) {
	if m := OOBMetadata(nil); len(m) != 0 {
		t.Fatalf("nil result: %v", m)
	}
	if m := OOBMetadata(&ScanResult{}); len(m) != 0 {
		t.Fatalf("no state: %v", m)
	}
	st := OOBOffState(OOBReasonNoServer)
	m := OOBMetadata(&ScanResult{OOB: st})
	got, ok := m[MetaOOB].(*OOBState)
	if !ok || got.State != OOBUnavailable || got.Reason != OOBReasonNoServer || got.Detail == "" || got == st {
		t.Fatalf("metadata %#v", m)
	}
	for _, r := range []string{OOBReasonNoServer, OOBReasonLocalPolicy, OOBReasonUnconfined, OOBReasonRegistration, OOBReasonDisabled} {
		if OOBOffState(r).Detail == "" {
			t.Errorf("%s has no detail", r)
		}
	}
}
