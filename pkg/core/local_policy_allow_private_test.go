package core

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Every local policy report says whether private targets are admitted,
// absent policy included, so the platform can stop routing private targets
// to a sensor that would refuse them (research 466 D8).
func TestLocalPolicyReport_AllowPrivateOnEveryReport(t *testing.T) {
	const filePrivate = "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow_private: true\n"
	const fileNoPrivate = "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  deny: [\"192.0.2.0/24\"]\n"
	cases := []struct {
		name     string
		switchOn bool
		required bool
		file     string
		want     bool
	}{
		{name: "absent, switch on", switchOn: true, want: true},
		{name: "absent, switch off", switchOn: false, want: false},
		{name: "absent and required, switch on", switchOn: true, required: true, want: false},
		{name: "file allows private, switch on", switchOn: true, file: filePrivate, want: true},
		{name: "file allows private, switch off", switchOn: false, file: filePrivate, want: false},
		{name: "file without allow_private, switch on", switchOn: true, file: fileNoPrivate, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]string{}
			if tc.switchOn {
				vars[EnvSensorAllowPrivateTargets] = "1"
				t.Setenv(EnvSensorAllowPrivateTargets, "1")
			} else {
				t.Setenv(EnvSensorAllowPrivateTargets, "")
			}
			var lp *LocalPolicy
			if tc.file != "" {
				var err error
				lp, err = ParseLocalPolicy([]byte(tc.file), LocalPolicyOptions{LookupEnv: env(vars)})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				lp, err = LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"), LookupEnv: env(vars)})
				if err != nil {
					t.Fatal(err)
				}
				lp = lp.WithRequired(tc.required)
			}
			r := lp.Report()
			if r.AllowPrivate != tc.want {
				t.Fatalf("allow_private = %t, want %t (report %+v)", r.AllowPrivate, tc.want, r)
			}
			if r.Summary != nil && r.Summary.AllowPrivate != r.AllowPrivate {
				t.Fatalf("summary allow_private %t disagrees with the report %t", r.Summary.AllowPrivate, r.AllowPrivate)
			}
			if got := !lp.NetworkScope().NoPrivate; got != tc.want {
				t.Fatalf("network scope private = %t, want %t", got, tc.want)
			}
			// The field is always on the wire, false included: a missing
			// field means an older SDK, not "refused".
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), `"allow_private":`) {
				t.Fatalf("allow_private missing from %s", b)
			}
		})
	}
}

// A nil policy (no policy loaded at all) follows the host switch.
func TestLocalPolicy_AllowsPrivateNil(t *testing.T) {
	var lp *LocalPolicy
	t.Setenv(EnvSensorAllowPrivateTargets, "1")
	if !lp.AllowsPrivate() {
		t.Fatal("nil policy with the switch on refuses private targets")
	}
	t.Setenv(EnvSensorAllowPrivateTargets, "")
	if lp.AllowsPrivate() {
		t.Fatal("nil policy with the switch off admits private targets")
	}
}

// The slim heartbeat keeps allow_private: the field is always on the wire,
// so dropping it would tell the platform "refused".
func TestSlimHeartbeat_KeepsAllowPrivate(t *testing.T) {
	t.Setenv(EnvSensorAllowPrivateTargets, "1")
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"), LookupEnv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	status := &SensorStatus{LocalPolicy: lp.Report()}
	slimHeartbeat(status)
	if !status.LocalPolicy.AllowPrivate {
		t.Fatal("the slim heartbeat drops allow_private")
	}
	if !status.LocalPolicy.AllowsPublic || !status.LocalPolicy.AllowsPrivate {
		t.Fatalf("the slim heartbeat drops allows_public or allows_private: %+v", status.LocalPolicy)
	}
}
