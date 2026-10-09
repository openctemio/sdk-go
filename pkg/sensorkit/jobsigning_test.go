package sensorkit

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

func pinJobKeysOnIdentity(t *testing.T, stateDir string, keys ...jobsig.PublicKey) {
	t.Helper()
	st := identity.NewStore(stateDir)
	id, _, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	id.JobSigningKeys = keys
	if err := st.Save(id); err != nil {
		t.Fatal(err)
	}
}

// Signed jobs are required for an identity that pinned the signer's keys
// at pairing; SENSOR_REQUIRE_SIGNED_JOBS overrides; a legacy identity
// verifies nothing unless keys are pinned in the environment.
func TestNew_JobSigningPosture(t *testing.T) {
	key := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name    string
		pinned  bool
		envKeys string
		require string
		want    string
		log     string
		failure string
	}{
		{name: "new identity", pinned: true, want: core.JobsSignedRequired, log: "Signed jobs: required (paired by this SDK)"},
		{name: "env false", pinned: true, require: "false", want: core.JobsSignedVerifiedWhenPresent, log: "verified when present"},
		{name: "legacy identity", want: core.JobsSignedOff},
		{name: "legacy identity, env keys", envKeys: key.KeyID, want: core.JobsSignedVerifiedWhenPresent, log: key.KeyID},
		{name: "legacy identity, env keys, required", envKeys: key.PublicKey, require: "true", want: core.JobsSignedRequired,
			log: "required (" + core.EnvRequireSignedJobs + "=true)"},
		{name: "required without a key", require: "true", failure: "no job-signing key or root is pinned"},
		{name: "bad key", envKeys: "SHA256:00", failure: EnvJobSigningKeys},
		{name: "bad require", require: "maybe", failure: core.EnvRequireSignedJobs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { core.SetJobsPosture("") })
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			opts, out, errw := baseOptions(t, f)
			opts.APIKey = ""
			pairedStore(t, opts.StateDir)
			if tc.pinned {
				pinJobKeysOnIdentity(t, opts.StateDir, key)
			}
			if tc.envKeys != "" {
				t.Setenv(EnvJobSigningKeys, tc.envKeys)
			}
			if tc.require != "" {
				t.Setenv(core.EnvRequireSignedJobs, tc.require)
			}
			k, err := New(opts)
			if tc.failure != "" {
				if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), tc.failure) {
					t.Fatalf("err = %v, want a usage error naming %q", err, tc.failure)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.closeClient)
			if got := k.s.jobs.Posture(); got != tc.want {
				t.Fatalf("posture %s, want %s", got, tc.want)
			}
			if p := k.sensor.Posture(); p == nil || p.Jobs == nil || p.Jobs.Signed != tc.want {
				t.Fatalf("manifest posture %+v", p)
			}
			if tc.log != "" && !strings.Contains(out.String()+errw.String(), tc.log) {
				t.Fatalf("log lacks %q:\nstdout %s\nstderr %s", tc.log, out.String(), errw.String())
			}
		})
	}
}

// A bearer-key sensor does not know its own organization: pinning job keys
// there is refused at start rather than verified against nothing.
func TestNew_JobSigningNeedsAPairedSensor(t *testing.T) {
	t.Cleanup(func() { core.SetJobsPosture("") })
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	t.Setenv(EnvJobSigningKeys, "SHA256:"+strings.Repeat("ab", 32))
	if _, err := New(opts); err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "paired") {
		t.Fatalf("err = %v", err)
	}
}

// A root pinned at pairing makes signed jobs required and replaces the
// keys pinned at pairing; SENSOR_JOB_SIGNING_ROOT overrides it; a bad root
// stops the start.
func TestNew_JobSigningRoot(t *testing.T) {
	key := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey))
	idRoot := "SHA256:" + strings.Repeat("ab", 32)
	envRoot := "SHA256:" + strings.Repeat("cd", 32)
	for _, tc := range []struct {
		name, env, wantRoot, failure string
	}{
		{name: "identity root", wantRoot: idRoot},
		{name: "env root overrides", env: envRoot, wantRoot: envRoot},
		{name: "bad env root", env: "SHA256:00", failure: EnvJobSigningRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { core.SetJobsPosture(""); core.SetJobsKeySet(nil) })
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			opts, out, errw := baseOptions(t, f)
			opts.APIKey = ""
			pairedStore(t, opts.StateDir)
			st := identity.NewStore(opts.StateDir)
			id, _, err := st.Load()
			if err != nil {
				t.Fatal(err)
			}
			id.JobSigningKeys, id.JobSigningRoot = []jobsig.PublicKey{key}, idRoot
			if err := st.Save(id); err != nil {
				t.Fatal(err)
			}
			if tc.env != "" {
				t.Setenv(EnvJobSigningRoot, tc.env)
			}
			k, err := New(opts)
			if tc.failure != "" {
				if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), tc.failure) {
					t.Fatalf("err = %v, want a usage error naming %q", err, tc.failure)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.closeClient)
			if got := k.s.jobs.Posture(); got != core.JobsSignedRequired {
				t.Fatalf("posture %s", got)
			}
			p := k.sensor.Posture()
			if p == nil || p.Jobs == nil || p.Jobs.Root != tc.wantRoot || p.Jobs.KeySetExpiresAt != nil {
				t.Fatalf("posture %+v", p.Jobs)
			}
			logs := out.String() + errw.String()
			if !strings.Contains(logs, "the key set of root "+tc.wantRoot) || strings.Contains(logs, key.KeyID) ||
				!strings.Contains(logs, "no job-signing key set") {
				t.Fatalf("log:\n%s", logs)
			}
		})
	}
}

// A sensor that requires signed jobs trusts custom templates through the
// verified job statement: its config report does not ask for
// SENSOR_TEMPLATE_SIGNING_KEYS. One that only verifies when present still
// needs them for unsigned jobs.
func TestNew_TemplateKeysCheckWithSignedJobs(t *testing.T) {
	key := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32)).Public().(ed25519.PublicKey))
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\n"+
		"targets:\n  allow: [\"203.0.113.0/24\"]\nallow_custom_templates: true\n"), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		require string
		want    string
	}{
		{name: "signed jobs required", want: "not_needed"},
		{name: "verified when present", require: "false", want: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { core.SetJobsPosture("") })
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			opts, _, _ := baseOptions(t, f)
			opts.APIKey = ""
			opts.LocalPolicy = lp
			pairedStore(t, opts.StateDir)
			pinJobKeysOnIdentity(t, opts.StateDir, key)
			if tc.require != "" {
				t.Setenv(core.EnvRequireSignedJobs, tc.require)
			}
			k, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.closeClient)
			if got := checkCode(k, CheckTemplateKeys); got != tc.want {
				t.Fatalf("%s = %q, want %q", CheckTemplateKeys, got, tc.want)
			}
		})
	}
}
