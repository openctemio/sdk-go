package sensorkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

// requireOnIdentity marks the stored identity as paired by an SDK that fails
// closed, as pairing now writes it.
func requireOnIdentity(t *testing.T, stateDir string) {
	t.Helper()
	st := identity.NewStore(stateDir)
	id, _, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	id.RequireLocalPolicy = true
	if err := st.Save(id); err != nil {
		t.Fatal(err)
	}
}

func checkCode(k *Kit, id string) string {
	for _, c := range k.ConfigReport().Checks {
		if c.ID == id {
			return c.Code
		}
	}
	return ""
}

// A sensor paired by this SDK fails closed without a local policy; one
// paired before (no flag in identity.json) keeps the legacy behavior.
func TestNew_PairedIdentityRequiresLocalPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		flag     bool
		env      string
		required bool
		log      string
	}{
		{name: "new identity", flag: true, required: true, log: "Local policy mode: fail closed (paired by this SDK)"},
		{name: "legacy identity", flag: false, required: false, log: "local policy mode: legacy install"},
		{name: "env false wins", flag: true, env: "false", required: false, log: "legacy (" + core.EnvRequireLocalPolicy + "=false)"},
		{name: "env true wins", flag: false, env: "true", required: true, log: "fail closed (" + core.EnvRequireLocalPolicy + "=true)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			opts, out, errw := baseOptions(t, f)
			opts.APIKey = ""
			pairedStore(t, opts.StateDir)
			if tc.flag {
				requireOnIdentity(t, opts.StateDir)
			}
			if tc.env != "" {
				t.Setenv(core.EnvRequireLocalPolicy, tc.env)
			}
			k, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.closeClient)
			lp := k.LocalPolicy()
			if lp.Present() || lp.Required() != tc.required || lp.Report().Required != tc.required {
				t.Fatalf("present %t required %t", lp.Present(), lp.Required())
			}
			if !strings.Contains(out.String()+errw.String(), tc.log) {
				t.Fatalf("log lacks %q:\nstdout %s\nstderr %s", tc.log, out.String(), errw.String())
			}
			want := "absent"
			if tc.required {
				want = "required_absent"
			}
			if got := checkCode(k, CheckLocalPolicy); got != want {
				t.Fatalf("config check %s = %q, want %q", CheckLocalPolicy, got, want)
			}
			// What the sensor hands the platform: the requirement, and the
			// posture on its manifest.
			if p := k.sensor.Posture(); p == nil || p.PlatformTLS == nil || p.PlatformTLS.Pin != core.TLSPinNone || p.Sandbox == nil {
				t.Fatalf("posture %+v", p)
			}
			// A policy installed later keeps the requirement; so does a
			// reload.
			k.SetLocalPolicy(lp.WithRequired(false))
			if k.LocalPolicy().Required() != tc.required {
				t.Fatal("SetLocalPolicy dropped the requirement")
			}
			got, err := k.ReloadLocalPolicy(core.LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml")})
			if err != nil || got.Required() != tc.required {
				t.Fatalf("reload: required %t, %v", got.Required(), err)
			}
		})
	}
}

// A bearer-key sensor has no identity: legacy unless the operator opts in.
func TestNew_BearerKeyIsLegacy(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.closeClient)
	if k.LocalPolicy().Required() {
		t.Fatal("a bearer-key sensor requires a local policy by default")
	}
	t.Setenv(core.EnvRequireLocalPolicy, "maybe")
	if _, err := New(opts); err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), core.EnvRequireLocalPolicy) {
		t.Fatalf("an unreadable %s: %v", core.EnvRequireLocalPolicy, err)
	}
}

// identity.json written by an SDK without the flag reads as legacy; the
// flag round-trips.
func TestResolveRequireLocalPolicy_IdentityFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	id := pairedStore(t, dir)
	path := filepath.Join(dir, identity.DirName, identity.IdentityFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "require_local_policy") {
		t.Fatalf("an identity without the flag writes it: %s", raw)
	}
	// An identity file exactly as an older SDK wrote it.
	old := map[string]any{"platform_url": "https://platform.example.com", "sensor_id": id.SensorID, "tenant_id": "t",
		"name": "paired-01", "key_id": id.KeyID, "paired_at": "2026-01-02T03:04:05Z"}
	b, _ := json.Marshal(old)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := identity.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if req, _, err := ResolveRequireLocalPolicy(got); err != nil || req {
		t.Fatalf("an old identity requires a policy: %t %v", req, err)
	}
	requireOnIdentity(t, dir)
	got, _, err = identity.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if req, from, err := ResolveRequireLocalPolicy(got); err != nil || !req || from != requireFromIdentity {
		t.Fatalf("a new identity: %t %q %v", req, from, err)
	}
	if req, _, _ := ResolveRequireLocalPolicy(nil); req {
		t.Fatal("no identity requires a policy")
	}
}
