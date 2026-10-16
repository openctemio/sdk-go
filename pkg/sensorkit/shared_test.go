package sensorkit

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

// SECURITY: shared mode refuses to start with the sandbox or its network
// confinement switched down, and before the sensor pairs.
func TestSharedModeRefusesWeakerSandbox(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		name            string
		shared          bool
		env, sandbox    string
		sandboxNet      string
		wantErrContains string
	}{
		{"option, sandbox off", true, "", "off", "", EnvSandbox + "=off"},
		{"env, sandbox auto", false, "1", "auto", "", EnvSandbox + "=auto"},
		{"env, network off", false, "1", "", "off", EnvSandboxNetwork + "=off"},
		{"env, network auto", false, "1", "required", "auto", EnvSandboxNetwork + "=auto"},
		{"env, typo", false, "yes", "", "", EnvSharedMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv(EnvSharedMode, tc.env)
			t.Setenv(EnvSandboxNetwork, tc.sandboxNet)
			_, err := New(Options{Name: "shared", Version: "1.0.0", APIURL: srv.URL, Sandbox: tc.sandbox, Shared: tc.shared,
				LocalPolicyPath: writeSharedPolicy(t), StateDir: t.TempDir(), Outbox: OutboxSettings{Dir: t.TempDir()}})
			if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("want a refusal naming %s, got %v", tc.wantErrContains, err)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the platform got %d requests before the refusal", n)
	}
}

// SECURITY (acceptance): shared mode refuses to start where the host cannot
// give every sandbox control and network confinement; where it can, the
// backend is the shared one.
func TestSharedModeFailsClosedWithoutSandbox(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvSharedMode, "1")
	err := ValidateSandboxNetwork("")
	_, probe := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, Shared: true})
	if (err == nil) != (probe == nil) {
		t.Fatalf("validate %v, backend %v: they must agree", err, probe)
	}
	if err != nil && !strings.Contains(err.Error(), EnvSharedMode+"=1") {
		t.Fatalf("the refusal does not name shared mode: %v", err)
	}
}

// writeSharedPolicy writes a minimal local policy and returns its path.
func writeSharedPolicy(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sensor-policy.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [203.0.113.0/24]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// SECURITY: a shared sensor without a local policy refuses to start, before
// it pairs, whatever its sandbox: its targets come from many tenants and
// the operator's own policy is mandatory.
func TestSharedModeRequiresLocalPolicy(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	clearEnv(t)
	t.Setenv("HOME", t.TempDir())
	_, err := New(Options{Name: "shared", Version: "1.0.0", APIURL: srv.URL, Shared: true,
		LocalPolicy: absentLocalPolicy(t), StateDir: t.TempDir(), Outbox: OutboxSettings{Dir: t.TempDir()}})
	if err == nil || !strings.Contains(err.Error(), "local policy") {
		t.Fatalf("want the local policy refusal, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the platform got %d requests before the refusal", n)
	}
	// With a policy, the refusal (on a host without confinement) or the
	// start no longer names the policy.
	_, err = New(Options{Name: "shared", Version: "1.0.0", APIURL: srv.URL, Shared: true,
		LocalPolicyPath: writeSharedPolicy(t), StateDir: t.TempDir(), Outbox: OutboxSettings{Dir: t.TempDir()}})
	if err != nil && strings.Contains(err.Error(), "needs a local policy") {
		t.Fatalf("a policy was given: %v", err)
	}
}

func absentLocalPolicy(t *testing.T) *core.LocalPolicy {
	t.Helper()
	lp, err := core.LoadLocalPolicy(core.LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

func TestSharedModeFromEnv(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "1": true, " 1 ": true} {
		t.Setenv(EnvSharedMode, v)
		got, err := SharedModeFromEnv()
		if err != nil || got != want {
			t.Errorf("%q: %v %v", v, got, err)
		}
	}
	for _, v := range []string{"true", "yes", "on", "2"} {
		t.Setenv(EnvSharedMode, v)
		if _, err := SharedModeFromEnv(); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

// Shared mode checks every dispatched scan target with the job's zone
// rule, whatever scan target policy the sensor configured.
func TestSharedScanTargetPolicyKeepsSettings(t *testing.T) {
	p := sharedScanTargetPolicy(&core.ScanTargetPolicy{AllowedRoots: []string{"/scan"}, AllowPrivate: true, Disabled: true, AllowLoopback: true})
	if !p.Shared || p.Disabled || p.AllowLoopback || !p.AllowPrivate || len(p.AllowedRoots) != 1 {
		t.Fatalf("%+v", p)
	}
	if p := sharedScanTargetPolicy(nil); !p.Shared {
		t.Fatal("default policy is not shared")
	}
}

// SECURITY: an instance-scope (shared) identity never runs without shared
// mode, and shared mode never runs on an organization sensor's identity.
func TestCheckSharedIdentity(t *testing.T) {
	instance := &identity.Identity{SensorID: "s", Scope: pairing.ScopeInstance}
	org := &identity.Identity{SensorID: "s", TenantID: "t"}
	for _, tc := range []struct {
		name    string
		shared  bool
		id      *identity.Identity
		wantErr string
	}{
		{"instance identity, shared mode off", false, instance, EnvSharedMode + "=1"},
		{"organization identity, shared mode on", true, org, "belongs to an organization"},
		{"instance identity, shared mode on", true, instance, ""},
		{"organization identity, shared mode off", false, org, ""},
		{"no identity (API key), either mode", true, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSharedIdentity(tc.shared, tc.id)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want a usage error with %q", err, tc.wantErr)
			}
		})
	}
}
