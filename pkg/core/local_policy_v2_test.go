package core

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Owner decision D13 (negative): schema v1 is frozen. A v1 file with a key
// that only v2 has is refused, exactly as every v1-only sensor (v0.9.x)
// refuses it, so a file that works here cannot work by accident on one
// sensor and stop another.
func TestLocalPolicy_V1IsFrozen(t *testing.T) {
	for _, doc := range []string{
		"apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: false}\n",
		"apiVersion: openctem.io/sensor-policy/v1\nmanaged: {}\n",
	} {
		if _, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{}); err == nil || !strings.Contains(err.Error(), "managed") {
			t.Errorf("v1 with a v2 key: %v", err)
		}
	}
	lp := mustPolicy(t, fullPolicy)
	if lp.Schema() != "v1" || !lp.AcceptsManagedPolicy() {
		t.Errorf("v1: schema %q, managed accepted %v", lp.Schema(), lp.AcceptsManagedPolicy())
	}
}

// Schema v2 reads every v1 key unchanged, plus managed.accept; it is
// strict too (an unknown key, a v3 key, is refused).
func TestLocalPolicy_V2(t *testing.T) {
	v2 := strings.Replace(fullPolicy, "sensor-policy/v1", "sensor-policy/v2", 1)
	lp1, lp2 := mustPolicy(t, fullPolicy), mustPolicy(t, v2)
	r1, r2 := lp1.Report(), lp2.Report()
	// Same rules: only the digest, the schema differ.
	s1, s2 := *r1.Summary, *r2.Summary
	if !slices.Equal(s1.Tools, s2.Tools) || s1.TargetsAllow != s2.TargetsAllow || s1.Ports != s2.Ports || s1.MaxRPS != s2.MaxRPS || s1.AllowInteractsh != s2.AllowInteractsh {
		t.Errorf("v2 reads the v1 keys differently:\n%+v\n%+v", s1, s2)
	}
	if r2.Schema != "v2" || r1.Schema != "v1" || !s2.ManagedAccept {
		t.Errorf("schemas %q/%q, managed_accept %v", r1.Schema, r2.Schema, s2.ManagedAccept)
	}
	if !slices.Equal(r2.Schemas, []string{"v1", "v2", "v3"}) || !slices.Equal(lp1.Report().Schemas, []string{"v1", "v2", "v3"}) {
		t.Errorf("supported schemas not reported: %v", r2.Schemas)
	}

	locked := mustPolicy(t, v2+"managed:\n  accept: false\n")
	if locked.AcceptsManagedPolicy() || locked.Report().Summary.ManagedAccept {
		t.Error("managed.accept: false not honored")
	}
	for _, bad := range []string{
		"apiVersion: openctem.io/sensor-policy/v2\nmanaged: {accept: false, require_signed: true}\n",
		"apiVersion: openctem.io/sensor-policy/v2\ntiers: {max: T2}\n",
		"apiVersion: openctem.io/sensor-policy/v2\nmanaged: {accept: maybe}\n",
		"apiVersion: openctem.io/sensor-policy/v9\n",
		"apiVersion: openctem.io/sensor-policy/v2\nhttp: {user_agent: x}\n",
		"apiVersion: [openctem.io/sensor-policy/v2]\n",
	} {
		if _, err := ParseLocalPolicy([]byte(bad), LocalPolicyOptions{}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// Absent policy and the shorthand accept managed documents and report
	// the supported schemas.
	if !(*LocalPolicy)(nil).AcceptsManagedPolicy() || absentPolicy().Report().Schemas == nil {
		t.Error("absent policy")
	}
}

// The absent-policy warning says what actually happens (api research/25
// §0.5): callbacks only when a job asks, custom templates only with pinned
// keys. It said both "are allowed".
func TestAbsentPolicyWarningIsAccurate(t *testing.T) {
	w := strings.Join(absentPolicy().Warnings(), "\n")
	if !strings.Contains(w, "jobs may enable out-of-band callbacks") || !strings.Contains(w, "SENSOR_TEMPLATE_SIGNING_KEYS") || strings.Contains(w, "are allowed") {
		t.Errorf("warning: %s", w)
	}
}

// Owner decision D10: a reload that loads replaces the policy; one that
// does not engages the kill switch (never keeps the previous, possibly
// looser, policy silently) and says why; a later good reload releases it.
func TestReloadLocalPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor-policy.yaml")
	write := func(doc string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	opts := LocalPolicyOptions{Path: path, LookupEnv: func(string) (string, bool) { return "", false }}
	write("apiVersion: openctem.io/sensor-policy/v1\ntools: {allow: [nuclei]}\n", 0o644)
	lp, err := LoadLocalPolicy(opts)
	if err != nil {
		t.Fatal(err)
	}

	write("apiVersion: openctem.io/sensor-policy/v2\ntools: {allow: [nuclei, httpx]}\nmanaged: {accept: false}\n", 0o644)
	next, err := ReloadLocalPolicy(lp, opts)
	if err != nil || next.Schema() != "v2" || !next.AllowsTool("httpx") || next.KillSwitchEngaged() {
		t.Fatalf("good reload: %v schema %q", err, next.Schema())
	}

	for name, bad := range map[string]func(){
		"typo":           func() { write("apiVersion: openctem.io/sensor-policy/v1\ntool: {allow: [x]}\n", 0o644) },
		"world-writable": func() { write("apiVersion: openctem.io/sensor-policy/v1\n", 0o666) },
		"v2 key in v1":   func() { write("apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: true}\n", 0o644) },
		"removed":        func() { _ = os.Remove(path) },
		"two documents":  func() { write("apiVersion: openctem.io/sensor-policy/v1\n---\nkill_switch: false\n", 0o644) },
		"empty":          func() { write("\n", 0o644) },
		"garbage":        func() { write("\x00\xff{{{", 0o644) },
		"oversize": func() {
			write("apiVersion: openctem.io/sensor-policy/v1\n#"+strings.Repeat("x", MaxLocalPolicyBytes)+"\n", 0o644)
		},
		"unknown version": func() { write("apiVersion: openctem.io/sensor-policy/v9\n", 0o644) },
	} {
		bad()
		failed, err := ReloadLocalPolicy(next, opts)
		if err == nil {
			t.Errorf("%s: reload succeeded", name)
			continue
		}
		if !failed.KillSwitchEngaged() || !failed.Report().KillSwitch {
			t.Errorf("%s: kill switch not engaged", name)
		}
		if w := strings.Join(failed.Warnings(), " "); !strings.Contains(w, "reload failed") {
			t.Errorf("%s: no warning: %s", name, w)
		}
		// The previous rules stay (narrowing is never lost) and the
		// previous policy object is not modified.
		if !failed.AllowsTool("httpx") || failed.AllowsTool("semgrep") || next.KillSwitchEngaged() {
			t.Errorf("%s: rules changed", name)
		}
		var lpe *LocalPolicyError
		if err := failed.AdmitCommand(t.Context(), &Command{ID: "x", Type: "scan", Payload: []byte(`{"scanner":"nuclei","target":"203.0.113.1"}`)}); !errors.As(err, &lpe) || lpe.Rule != "kill_switch" {
			t.Errorf("%s: command admitted: %v", name, err)
		}
	}

	write("apiVersion: openctem.io/sensor-policy/v1\ntools: {allow: [nuclei]}\n", 0o644)
	failed, _ := ReloadLocalPolicy(next, LocalPolicyOptions{Path: filepath.Join(dir, "missing.yaml")})
	fixed, err := ReloadLocalPolicy(failed, opts)
	if err != nil || fixed.KillSwitchEngaged() {
		t.Fatalf("fixed reload: %v, kill switch %v", err, fixed.KillSwitchEngaged())
	}
	// From no policy at all, a failed reload engages the kill switch too.
	if f, err := ReloadLocalPolicy(nil, LocalPolicyOptions{Path: filepath.Join(dir, "missing.yaml")}); err == nil || !f.KillSwitchEngaged() {
		t.Error("failed reload from no policy")
	}
}

// Schema v3 adds http: the network owner can force the tools User-Agent
// and forbid skipping TLS verification; v1 and v2 files cannot.
func TestLocalPolicy_V3HTTP(t *testing.T) {
	if ua, ok := (*LocalPolicy)(nil).HTTPPolicy(); ua != "" || !ok {
		t.Fatalf("no policy: %q %v", ua, ok)
	}
	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v3\nhttp:\n  user_agent: \"acme-security-scan (+soc@acme.example)\"\n  allow_insecure_tls: false\nmanaged: {accept: false}\n")
	if ua, ok := lp.HTTPPolicy(); ua != "acme-security-scan (+soc@acme.example)" || ok {
		t.Fatalf("v3 http: %q %v", ua, ok)
	}
	if lp.Schema() != "v3" || lp.AcceptsManagedPolicy() {
		t.Fatalf("v3 keeps the v2 keys: schema %s managed %v", lp.Schema(), lp.AcceptsManagedPolicy())
	}
	if ua, ok := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v3\n").HTTPPolicy(); ua != "" || !ok {
		t.Fatalf("v3 without http: %q %v", ua, ok)
	}
	for _, bad := range []string{"\"\"", "\"a\\nb\""} {
		if _, err := ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v3\nhttp: {user_agent: "+bad+"}\n"), LocalPolicyOptions{}); err == nil {
			t.Errorf("user_agent %s accepted", bad)
		}
	}
}
