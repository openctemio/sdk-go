package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// There is one schema, v1, with every key; any other apiVersion is refused.
func TestLocalPolicy_SingleSchema(t *testing.T) {
	all := `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["*"]
  deny: ["203.0.113.0/24"]
ports: {allow: "80,443"}
tools: {allow: [nuclei, httpx]}
managed: {accept: false}
http:
  user_agent: corp-scan
  allow_insecure_tls: false
  headers:
    - {name: X-Netops, value: dc1}
rate: {max_rps: 20}
`
	lp := mustPolicy(t, all)
	r := lp.Report()
	if r.Schema != "v1" || len(r.Schemas) != 1 || r.Schemas[0] != "v1" || len(r.Warnings) != 0 {
		t.Fatalf("report %+v", r)
	}
	if lp.AcceptsManagedPolicy() || r.Summary.Mode != "allow_all" || r.Summary.HTTPUserAgent != "corp-scan" || len(lp.HTTPHeaders()) != 1 || r.Summary.MaxRPS != 20 {
		t.Fatalf("v1 with every key: %+v", r.Summary)
	}
	// Only v1 exists: the older apiVersions are refused with a message
	// naming the one that is accepted.
	for _, v := range []string{"v2", "v3", "v4"} {
		_, err := ParseLocalPolicy([]byte(strings.Replace(all, "sensor-policy/v1", "sensor-policy/"+v, 1)), LocalPolicyOptions{})
		if err == nil || !strings.Contains(err.Error(), "must be openctem.io/sensor-policy/v1") || !strings.Contains(err.Error(), "set-policy") {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, bad := range []string{
		"apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: false, require_signed: true}\n",
		"apiVersion: openctem.io/sensor-policy/v1\ntiers: {max: T2}\n",
		"apiVersion: openctem.io/sensor-policy/v1\ntool: {allow: [x]}\n",
		"apiVersion: openctem.io/sensor-policy/v1\nhttp: {user_agnt: x}\n",
		"apiVersion: openctem.io/sensor-policy/v1\nmanaged: {accept: maybe}\n",
		"apiVersion: openctem.io/sensor-policy/v1\ntiers: {max: T2}\n",
		"apiVersion: openctem.io/sensor-policy/v9\n",
		"apiVersion: openctem.io/sensor-policy/v5\n",
		"apiVersion: [openctem.io/sensor-policy/v1]\n",
	} {
		if _, err := ParseLocalPolicy([]byte(strings.ReplaceAll(bad, "\\n", "\n")), LocalPolicyOptions{}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if !(*LocalPolicy)(nil).AcceptsManagedPolicy() || absentPolicy().Report().Schemas == nil {
		t.Error("absent policy")
	}
}

// A sensor that follows the platform's signed scope is the default mode, not
// something to fix: no warning. A required-but-absent policy still warns.
func TestAbsentPolicyDefaultHasNoWarning(t *testing.T) {
	if w := absentPolicy().Warnings(); len(w) != 0 {
		t.Errorf("default mode warns: %v", w)
	}
	if !strings.Contains(absentPolicy().Describe(), "follows the platform's signed scope") {
		t.Errorf("describe: %s", absentPolicy().Describe())
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

	write("apiVersion: openctem.io/sensor-policy/v1\ntools: {allow: [nuclei, httpx]}\nmanaged: {accept: false}\n", 0o644)
	next, err := ReloadLocalPolicy(lp, opts)
	if err != nil || next.Schema() != "v1" || !next.AllowsTool("httpx") || next.KillSwitchEngaged() {
		t.Fatalf("good reload: %v schema %q", err, next.Schema())
	}

	for name, bad := range map[string]func(){
		"typo":           func() { write("apiVersion: openctem.io/sensor-policy/v1\ntool: {allow: [x]}\n", 0o644) },
		"world-writable": func() { write("apiVersion: openctem.io/sensor-policy/v1\n", 0o666) },
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

// The http section: the network owner can force the tools User-Agent and
// forbid skipping TLS verification.
func TestLocalPolicy_V3HTTP(t *testing.T) {
	if ua, ok := (*LocalPolicy)(nil).HTTPPolicy(); ua != "" || !ok {
		t.Fatalf("no policy: %q %v", ua, ok)
	}
	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nhttp:\n  user_agent: \"acme-security-scan (+soc@acme.example)\"\n  allow_insecure_tls: false\nmanaged: {accept: false}\n")
	if ua, ok := lp.HTTPPolicy(); ua != "acme-security-scan (+soc@acme.example)" || ok {
		t.Fatalf("v3 http: %q %v", ua, ok)
	}
	if lp.Schema() != "v1" || lp.AcceptsManagedPolicy() {
		t.Fatalf("v1 keeps every key: schema %s managed %v", lp.Schema(), lp.AcceptsManagedPolicy())
	}
	if ua, ok := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n").HTTPPolicy(); ua != "" || !ok {
		t.Fatalf("v3 without http: %q %v", ua, ok)
	}
	for _, bad := range []string{"\"\"", "\"a\\nb\""} {
		if _, err := ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\nhttp: {user_agent: "+bad+"}\n"), LocalPolicyOptions{}); err == nil {
			t.Errorf("user_agent %s accepted", bad)
		}
	}
}

// The report names the http section, so the platform shows what the owner
// decided about the tools requests.
func TestLocalPolicy_V3HTTPReported(t *testing.T) {
	s := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nhttp: {user_agent: corp-scan, allow_insecure_tls: false}\n").Report().Summary
	if s.HTTPUserAgent != "corp-scan" || s.AllowInsecureTLS {
		t.Fatalf("summary %+v", s)
	}
	if s := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n").Report().Summary; s.HTTPUserAgent != "" || !s.AllowInsecureTLS {
		t.Fatalf("defaults %+v", s)
	}
}

const allowAllV2 = "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"*\"]\n"

// targets.allow: ["*"] (v2): every target the platform signs, still inside the
// built-in deny list, the deny entries and the private-range rule.
func TestLocalPolicy_AllowAll(t *testing.T) {
	lp := mustPolicy(t, allowAllV2+"  deny: [\"203.0.113.0/24\"]\n")
	r := lp.Report()
	if r.Schema != "v1" || r.Summary.Mode != "allow_all" || r.Summary.TargetsAllow != -1 {
		t.Fatalf("report %+v", r.Summary)
	}
	if d := lp.Describe(); !strings.Contains(d, "everything the platform signs") {
		t.Errorf("describe: %s", d)
	}
	ctx := t.Context()
	for _, ok := range []string{"198.51.100.7", "app.example.org"} {
		if err := lp.CheckTarget(ctx, ok); err != nil {
			t.Errorf("%s refused under allow-all: %v", ok, err)
		}
	}
	for _, no := range []string{"203.0.113.9", "169.254.169.254", "10.1.2.3", "imds.corp.example.com"} {
		if err := lp.CheckTarget(ctx, no); err == nil {
			t.Errorf("%s allowed under allow-all", no)
		}
	}
	if mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n").Report().Summary.Mode != "platform_scope" {
		t.Error("no allow list is platform_scope")
	}
	if mustPolicy(t, fullPolicy).Report().Summary.Mode != "allow_list" {
		t.Error("an allow list is allow_list")
	}
}

func TestLocalPolicy_AllowAllRefusals(t *testing.T) {
	for doc, want := range map[string]string{
		"apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"*\", \"10.0.0.0/8\"]\n":  "cannot be mixed",
		"apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"example.com\", \"*\"]\n": "cannot be mixed",
	} {
		if _, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
}
