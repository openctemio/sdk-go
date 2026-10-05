package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// fullPolicy is a policy using every key.
const fullPolicy = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["203.0.113.0/24", "198.51.100.7", "10.20.0.0/16", "*.corp.example.com", "app.example.org"]
  deny: ["10.20.5.0/24", "secret.corp.example.com", "*.prod.corp.example.com"]
  allow_private: true
ports:
  allow: "80,443, 8000-8999"
tools:
  allow: [nuclei, HTTPX, gitleaks]
checks:
  allow: [scan, validate]
allow_custom_templates: false
allow_interactsh: false
rate:
  max_rps: 50
  max_job_seconds: 3600
kill_switch_file: /etc/openctem/STOP
`

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

var privateOn = env(map[string]string{EnvSensorAllowPrivateTargets: "1"})

// fakeDNS resolves from a table; anything else does not resolve.
func fakeDNS(table map[string][]string) func(context.Context, string) ([]net.IP, error) {
	return func(_ context.Context, host string) ([]net.IP, error) {
		addrs, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var ips []net.IP
		for _, a := range addrs {
			ips = append(ips, net.ParseIP(a))
		}
		return ips, nil
	}
}

var policyDNS = fakeDNS(map[string][]string{
	"www.corp.example.com":    {"10.20.1.10"},
	"rebind.corp.example.com": {"10.20.5.9"},       // allowed domain, denied range
	"imds.corp.example.com":   {"169.254.169.254"}, // allowed domain, built-in deny
	"mixed.corp.example.com":  {"10.20.1.11", "127.0.0.1"},
	"app.example.org":         {"192.0.2.10"},   // allowed by name, outside the ranges
	"in-range.other.test":     {"203.0.113.40"}, // not a listed domain, inside a range
	"out-of-range.other.test": {"192.0.2.99"},
	"x.prod.corp.example.com": {"10.20.1.12"},
	"secret.corp.example.com": {"10.20.1.13"},
})

func mustPolicy(t *testing.T, doc string) *LocalPolicy {
	t.Helper()
	lp, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{LookupEnv: privateOn, LookupIP: policyDNS})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return lp
}

func TestParseLocalPolicy_Full(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	r := lp.Report()
	if r.State != LocalPolicyStateEnforced || r.Source != LocalPolicySourceFile || !strings.HasPrefix(r.Digest, "sha256:") {
		t.Fatalf("report %+v", r)
	}
	s := r.Summary
	if s.TargetsAllow != 5 || s.TargetsDeny != 3 || !s.AllowPrivate || s.Ports != "80,443,8000-8999" ||
		s.AllowCustomTemplates || s.AllowInteractsh || s.MaxRPS != 50 || s.MaxJobSeconds != 3600 {
		t.Fatalf("summary %+v", s)
	}
	// Tools take their canonical names (gitleaks -> betterleaks), sorted.
	if strings.Join(s.Tools, ",") != "betterleaks,httpx,nuclei" || strings.Join(s.Checks, ",") != "scan,validate" {
		t.Fatalf("tools %v checks %v", s.Tools, s.Checks)
	}
	// The summary names no range or domain.
	raw, _ := json.Marshal(r)
	for _, secret := range []string{"203.0.113", "corp.example.com", "10.20"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("report leaks %q: %s", secret, raw)
		}
	}
}

// Every malformed policy is an error: the sensor fails closed.
func TestParseLocalPolicy_FailsClosed(t *testing.T) {
	head := "apiVersion: openctem.io/sensor-policy/v1\n"
	for name, doc := range map[string]string{
		"empty":                  "",
		"blank":                  "  \n# only a comment\n",
		"no apiVersion":          "targets: {allow: [203.0.113.0/24]}\n",
		"wrong apiVersion":       "apiVersion: openctem.io/sensor-policy/v3\n",
		"unknown top key":        head + "allow_everything: true\n",
		"unknown nested key":     head + "targets: {allow: [203.0.113.0/24], allowed: []}\n",
		"typo of a switch":       head + "allow_interact_sh: true\n",
		"two documents":          head + "---\n" + head,
		"duplicate key":          head + "allow_interactsh: false\nallow_interactsh: true\n",
		"bad CIDR":               head + "targets: {allow: [203.0.113.0/33]}\n",
		"host bits":              head + "targets: {allow: [203.0.113.7/24]}\n",
		"bad domain":             head + "targets: {allow: [\"exa mple.com\"]}\n",
		"inner wildcard":         head + "targets: {allow: [\"a.*.example.com\"]}\n",
		"bare wildcard":          head + "targets: {allow: [\"*.com\"]}\n",
		"empty entry":            head + "targets: {deny: [\"\"]}\n",
		"loopback allowed":       head + "targets: {allow: [127.0.0.0/8]}\n",
		"metadata allowed":       head + "targets: {allow: [169.254.169.254]}\n",
		"private w/o switch":     head + "targets: {allow: [10.20.0.0/16]}\n",
		"port zero":              head + "ports: {allow: \"0-80\"}\n",
		"port too big":           head + "ports: {allow: \"70000\"}\n",
		"port reversed":          head + "ports: {allow: \"443-80\"}\n",
		"port empty item":        head + "ports: {allow: \"80,,443\"}\n",
		"ports without allow":    head + "ports: {}\n",
		"bad tool name":          head + "tools: {allow: [\"nuclei;rm\"]}\n",
		"rate zero":              head + "rate: {max_rps: 0}\n",
		"rate negative":          head + "rate: {max_job_seconds: -1}\n",
		"job seconds over cap":   head + "rate: {max_job_seconds: 999999}\n",
		"relative kill switch":   head + "kill_switch_file: STOP\n",
		"wrong type":             head + "allow_interactsh: maybe\n",
		"list instead of string": head + "ports: {allow: [80, 443]}\n",
	} {
		if _, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{LookupEnv: env(nil)}); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

// Absent switches are off in a policy (owner decision Q4 (a): off for new
// installs), absent sections restrict nothing.
func TestParseLocalPolicy_Defaults(t *testing.T) {
	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n")
	if lp.AllowsCustomTemplates() || lp.AllowsInteractsh() {
		t.Fatal("a policy must default custom templates and interactsh to off")
	}
	if !lp.AllowsTool("anything") || !lp.AllowsCheck("scan") {
		t.Fatal("absent sections restrict nothing")
	}
	if lp.Report().Summary.TargetsAllow != -1 {
		t.Fatal("no allow list reports -1")
	}
	if err := lp.CheckTarget(context.Background(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	// Private targets need both the policy and the switch.
	if err := lp.CheckTarget(context.Background(), "10.1.2.3"); !isRule(err, "targets.allow_private") {
		t.Fatalf("private without allow_private: %v", err)
	}
	// An empty list allows nothing.
	none := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntools: {allow: []}\nchecks: {allow: []}\n")
	if none.AllowsTool("nuclei") || none.AllowsCheck("scan") || !none.AllowsCheck("health_check") {
		t.Fatal("empty lists must allow nothing (health_check excepted)")
	}
}

// allow_private true in the file without SENSOR_ALLOW_PRIVATE_TARGETS=1 stays
// off, with a warning: the policy only narrows.
func TestParseLocalPolicy_PrivateNeedsBoth(t *testing.T) {
	doc := "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow_private: true}\n"
	lp, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{LookupEnv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if lp.Report().Summary.AllowPrivate || len(lp.Warnings()) == 0 {
		t.Fatalf("private on without the switch: %+v %v", lp.Report().Summary, lp.Warnings())
	}
	if err := lp.CheckTarget(context.Background(), "192.168.1.1"); !isRule(err, "targets.allow_private") {
		t.Fatalf("%v", err)
	}
}

func isRule(err error, rule string) bool {
	var pe *LocalPolicyError
	return errors.As(err, &pe) && pe.Rule == rule && errors.Is(err, ErrRefusedByLocalPolicy)
}

// noLoopback undoes the test harness's OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK
// for one test, so loopback is refused as in production.
func noLoopback(t *testing.T) {
	t.Helper()
	prev := httpsec.AllowLoopback
	httpsec.AllowLoopback = false
	t.Cleanup(func() { httpsec.AllowLoopback = prev })
}

func TestLocalPolicy_CheckTarget(t *testing.T) {
	noLoopback(t)
	lp := mustPolicy(t, fullPolicy)
	ctx := context.Background()
	for target, rule := range map[string]string{
		// Ranges.
		"203.0.113.9":     "",
		"203.0.113.0/25":  "",
		"203.0.112.0/23":  "targets.allow", // wider than the allowed range
		"10.20.5.0/28":    "targets.deny",
		"10.20.0.0/16":    "targets.deny", // overlaps the denied /24
		"198.51.100.7":    "",
		"198.51.100.8":    "targets.allow",
		"192.0.2.1":       "targets.allow",
		"10.20.5.1":       "targets.deny",
		"169.254.169.254": "builtin",
		"127.0.0.1":       "builtin",
		"0.0.0.0/0":       "builtin",
		// Names: an allowed domain, every address checked (DNS rebinding).
		"www.corp.example.com":      "",
		"rebind.corp.example.com":   "targets.deny",
		"imds.corp.example.com":     "builtin",
		"mixed.corp.example.com":    "builtin",
		"app.example.org":           "",
		"in-range.other.test":       "",
		"out-of-range.other.test":   "targets.allow",
		"x.prod.corp.example.com":   "targets.deny",
		"secret.corp.example.com":   "targets.deny",
		"nxdomain.corp.example.com": "targets",
		// Ports, explicit and from the scheme.
		"https://www.corp.example.com/login":  "",
		"http://www.corp.example.com:8080/":   "",
		"http://www.corp.example.com:9000/":   "ports.allow",
		"www.corp.example.com:22":             "ports.allow",
		"203.0.113.9:443":                     "",
		"[2001:db8::1]:443":                   "targets.allow",
		"ftp://www.corp.example.com/":         "",
		"https://rebind.corp.example.com/":    "targets.deny",
		"https://169.254.169.254/latest/meta": "builtin",
		// An image reference reaches no target network.
		"alpine":       "",
		"nginx:latest": "",
	} {
		err := lp.CheckTarget(ctx, target)
		if rule == "" && err != nil {
			t.Errorf("%s: refused: %v", target, err)
		}
		if rule != "" && !isRule(err, rule) {
			t.Errorf("%s: err %v, want rule %s", target, err, rule)
		}
	}
	// Filesystem targets are confined by the scan workspace, not here.
	if err := lp.CheckTarget(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func cmdWith(id, typ string, payload map[string]any) *Command {
	raw, _ := json.Marshal(payload)
	return &Command{ID: id, Type: typ, Payload: raw}
}

func TestLocalPolicy_AdmitCommand(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		cmd  *Command
		rule string
	}{
		"allowed scan":     {cmdWith("a", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.9", "https://www.corp.example.com"}}), ""},
		"tool not allowed": {cmdWith("b", "scan", map[string]any{"scanner": "naabu", "target": "203.0.113.9"}), "tools.allow"},
		"preferred tool":   {cmdWith("c", "scan", map[string]any{"preferred_tool": "semgrep", "target": "203.0.113.9"}), "tools.allow"},
		"retired name":     {cmdWith("d", "scan", map[string]any{"scanner": "gitleaks", "target": "203.0.113.9"}), ""},
		"no tool":          {cmdWith("e", "scan", map[string]any{"target": "203.0.113.9"}), "tools.allow"},
		"check type":       {cmdWith("f", "collect", map[string]any{"collector": "github"}), "checks.allow"},
		"health check":     {cmdWith("g", "health_check", nil), ""},
		"one bad target": {cmdWith("h", "scan", map[string]any{"scanner": "nuclei",
			"targets": []string{"203.0.113.9", "rebind.corp.example.com"}}), "targets.deny"},
		"target beside targets": {cmdWith("i", "scan", map[string]any{"scanner": "nuclei",
			"target": "203.0.113.9", "targets": []string{"192.0.2.1"}}), "targets.allow"},
		"interactsh": {cmdWith("j", "scan", map[string]any{"scanner": "nuclei", "target": "203.0.113.9",
			"config": map[string]any{"allow_interactsh": true}}), "allow_interactsh"},
		"interactsh off is fine": {cmdWith("k", "scan", map[string]any{"scanner": "nuclei", "target": "203.0.113.9",
			"config": map[string]any{"allow_interactsh": false}}), ""},
		"custom templates": {cmdWith("l", "scan", map[string]any{"scanner": "nuclei", "target": "203.0.113.9",
			"custom_templates": []map[string]any{{"id": "t", "name": "t.yaml", "template_type": "nuclei", "content": "eA=="}}}), "allow_custom_templates"},
		"validate object target": {cmdWith("m", "validate", map[string]any{"executor_kind": "safe_check",
			"target": map[string]any{"address": "10.20.5.4:443"}}), "targets.deny"},
		"validate allowed": {cmdWith("n", "validate", map[string]any{"executor_kind": "nuclei",
			"target": map[string]any{"address": "https://www.corp.example.com"}}), ""},
		"validate port": {cmdWith("o", "validate", map[string]any{"executor_kind": "safe_check",
			"target": map[string]any{"address": "www.corp.example.com:3389"}}), "ports.allow"},
		"unreadable target":  {&Command{ID: "p", Type: "scan", Payload: []byte(`{"scanner":"nuclei","target":42}`)}, "payload"},
		"unreadable payload": {&Command{ID: "q", Type: "scan", Payload: []byte(`["not an object"]`)}, "payload"},
	} {
		err := lp.AdmitCommand(ctx, tc.cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
	err := lp.AdmitCommand(ctx, cmdWith("h", "scan", map[string]any{"scanner": "nuclei",
		"targets": []string{"203.0.113.9", "rebind.corp.example.com"}}))
	if !strings.HasPrefix(err.Error(), "refused by local policy: targets.deny: ") || !strings.Contains(err.Error(), `"rebind.corp.example.com"`) {
		t.Fatalf("the reason must name the rule and the target: %v", err)
	}
}

// No policy: today's behavior (owner decision Q3 (a)) and warnings for the
// switches a policy would close (Q4 (a)); the kill switch still works.
func TestLocalPolicy_Absent(t *testing.T) {
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"), LookupEnv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if lp.Present() || lp.Report().State != LocalPolicyStateAbsent || lp.Report().Summary != nil || len(lp.Report().Warnings) == 0 {
		t.Fatalf("absent report %+v", lp.Report())
	}
	cmd := cmdWith("a", "scan", map[string]any{"scanner": "anything", "target": "192.0.2.1",
		"config":           map[string]any{"allow_interactsh": true},
		"custom_templates": []map[string]any{{"id": "t"}}})
	if err := lp.AdmitCommand(context.Background(), cmd); err != nil {
		t.Fatalf("absent policy refused: %v", err)
	}
	if w := lp.CommandWarnings(cmd); len(w) != 2 {
		t.Fatalf("warnings %v", w)
	}
	var nilPolicy *LocalPolicy
	if err := nilPolicy.AdmitCommand(context.Background(), cmd); err != nil || nilPolicy.KillSwitchEngaged() || !nilPolicy.AllowsInteractsh() {
		t.Fatal("a nil policy restricts nothing")
	}
}

func writePolicy(t *testing.T, dir, doc string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "sensor-policy.yaml")
	if err := os.WriteFile(p, []byte(doc), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadLocalPolicy(t *testing.T) {
	dir := t.TempDir()
	good := writePolicy(t, dir, fullPolicy, 0o644)

	// The default path is read when it exists.
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: good, LookupEnv: privateOn})
	if err != nil || !lp.Present() || lp.Path() != good {
		t.Fatalf("default path: %v %v", lp, err)
	}
	// SENSOR_LOCAL_POLICY names a file that must exist.
	if _, err := LoadLocalPolicy(LocalPolicyOptions{LookupEnv: env(map[string]string{EnvLocalPolicy: filepath.Join(dir, "missing.yaml")})}); err == nil {
		t.Fatal("a configured policy that does not exist must stop the sensor")
	}
	if _, err := LoadLocalPolicy(LocalPolicyOptions{Path: filepath.Join(dir, "missing.yaml"), LookupEnv: env(nil)}); err == nil {
		t.Fatal("a policy flag naming no file must stop the sensor")
	}
	// A world-writable policy is refused.
	wdir := t.TempDir()
	ww := writePolicy(t, wdir, fullPolicy, 0o666)
	if _, err := LoadLocalPolicy(LocalPolicyOptions{Path: ww, LookupEnv: privateOn}); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable: %v", err)
	}
	// A malformed file at the default path stops the sensor too.
	bdir := t.TempDir()
	bad := writePolicy(t, bdir, "apiVersion: openctem.io/sensor-policy/v1\nbogus: 1\n", 0o644)
	if _, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: bad, LookupEnv: env(nil)}); err == nil {
		t.Fatal("malformed default policy must stop the sensor")
	}
	// The shorthands do not mix with a file.
	if _, err := LoadLocalPolicy(LocalPolicyOptions{Path: good, LookupEnv: env(map[string]string{EnvAllowedRanges: "203.0.113.0/24"})}); err == nil {
		t.Fatal("file + shorthand must be an error")
	}
	// A relative kill switch file is an error.
	if _, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(dir, "none"), LookupEnv: env(map[string]string{EnvKillSwitchFile: "STOP"})}); err == nil {
		t.Fatal("relative kill switch file must be an error")
	}
}

func TestLoadLocalPolicy_Shorthands(t *testing.T) {
	lp, err := LoadLocalPolicy(LocalPolicyOptions{
		DefaultPath: filepath.Join(t.TempDir(), "none.yaml"),
		LookupEnv: env(map[string]string{
			EnvAllowedRanges: "10.20.0.0/16, *.corp.example.com", EnvAllowedPorts: "443",
			EnvSensorAllowPrivateTargets: "1",
		}),
		LookupIP: policyDNS,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := lp.Report()
	if r.State != LocalPolicyStateEnforced || r.Source != LocalPolicySourceEnv || r.Summary.TargetsAllow != 2 || r.Summary.Ports != "443" {
		t.Fatalf("report %+v %+v", r, r.Summary)
	}
	if lp.AllowsCustomTemplates() || lp.AllowsInteractsh() {
		t.Fatal("a shorthand policy keeps templates and callbacks off")
	}
	ctx := context.Background()
	if err := lp.CheckTarget(ctx, "https://www.corp.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := lp.CheckTarget(ctx, "http://www.corp.example.com"); !isRule(err, "ports.allow") {
		t.Fatalf("port 80: %v", err)
	}
	if err := lp.CheckTarget(ctx, "203.0.113.1:443"); !isRule(err, "targets.allow") {
		t.Fatalf("outside: %v", err)
	}
	// Private ranges in the shorthand need the private switch.
	if _, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"),
		LookupEnv: env(map[string]string{EnvAllowedRanges: "10.20.0.0/16"})}); err == nil {
		t.Fatal("private shorthand range without the switch must be an error")
	}
}

func TestLocalPolicy_KillSwitch(t *testing.T) {
	dir := t.TempDir()
	stop := filepath.Join(dir, "STOP")
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(dir, "none.yaml"),
		LookupEnv: env(map[string]string{EnvKillSwitchFile: stop})})
	if err != nil {
		t.Fatal(err)
	}
	cmd := cmdWith("a", "health_check", nil)
	if lp.KillSwitchEngaged() || lp.AdmitCommand(context.Background(), cmd) != nil {
		t.Fatal("no file: not engaged")
	}
	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !lp.KillSwitchEngaged() || !lp.Report().KillSwitch {
		t.Fatal("file present: engaged")
	}
	if err := lp.AdmitCommand(context.Background(), cmd); !isRule(err, "kill_switch") {
		t.Fatalf("engaged kill switch must refuse every job: %v", err)
	}
	// The static switch in the file.
	static := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nkill_switch: true\n")
	if !static.KillSwitchEngaged() {
		t.Fatal("kill_switch: true")
	}
}

func TestLocalPolicy_CapRateAndTimeout(t *testing.T) {
	lp := mustPolicy(t, fullPolicy) // max_rps 50, max_job_seconds 3600
	for req, want := range map[int]int{0: 50, 10: 10, 50: 50, 100000: 50} {
		if got := lp.CapRate(req); got != want {
			t.Errorf("CapRate(%d) = %d, want %d", req, got, want)
		}
	}
	if lp.CapTimeout(0) != time.Hour || lp.CapTimeout(2*time.Hour) != time.Hour || lp.CapTimeout(time.Minute) != time.Minute {
		t.Fatal("max_job_seconds")
	}
	var none *LocalPolicy
	if none.CapRate(0) != 0 || none.CapTimeout(0) != 0 || none.CapTimeout(100*time.Hour) != MaxScanTimeout {
		t.Fatal("without a policy only MaxScanTimeout applies")
	}
}

// The egress hook pins the addresses it checked: a name that resolved to an
// allowed address is dialed at that address, and one that resolves to a
// denied address is never dialed.
func TestLocalPolicy_DialContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [\"*.corp.example.com\"], deny: [\"192.0.2.0/24\"]}\nports: {allow: \""+port+"\"}\n")
	lp.allowLoopback = true
	answers := map[string][]string{"svc.corp.example.com": {"127.0.0.1"}}
	lp.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		return fakeDNS(answers)(ctx, host)
	}
	dial := lp.DialContext(nil)
	ctx := context.Background()
	conn, err := dial(ctx, "tcp", net.JoinHostPort("svc.corp.example.com", port))
	if err != nil {
		t.Fatalf("allowed dial: %v", err)
	}
	if got := conn.RemoteAddr().String(); got != ln.Addr().String() {
		t.Fatalf("dialed %s, want the checked address %s", got, ln.Addr())
	}
	_ = conn.Close()

	// The name now resolves to a denied address (rebinding): refused.
	answers["svc.corp.example.com"] = []string{"192.0.2.5"}
	if _, err := dial(ctx, "tcp", net.JoinHostPort("svc.corp.example.com", port)); !isRule(err, "targets.deny") {
		t.Fatalf("rebound dial: %v", err)
	}
	if _, err := dial(ctx, "tcp", "svc.corp.example.com:1"); !isRule(err, "ports.allow") {
		t.Fatalf("port: %v", err)
	}
	if _, err := lp.CheckDial(ctx, "tcp", "evil.example.net:"+port); !isRule(err, "targets") {
		t.Fatalf("unresolvable: %v", err)
	}

	// Without a policy the built-in deny list still applies.
	var none *LocalPolicy
	if _, err := none.CheckDial(ctx, "tcp", "169.254.169.254:80"); !isRule(err, "builtin") {
		t.Fatalf("absent policy, metadata address: %v", err)
	}
}
