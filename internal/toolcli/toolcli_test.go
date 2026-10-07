package toolcli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	os.Exit(m.Run())
}

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := Main(args, &out, &errw)
	return code, out.String() + errw.String()
}

// Every kind scaffolds a tool that passes "openctem tool test" with no
// edit (go after a build; exec-json once the SDK has the json formats).
func TestInitThenTestIsGreen(t *testing.T) {
	for _, tc := range []struct{ kind, capability string }{
		{KindExecSARIF, "sast.code@1"},
		{KindExecCTIS, "scan.ports@1"},
		{KindExecJSON, "vuln.templates@1"},
		{KindPython, "probe.http@1"},
		{KindGo, "secrets.code@1"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "tool")
			code, out := run(t, "init", "--kind", tc.kind, "--capability", tc.capability, dir)
			if tc.kind == KindExecJSON && strings.Contains(out, `unknown field "mapping"`) {
				t.Skip("this SDK has no json/jsonl exec formats yet (sdk-go #196)")
			}
			if code != ExitOK {
				t.Fatalf("init: %d %s", code, out)
			}
			switch tc.kind {
			case KindPython:
				if _, err := exec.LookPath("python3"); err != nil {
					t.Skip("python3 is not installed")
				}
			case KindGo:
				buildGoScaffold(t, dir)
			}
			if code, out := run(t, "test", dir); code != ExitOK || !strings.Contains(out, "PASS") {
				t.Fatalf("test: %d\n%s", code, out)
			}
			if code, out := run(t, "validate", dir); code != ExitOK || !strings.Contains(out, "valid") {
				t.Fatalf("validate: %d\n%s", code, out)
			}
			// init never overwrites.
			if code, out := run(t, "init", "--kind", tc.kind, "--capability", tc.capability, dir); code != ExitFail || !strings.Contains(out, "never overwrites") {
				t.Fatalf("second init: %d %s", code, out)
			}
		})
	}
}

// buildGoScaffold builds the go scaffold against this checkout of the SDK.
func buildGoScaffold(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not installed")
	}
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	f, err := os.OpenFile(filepath.Join(dir, "go.mod"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("replace github.com/openctemio/sdk-go => " + root + "\n")
	_ = f.Close()
	env := append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	for _, args := range [][]string{{"mod", "tidy"}, {"build", "-o", "bin/my-secrets-code", "."}} {
		cmd := exec.Command("go", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, out)
		}
	}
}

// Every capability that can be implemented scaffolds a valid descriptor
// for every kind the SDK supports.
func TestScaffoldIsValidForEveryCapability(t *testing.T) {
	for _, c := range capability.All() {
		for _, kind := range []string{KindExecSARIF, KindExecCTIS, KindGo, KindPython} {
			files, m, err := Scaffold(kind, c.Ref(), "")
			if c.Status == capability.StatusLater {
				if err == nil {
					t.Errorf("%s: a reserved capability scaffolded", c.Ref())
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s %s: %v", kind, c.Ref(), err)
			}
			if _, err := tool.LoadManifest([]byte(files["tool.yaml"].content)); err != nil {
				t.Errorf("%s %s: %v\n%s", kind, c.Ref(), err, files["tool.yaml"].content)
			}
			if m.MinimumTier() != tool.Tier("T"+string(rune('0'+c.TierFloor))) && c.TierFloor > 0 {
				t.Errorf("%s: tier %s, floor T%d", c.Ref(), m.MinimumTier(), c.TierFloor)
			}
		}
	}
	for _, bad := range []string{"scan.ports", "scan.everything@1", "Scan.Ports@1"} {
		if _, _, err := Scaffold(KindExecCTIS, bad, ""); err == nil {
			t.Errorf("%q scaffolded", bad)
		}
	}
}

func TestCommands(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindExecCTIS, "--capability", "scan.ports@1", "--name", "acme-ports", dir); code != ExitOK {
		t.Fatalf("init: %s", out)
	}
	code, out := run(t, "run", dir, "--target", "192.0.2.10@ip_address", "--capability", "scan.ports@1", "--param", "ports=80,443", "--config", "rate=10")
	if code != ExitOK || !strings.Contains(out, "status") || !strings.Contains(out, "ok") {
		t.Fatalf("run: %d %s", code, out)
	}
	if code, out := run(t, "run", dir, "--target", "192.0.2.10", "--format", "ctis"); code != ExitOK || !strings.Contains(out, `"version"`) {
		t.Fatalf("run ctis: %d %s", code, out)
	}
	// SECURITY: a standard param the tool does not support fails the task.
	if code, out := run(t, "run", dir, "--target", "192.0.2.10", "--capability", "scan.ports@1", "--param", `protocol="udp"`); code != ExitFail || !strings.Contains(out, "invalid_input") {
		t.Fatalf("run unsupported value: %d %s", code, out)
	}
	if code, out := run(t, "describe", "--json", dir); code != ExitOK || !strings.Contains(out, `"digest":"sha256:`) {
		t.Fatalf("describe: %d %s", code, out)
	}
	if code, out := run(t, "describe", dir); code != ExitOK || !strings.Contains(out, "implements scan.ports@1") {
		t.Fatalf("describe: %d %s", code, out)
	}
	// diff: a narrowed produces without a major bump fails.
	newDir := filepath.Join(t.TempDir(), "new")
	_ = os.MkdirAll(newDir, 0o755)
	doc, _ := os.ReadFile(filepath.Join(dir, "tool.yaml"))
	changed := strings.Replace(string(doc), `"asset:open_port", `, "", 1)
	changed = strings.Replace(changed, `version: "0.1.0"`, `version: "0.2.0"`, 1)
	_ = os.WriteFile(filepath.Join(newDir, "tool.yaml"), []byte(changed), 0o600)
	if code, out := run(t, "diff", dir, newDir); code != ExitFail || !strings.Contains(out, "breaking: no longer produces asset:open_port") || !strings.Contains(out, "major") {
		t.Fatalf("diff: %d %s", code, out)
	}
	if code, out := run(t, "diff", dir, dir); code != ExitOK || !strings.Contains(out, "OK") {
		t.Fatalf("diff same: %d %s", code, out)
	}
	// validate reports a broken descriptor with JSON pointers.
	_ = os.WriteFile(filepath.Join(newDir, "tool.yaml"), []byte(strings.Replace(string(doc), "tier: T1", "tier: T0", 1)), 0o600)
	if code, out := run(t, "validate", newDir); code != ExitFail || !strings.Contains(out, "/tier") {
		t.Fatalf("validate: %d %s", code, out)
	}
	for _, args := range [][]string{nil, {"bogus"}, {"init"}, {"init", "--kind", "rust", "--capability", "scan.ports@1"}, {"diff", dir}, {"run", "--format", "xml"}} {
		if code, _ := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
	if code, out := run(t, "help"); code != ExitOK || !strings.Contains(out, "describe") {
		t.Fatal("help")
	}
	if code, _ := run(t, "describe", "missing"); code != ExitFail {
		t.Fatal("describe missing")
	}
	if code, _ := run(t, "run", "missing", "--target", "x"); code != ExitFail {
		t.Fatal("run missing")
	}
	if code, _ := run(t, "diff", "missing", dir); code != ExitFail {
		t.Fatal("diff missing")
	}
	if code, _ := run(t, "init", "--kind", KindExecCTIS, "--capability", "simulate.attack@1", filepath.Join(t.TempDir(), "x")); code != ExitFail {
		t.Fatal("a reserved capability scaffolded")
	}
}

// The CI templates of the repository are the ones init writes.
func TestCITemplatesInSync(t *testing.T) {
	for file, want := range map[string]string{"github/openctem-tool.yml": GitHubCI(), "gitlab/openctem-tool.yml": GitLabCI()} {
		got, err := os.ReadFile(filepath.Join("..", "..", "ci", file))
		if err != nil || string(got) != want {
			t.Errorf("ci/%s differs from internal/toolcli/templates (copy it): %v", file, err)
		}
	}
}

func TestToYAMLRoundTrips(t *testing.T) {
	doc := map[string]any{"name": "x", "version": "1.0.0", "tier": "T1", "flag": "yes", "n": 3.0, "list": []any{"-a", "b"},
		"nested": map[string]any{"empty": map[string]any{}, "items": []any{map[string]any{"k": "v", "z": []any{}}}}, "weird key": "{{x}}"}
	out := toYAML(doc, 0)
	for _, want := range []string{`version: "1.0.0"`, `flag: "yes"`, `["-a", b]`, `"weird key": "{{x}}"`, "empty: {}", "- k: v"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
