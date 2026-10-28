package analystcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitThenTestPassesForEveryKind(t *testing.T) {
	for _, kind := range []string{"triage.v1", "remediation.v1", "summary.v1"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "my-playbook")
			var out, errb bytes.Buffer
			if code := Main([]string{"init", "--kind", kind, dir}, &out, &errb); code != ExitOK {
				t.Fatalf("init exit %d: %s", code, errb.String())
			}
			out.Reset()
			if code := Main([]string{"test", dir}, &out, &errb); code != ExitOK {
				t.Fatalf("test exit %d: %s %s", code, out.String(), errb.String())
			}
			if !strings.Contains(out.String(), "PASS") || !strings.Contains(out.String(), "my-playbook@0.1.0") {
				t.Fatalf("report: %s", out.String())
			}
		})
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pb")
	var out, errb bytes.Buffer
	_ = Main([]string{"init", dir}, &out, &errb)
	if code := Main([]string{"init", dir}, &out, &errb); code != ExitFail {
		t.Fatalf("second init exit %d", code)
	}
}

func TestSampleGoldenSetPassesAndJSONReport(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main([]string{"test", "--json", "../../examples/playbooks/web-vuln-triage"}, &out, &errb); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"injection_passed": 1`) {
		t.Fatalf("%s", out.String())
	}
}

func TestFailingGoldenCaseFailsTheCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pb")
	var out, errb bytes.Buffer
	_ = Main([]string{"init", dir}, &out, &errb)
	p := filepath.Join(dir, "golden", "01-example.json")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, bytes.Replace(b, []byte(`"verdict": "needs_info"}`), []byte(`"verdict": "true_positive"}`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Main([]string{"test", dir}, &out, &errb); code != ExitFail || !strings.Contains(errb.String(), "eval gate failed") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if Main(nil, &out, &errb) != ExitUsage || Main([]string{"init", "--kind", "x.v1", "d"}, &out, &errb) != ExitUsage {
		t.Fatal("usage errors")
	}
}
