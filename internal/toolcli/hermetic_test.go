package toolcli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A scaffold's fixture names no host on the internet for a type the kit can
// serve: its targets are placeholders, answered by the kit on loopback.
func TestScaffoldFixturesAreHermetic(t *testing.T) {
	for _, capRef := range []string{"probe.http@1", "vuln.templates@1", "scan.ports@1", "discover.hosts@1"} {
		files, m, err := Scaffold(KindExecCTIS, capRef, "")
		if err != nil {
			continue
		}
		task := files["fixtures/task.json"].content
		for _, typ := range m.Consumes {
			if _, served := servedValues[typ]; !served {
				continue
			}
			if strings.Contains(task, "example.com") || !strings.Contains(task, "{{fixture.") || !strings.Contains(task, `"serve"`) {
				t.Errorf("%s: fixture for %s is not hermetic:\n%s", capRef, typ, task)
			}
		}
	}
	files, _, err := Scaffold(KindGo, "probe.http@1", "")
	if err != nil {
		t.Fatal(err)
	}
	if g := files[".gitignore"].content; !strings.Contains(g, "bin/") || !strings.Contains(g, "__pycache__/") || !strings.Contains(g, "fuzz/crashers/") {
		t.Fatalf("go .gitignore: %q", g)
	}
	files, _, _ = Scaffold(KindPython, "probe.http@1", "")
	if strings.Contains(files[".gitignore"].content, "bin/") {
		t.Fatalf("python .gitignore ignores bin/: %q", files[".gitignore"].content)
	}
}

// init then test of a python scaffold passes with no network but loopback:
// the fixture's server answers, and the tool really reaches it.
func TestPythonScaffoldTestsAgainstTheKitServer(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindPython, "--capability", "probe.http@1", "--name", "hermetic", dir); code != ExitOK {
		t.Fatalf("init: %s", out)
	}
	task, err := os.ReadFile(filepath.Join(dir, "fixtures", "task.json"))
	if err != nil || strings.Contains(string(task), "example.com") || !strings.Contains(string(task), "{{fixture.url}}") {
		t.Fatalf("fixture %v:\n%s", err, task)
	}
	if code, out := run(t, "test", dir); code != ExitOK || !strings.Contains(out, "PASS") {
		t.Fatalf("test: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "__pycache__")); err == nil {
		t.Fatal("the run left __pycache__ in the tool's tree")
	}
	// Make the tool fetch its target: the kit's server answers, and the
	// expect file stays the same across runs although the port changes.
	src := filepath.Join(dir, "hermetic.py")
	b, _ := os.ReadFile(src)
	s := string(b)
	i, j := strings.Index(s, "def run(ctx, task):"), strings.Index(s, "if __name__")
	s = s[:i] + `def run(ctx, task):
    import urllib.request
    for target in task.targets:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(target.value, timeout=5) as r:
            open("seen.txt", "w").write(str(r.status) + " " + r.headers["Server"])
        ctx.asset(target, {"type": "http_service", "name": target.value, "value": target.value, "properties": {"status_code": r.status}})
        ctx.done(target)

` + s[j:]
	if err := os.WriteFile(src, []byte(s), 0o755); err != nil { //nolint:gosec // a test tool must be executable
		t.Fatal(err)
	}
	if code, out := run(t, "test", "--update", dir); code != ExitOK {
		t.Fatalf("update: %d\n%s", code, out)
	}
	seen, err := os.ReadFile(filepath.Join(dir, "seen.txt"))
	if err != nil || string(seen) != "200 fixture" {
		t.Fatalf("seen %q %v", seen, err)
	}
	expect, _ := os.ReadFile(filepath.Join(dir, "fixtures", "expect.ctis.json"))
	if !strings.Contains(string(expect), "{{fixture.url}}") || strings.Contains(string(expect), "127.0.0.1") {
		t.Fatalf("expect is not normalized:\n%s", expect)
	}
	for k := 0; k < 2; k++ { // a new port each run, the same expectation
		if code, out := run(t, "test", dir); code != ExitOK || !strings.Contains(out, "PASS") {
			t.Fatalf("test %d: %d\n%s", k, code, out)
		}
	}
}

// A fixture with CRLF in a served header is refused by openctem tool test.
func TestToolTestRefusesCRLFInServedHeader(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindPython, "--capability", "probe.http@1", dir); code != ExitOK {
		t.Fatalf("init: %s", out)
	}
	p := filepath.Join(dir, "fixtures", "task.json")
	b, _ := os.ReadFile(p)
	b = []byte(strings.Replace(string(b), `"Server": "fixture"`, `"Server": "a\r\nX-Evil: 1"`, 1))
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // a test fixture
		t.Fatal(err)
	}
	if code, out := run(t, "test", dir); code == ExitOK || !strings.Contains(out, "CR or LF") {
		t.Fatalf("test: %d\n%s", code, out)
	}
}
