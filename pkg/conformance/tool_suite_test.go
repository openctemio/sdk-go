package conformance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func needPython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
}

// The Python example tool passes the whole suite.
func TestToolSuite_PythonExample(t *testing.T) {
	needPython(t)
	RunToolSuite(t, filepath.Join("..", "..", "examples", "python-adapter", "tool.yaml"), ToolSuiteOptions{})
}

// suiteRecorder is a T that keeps what the suite reported.
type suiteRecorder struct {
	errs []string
}

func (r *suiteRecorder) Helper()                   {}
func (r *suiteRecorder) Logf(string, ...any)       {}
func (r *suiteRecorder) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *suiteRecorder) Fatalf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }

// copyExample copies the Python example to a temporary directory and
// applies edit to its program.
func copyExample(t *testing.T, edit func(src string) string) string {
	t.Helper()
	src := filepath.Join("..", "..", "examples", "python-adapter")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"tool.yaml", "http_plaintext.py", "testdata/task.json", "testdata/expect.json"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if f == "http_plaintext.py" {
			b, mode = []byte(edit(string(b))), 0o755
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, mode); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "tool.yaml")
}

// The suite catches the mistakes that make the runtime refuse or
// mis-handle a tool.
func TestToolSuite_CatchesBrokenTools(t *testing.T) {
	needPython(t)
	for name, tc := range map[string]struct {
		edit func(string) string
		want string
	}{
		"prints on stdout": {func(s string) string {
			return strings.Replace(s, "def main():\n", "def main():\n    print(\"debug output\")\n", 1)
		}, "StdoutIsProtocol"},
		"describes itself differently": {func(s string) string {
			return strings.Replace(s, `"tier": "T0"`, `"tier": "T1"`, 1)
		}, "describes itself differently"},
		"accepts any configuration": {func(s string) string {
			return strings.Replace(s, "if config:", "if False:", 1)
		}, "Validate"},
		"wrong output": {func(s string) string {
			return strings.Replace(s, `"severity": "medium"`, `"severity": "high"`, 1)
		}, "Fixtures/basic: the report differs"},
		"undeclared output": {func(s string) string {
			return strings.Replace(s, `"type": "misconfiguration",`, `"type": "secret",`, 1)
		}, "Fixtures/basic"},
		"exits non-zero": {func(s string) string {
			return strings.Replace(s, "    return 0\n\n\nif __name__", "    return 4\n\n\nif __name__", 1)
		}, "ExitsOnEOF"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &suiteRecorder{}
			RunToolSuite(r, copyExample(t, tc.edit), ToolSuiteOptions{Timeout: 10 * time.Second})
			if !strings.Contains(strings.Join(r.errs, "\n"), tc.want) {
				t.Fatalf("want a failure mentioning %q, got:\n%s", tc.want, strings.Join(r.errs, "\n"))
			}
		})
	}
}
