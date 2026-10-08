package toolcli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// "run" and "test" run the tool in the sensor's sandbox, as a sensor does:
// a tool that only works outside it fails here, not on a sensor.
func TestRunUsesTheSandbox(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the process sandbox is Linux only")
	}
	if _, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, WorkRoot: t.TempDir()}); err != nil {
		t.Skipf("sandbox not available here: %v", err)
	}
	defer executor.SetCurrent(nil)
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindExecCTIS, "--capability", "scan.ports@1", dir); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	code, out := run(t, "run", dir, "--target", "127.0.0.1@ip_address", "--sandbox", "required")
	if code != ExitOK || sandboxMode(out) != "required" {
		t.Fatalf("run --sandbox required: %d\n%s", code, out)
	}
	t.Setenv(EnvSandbox, "off")
	if code, out := run(t, "run", dir, "--target", "127.0.0.1@ip_address"); code != ExitOK || sandboxMode(out) != "off" {
		t.Fatalf("run with %s=off: %d\n%s", EnvSandbox, code, out)
	}
	if code, out := run(t, "run", dir, "--target", "127.0.0.1@ip_address", "--sandbox", "loose"); code != ExitUsage {
		t.Fatalf("an unknown mode is a usage error: %d\n%s", code, out)
	}
}

// sandboxMode is the mode on the "sandbox" line of run's table.
func sandboxMode(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "sandbox" {
			return f[1]
		}
	}
	return ""
}

// "run ." works from the tool's directory: a relative program resolves
// against the manifest, not the task's private directory.
func TestRunFromToolDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindExecCTIS, "--capability", "scan.ports@1", dir); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	t.Chdir(dir)
	if code, out := run(t, "run", ".", "--target", "127.0.0.1@ip_address", "--sandbox", "off"); code != ExitOK {
		t.Fatalf("run .: %d\n%s", code, out)
	}
}

// A Go scaffold requires the SDK this CLI was built from, and its CI
// installs that same CLI: never a release older than the descriptor keys
// the CLI writes, never @latest.
func TestScaffoldPinsTheCLIVersion(t *testing.T) {
	defer func(f func() string) { buildSDKVersion = f }(buildSDKVersion)
	for _, tc := range []struct{ built, want string }{
		{"0.18.1-0.20261008095043-b1383c499d28", "0.18.1-0.20261008095043-b1383c499d28"},
		{"0.19.0", "0.19.0"},
		{"0.18.1-0.20261008095043-b1383c499d28+dirty", "0.18.1-0.20261008095043-b1383c499d28"},
		{sdk.Version + "-devel", sdk.Version},
		{"", sdk.Version},
	} {
		buildSDKVersion = func() string { return tc.built }
		dir := filepath.Join(t.TempDir(), "tool")
		if code, out := run(t, "init", "--kind", KindGo, "--capability", "scan.ports@1", dir); code != ExitOK {
			t.Fatalf("init: %d %s", code, out)
		}
		gomod, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
		if !strings.Contains(string(gomod), "github.com/openctemio/sdk-go v"+tc.want+"\n") {
			t.Errorf("built %q: go.mod %s", tc.built, gomod)
		}
		ci, _ := os.ReadFile(filepath.Join(dir, ".github", "workflows", "openctem-tool.yml"))
		if strings.Contains(string(ci), "@latest") || !strings.Contains(string(ci), "cmd/openctem@v"+tc.want) {
			t.Errorf("built %q: CI does not pin the CLI:\n%s", tc.built, ci)
		}
	}
}

// --content hands a local pack to a tool (development); a slot the tool
// does not declare is refused.
func TestRunContentFlag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindExecCTIS, "--capability", "scan.ports@1", dir); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	code, out := run(t, "run", dir, "--target", "127.0.0.1@ip_address", "--sandbox", "off", "--content", "templates="+t.TempDir())
	if code == ExitOK || !strings.Contains(out, "content slot \"templates\" is not declared") {
		t.Fatalf("undeclared slot: %d %s", code, out)
	}
	if code, out := run(t, "run", dir, "--target", "127.0.0.1@ip_address", "--content", "nodir"); code != ExitUsage {
		t.Fatalf("malformed --content: %d %s", code, out)
	}
}
