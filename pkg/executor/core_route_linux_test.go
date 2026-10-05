//go:build linux

package executor_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/executor"
)

// Every scanner the SDK runs (core.ExecuteScanner) goes through the
// installed executor: with the sandbox on, a scanner that tries to read the
// sensor's key is refused, its normal output is captured, and the result is
// stamped with the sandbox it ran under.
func TestExecuteScannerRunsInTheSandbox(t *testing.T) {
	state := t.TempDir()
	key := filepath.Join(state, "sensor-credentials.json")
	if err := os.WriteFile(key, []byte(`{"api_key":"oc_secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ReadDeny: []string{state}, WorkRoot: t.TempDir()})
	if err != nil {
		t.Skipf("sandbox not available: %v", err)
	}
	executor.SetCurrent(b)
	t.Cleanup(func() { executor.SetCurrent(nil) })

	exe, _ := os.Executable()
	res, err := core.ExecuteScanner(context.Background(), &core.ExecConfig{
		Binary: exe, Env: map[string]string{"EXECUTOR_TEST_TOOL": "read"}, Args: []string{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out := string(res.Stdout); !strings.Contains(out, "permission denied") || strings.Contains(out, "oc_secret") {
		t.Fatalf("scanner read the key: %q", out)
	}
	if !res.Sandbox.Complete() {
		t.Errorf("result not stamped: %+v", res.Sandbox)
	}

	// A scanner writing its output where the caller said it may.
	out := t.TempDir()
	res, err = core.ExecuteScanner(context.Background(), &core.ExecConfig{
		Binary: exe, Env: map[string]string{"EXECUTOR_TEST_TOOL": "write"}, Args: []string{filepath.Join(out, "r.json")},
		WritePaths: []string{out},
	})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "OK" || res.ExitCode != 0 {
		t.Fatalf("allowed write: %v %q", err, res.Stdout)
	}
}
