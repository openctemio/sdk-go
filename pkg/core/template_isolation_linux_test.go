//go:build linux

package core

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// readInTask runs the test binary as a tool on the current backend (the
// same path as every scanner run) and returns what it printed.
func readInTask(ctx context.Context, t *testing.T, file string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	res, _ := runScanner(ctx, &ExecConfig{Binary: exe, Args: []string{testReadTool, file}, Timeout: 30 * time.Second}, nil, nil)
	if res == nil {
		t.Fatal("no result")
	}
	return strings.TrimSpace(string(res.Stdout))
}

// On a shared sensor, one organization's custom templates (which may carry
// auth headers) were written to the system's temporary directory, which
// the sandbox leaves readable: another organization's concurrent task read
// them. They now go to a private directory under the task root, granted
// only to the tasks of the job that carries them.
func TestCustomTemplatesAreReadableOnlyByTheirJob(t *testing.T) {
	b, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, WorkRoot: t.TempDir(),
		Limits: executor.Limits{Processes: 64}})
	if err != nil {
		t.Skipf("sandbox not available here: %v", err)
	}
	prev := executor.Current()
	executor.SetCurrent(b)
	t.Cleanup(func() { executor.SetCurrent(prev) })

	content := "id: tenant-a-check\ninfo:\n  name: x\nhttp:\n  - headers:\n      Authorization: Bearer tenant-a-secret\n"
	dir, files, cleanup, err := WriteCustomTemplates("nuclei", []EmbeddedTemplate{{
		ID: "t1", Name: "tenant-a-check", TemplateType: "nuclei",
		Content: base64.StdEncoding.EncodeToString([]byte(content)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !strings.HasPrefix(dir, executor.TaskRoot()+string(filepath.Separator)) {
		t.Fatalf("templates written to %s, outside the private task root %s", dir, executor.TaskRoot())
	}

	// Another job's task (its context carries no grant): refused.
	if out := readInTask(context.Background(), t, files[0]); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("another job's task read the templates: %q", out)
	}
	// Another job with a grant of its own: still refused.
	other := executor.WithReadPaths(context.Background(), t.TempDir())
	if out := readInTask(other, t, files[0]); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("another job's task read the templates: %q", out)
	}
	// The job that carries them: reads them.
	own := executor.WithReadPaths(context.Background(), dir)
	if out := readInTask(own, t, files[0]); out != "OK" {
		t.Fatalf("the job's own task could not read its templates: %q", out)
	}
}
