package toolhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

const packDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// An exec tool gets its content packs as arguments; a slot with no pack
// leaves its argument out; a pack path outside the sensor's content cache
// is refused before anything runs.
func TestExecContentPlaceholders(t *testing.T) {
	exe, _ := os.Executable()
	root := t.TempDir()
	a, b := filepath.Join(root, "sha256-a"), filepath.Join(root, "sha256-b")
	m := tool.Manifest{
		Name: "argv-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
		Consumes: []string{"repository"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetNone},
		Content:     []tool.ContentSlot{{Slot: "templates", Kind: "nuclei-templates"}, {Slot: "words", Kind: "wordlist"}},
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe, "{{content.templates...}}", "-t={{content.templates}}", "-w={{content.words}}", "end"},
			Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	h := testHost(t)
	h.ContentRoot = root
	task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "x"}},
		Content: []tool.TaskContent{{Slot: "templates", Packs: []tool.ContentPack{{Digest: packDigest, Path: a}, {Digest: packDigest, Path: b}}}}}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	want := a + "|" + b + "|-t=" + a + "," + b + "|end"
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != want {
		t.Fatalf("argv %+v (status %s, err %v), want %q", out.Report.Findings, out.Status, out.Err, want)
	}

	// SECURITY: a job cannot point a task at a path outside the cache.
	task.Content[0].Packs[0].Path = "/etc"
	out, _ = h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("a pack outside the content cache ran: %s %v", out.Status, out.Err)
	}
}
