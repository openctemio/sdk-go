package toolhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

func wordlistManifest(argv ...string) tool.Manifest {
	exe, _ := os.Executable()
	return tool.Manifest{
		Name: "wl-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
		Consumes: []string{"repository"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetNone},
		Content:     []tool.ContentSlot{{Slot: "labels", Kind: "wordlist", Purpose: "dns-labels", MaxLines: 4}},
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: append([]string{exe}, argv...),
			Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
}

// packWith writes a pack directory like the content cache does (read-only
// regular files) and returns its path.
func packWith(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	for f, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The job's lists become one normalised file in the task directory: the
// inline list first, the pack's named files after it, no repeats, the line
// cap applied; the pack is no longer granted to the task and the caller's
// content list is not changed.
func TestComposeWordlists(t *testing.T) {
	root := t.TempDir()
	pack := packWith(t, root, "sha256-a", map[string]string{"dns/s.txt": "www\nmail\n*.bad\nftp\n", "dns/other.txt": "secret\n"})
	work := t.TempDir()
	m := wordlistManifest()
	task := tool.Task{Content: []tool.TaskContent{{Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}, Files: map[string][]string{packDigest: {"dns/s.txt"}},
		Inline: []tool.InlineList{{Purpose: "dns-labels", Data: []byte("Staging\nwww\n")}}}}}
	var notes []LogLine
	consumed, terr := composeWordlists(m, &task, work, &notes)
	if terr != nil {
		t.Fatal(terr)
	}
	if len(consumed) != 1 || consumed[0] != pack {
		t.Fatalf("consumed %v", consumed)
	}
	got := task.ContentPaths("labels")
	if len(got) != 1 || filepath.Dir(got[0]) != filepath.Join(work, "wordlists") {
		t.Fatalf("composed path %v is not in the task directory", got)
	}
	b, err := os.ReadFile(got[0])
	if err != nil {
		t.Fatal(err)
	}
	// MaxLines 4 of the slot; the file named in the job only (other.txt is not read).
	if string(b) != "staging\nwww\nmail\nftp\n" {
		t.Fatalf("composed %q", b)
	}
	if st, _ := os.Stat(got[0]); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if len(task.Content[0].Inline) != 0 || len(notes) != 1 {
		t.Fatalf("inline list kept or no note: %+v %v", task.Content[0].Inline, notes)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatal("a file the job did not name was read")
	}
}

func TestComposeWordlistsRefusals(t *testing.T) {
	root := t.TempDir()
	pack := packWith(t, root, "sha256-a", map[string]string{"s.txt": "www\n", "bad.txt": "*\n"})
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "sha256-a", "link.txt")); err != nil {
		t.Skip(err)
	}
	m := wordlistManifest()
	cases := map[string]tool.TaskContent{
		"escape":     {Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}, Files: map[string][]string{packDigest: {"../x"}}},
		"missing":    {Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}, Files: map[string][]string{packDigest: {"nope.txt"}}},
		"symlink":    {Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}, Files: map[string][]string{packDigest: {"link.txt"}}},
		"no entries": {Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}, Files: map[string][]string{packDigest: {"bad.txt"}}},
		"purpose":    {Slot: "labels", Inline: []tool.InlineList{{Purpose: "params", Data: []byte("a\n")}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			task := tool.Task{Content: []tool.TaskContent{c}}
			if _, terr := composeWordlists(m, &task, t.TempDir(), nil); terr == nil {
				t.Fatal("composed")
			}
		})
	}
	// A wordlist slot with neither files nor inline lists is left alone.
	task := tool.Task{Content: []tool.TaskContent{{Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}}}}
	if consumed, terr := composeWordlists(m, &task, t.TempDir(), nil); terr != nil || len(consumed) != 0 || task.ContentPaths("labels")[0] != pack {
		t.Fatalf("plain pack slot changed: %v %v", consumed, terr)
	}
}

// End to end through the host: the tool is handed the one composed file under
// its own task directory, not the pack; a file name that leaves the pack is
// refused before anything runs.
func TestRunManifestWordlist(t *testing.T) {
	root := t.TempDir()
	pack := packWith(t, root, "sha256-a", map[string]string{"s.txt": "www\nmail\n"})
	m := wordlistManifest("-w={{content.labels}}")
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	h := testHost(t)
	h.ContentRoot = root
	task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "x"}},
		Content: []tool.TaskContent{{Slot: "labels", Packs: []tool.ContentPack{{Digest: packDigest, Path: pack}}, Files: map[string][]string{packDigest: {"s.txt"}}}}}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Report.Findings) != 1 {
		t.Fatalf("status %s err %v", out.Status, out.Err)
	}
	arg := out.Report.Findings[0].Title
	if !strings.HasPrefix(arg, "-w=") || strings.Contains(arg, pack) || !strings.HasSuffix(arg, filepath.Join("wordlists", "labels.txt")) {
		t.Fatalf("tool argv %q", arg)
	}
	task.Content[0].Files = map[string][]string{packDigest: {"../../etc/passwd"}}
	out, _ = h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("a file outside the pack ran: %s %v", out.Status, out.Err)
	}
}

// A list that only travels in the job (no pack) reaches the tool the same
// way: one file under the task directory, nothing from the content cache.
func TestRunManifestInlineWordlist(t *testing.T) {
	m := wordlistManifest("-w={{content.labels}}")
	h := testHost(t)
	h.ContentRoot = t.TempDir()
	task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "x"}},
		Content: []tool.TaskContent{{Slot: "labels", Inline: []tool.InlineList{{Purpose: "dns-labels", Data: []byte("staging\nvpn\ninternal-db-7\n")}}}}}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Report.Findings) != 1 {
		t.Fatalf("status %s err %v", out.Status, out.Err)
	}
	arg := out.Report.Findings[0].Title
	if !strings.HasPrefix(arg, "-w=") || strings.HasPrefix(arg, "-w="+h.ContentRoot) || !strings.HasSuffix(arg, filepath.Join("wordlists", "labels.txt")) {
		t.Fatalf("tool argv %q", arg)
	}
	if len(task.Content[0].Inline) != 1 {
		t.Fatal("the caller's content list was changed")
	}
	// Never in the content cache: nothing was written under its root, and no
	// file anywhere in it holds the tenant's list.
	_ = filepath.WalkDir(h.ContentRoot, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != h.ContentRoot {
			t.Errorf("a private inline list reached the content cache: %s", p)
		}
		return nil
	})
	// The task directory, and the list with it, is gone after the task.
	path := strings.TrimPrefix(arg, "-w=")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the inline list outlived its task: %v", err)
	}
}
