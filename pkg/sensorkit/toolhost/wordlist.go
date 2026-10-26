package toolhost

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/wordlist"
)

// composeWordlists turns a task's wordlist content into one file per slot in
// the task's own directory (api RFC-061): the lists the job carried inline
// first (they are specific to the target, so they rank first), then the named
// files of the job's packs, normalised for the slot's purpose, without
// repeats and within the line cap. The slot's content then holds that one
// file, so the tool reads a single path, never a pack, and the packs need no
// read grant. Inline lists are written only here, under the task directory,
// and are cleared from the task; they are never written to the content cache.
//
// A wordlist slot with neither named files nor inline lists is left as it is
// (the tool receives the pack directories). It returns the pack directories
// it read, whose read grants the task no longer needs.
func composeWordlists(m tool.Manifest, task *tool.Task, workdir string, notes *[]LogLine) ([]string, *tool.Error) {
	var consumed []string
	for i := range task.Content {
		c := &task.Content[i]
		slot, ok := m.Slot(c.Slot)
		if !ok || slot.Kind != "wordlist" {
			continue
		}
		if len(c.Files) == 0 && len(c.Inline) == 0 {
			continue
		}
		var readers []io.Reader
		var closers []io.Closer
		closeAll := func() {
			for _, cl := range closers {
				_ = cl.Close()
			}
		}
		for _, l := range c.Inline {
			if slot.Purpose != "" && l.Purpose != "" && l.Purpose != slot.Purpose {
				closeAll()
				return nil, tool.AsError(tool.Invalid("content slot %q: a %s list was given to a %s slot", c.Slot, l.Purpose, slot.Purpose))
			}
			readers = append(readers, strings.NewReader(string(l.Data)))
		}
		for _, p := range c.Packs {
			for _, f := range c.Files[p.Digest] {
				file, err := openPackFile(p.Path, f)
				if err != nil {
					closeAll()
					return nil, tool.AsError(tool.Invalid("content slot %q: %v", c.Slot, err))
				}
				readers = append(readers, file)
				closers = append(closers, file)
			}
		}
		dir := filepath.Join(workdir, "wordlists")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			closeAll()
			return nil, tool.AsError(fmt.Errorf("content slot %q: %w", c.Slot, err))
		}
		out := filepath.Join(dir, c.Slot+".txt")
		w, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside the task directory
		if err != nil {
			closeAll()
			return nil, tool.AsError(fmt.Errorf("content slot %q: %w", c.Slot, err))
		}
		maxLines := minPositive(slot.MaxLines, c.MaxLines)
		res, cerr := wordlist.Compose(w, wordlist.Options{Purpose: slot.Purpose, MaxLines: maxLines}, readers...)
		closeAll()
		if werr := w.Close(); cerr == nil {
			cerr = werr
		}
		if cerr != nil {
			return nil, tool.AsError(tool.Invalid("content slot %q: %v", c.Slot, cerr))
		}
		if notes != nil {
			f := map[string]any{"slot": c.Slot, "lines": res.Lines, "duplicates": res.Duplicates, "invalid": res.Invalid, "truncated": res.Truncated}
			level := "info"
			if res.Truncated {
				level = "warn"
			}
			*notes = append(*notes, LogLine{Level: level, Msg: "wordlist composed", Fields: f})
		}
		for _, p := range c.Packs {
			if p.Path != "" {
				consumed = append(consumed, filepath.Clean(p.Path))
			}
		}
		task.Content[i] = tool.TaskContent{Slot: c.Slot, Mode: c.Mode, Packs: []tool.ContentPack{{Digest: "sha256:" + res.SHA256, Source: "composed", Path: out}}}
	}
	return consumed, nil
}

// openPackFile opens a regular file inside a pack directory. The name was
// checked clean by tool.CheckTaskContent; this keeps the path inside the pack
// and refuses a symbolic link or any other non-regular file.
func openPackFile(packDir, name string) (*os.File, error) {
	if !tool.CleanPackFile(name) {
		return nil, fmt.Errorf("%q is not a clean file path inside the pack", name)
	}
	p := filepath.Join(packDir, filepath.FromSlash(name))
	if rel, err := filepath.Rel(packDir, p); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("%q leaves the pack", name)
	}
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a file of the pack", name)
	}
	return os.Open(p) //nolint:gosec // inside the content cache, checked above
}

func minPositive(a, b int) int {
	switch {
	case a <= 0:
		return max(b, 0)
	case b <= 0:
		return a
	}
	return min(a, b)
}

// withoutPaths removes drop from paths (the read grants of packs the tool
// reads as one composed file).
func withoutPaths(paths, drop []string) []string {
	if len(drop) == 0 {
		return paths
	}
	skip := map[string]bool{}
	for _, p := range drop {
		skip[p] = true
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !skip[p] {
			out = append(out, p)
		}
	}
	return out
}
