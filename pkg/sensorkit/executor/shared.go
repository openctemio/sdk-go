package executor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// sharedEnvDirs are the variables that name where a tool keeps state
// between runs (its home, temporary files, caches, configuration). On a
// shared backend they may point only beneath the task root.
var sharedEnvDirs = []string{"HOME", "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"}

// checkShared refuses, on a shared backend, a task that would write where
// another task (another tenant's job) could later read: a write path or a
// state directory variable outside the task root.
func (b *ProcessBackend) checkShared(spec TaskSpec) error {
	if !b.cfg.Shared {
		return nil
	}
	for _, p := range spec.WritePaths {
		if !b.underTaskRoot(p) {
			return fmt.Errorf("executor: shared sensor: write path %q is outside the task root (no writable cache or output directory is shared between jobs)", p)
		}
	}
	for _, k := range sharedEnvDirs {
		if v, ok := spec.SetEnv[k]; ok && !b.underTaskRoot(v) {
			return fmt.Errorf("executor: shared sensor: %s=%q is outside the task root (no tool state is shared between jobs)", k, v)
		}
	}
	return nil
}

// underTaskRoot reports whether p lies strictly beneath the task root or
// the backend's work root (after symbolic links), where only per-task
// directories live.
func (b *ProcessBackend) underTaskRoot(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	abs = resolveExisting(filepath.Clean(abs))
	for _, root := range []string{b.cfg.WorkRoot, TaskRoot()} {
		r, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if e, err := filepath.EvalSymlinks(r); err == nil {
			r = e
		}
		r = filepath.Clean(r)
		if r != "/" && strings.HasPrefix(abs, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolveExisting resolves the symbolic links of the longest existing
// prefix of the absolute path p and appends the rest: a path that does not
// exist yet is judged by where its existing parent really is.
func resolveExisting(p string) string {
	rest := ""
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
