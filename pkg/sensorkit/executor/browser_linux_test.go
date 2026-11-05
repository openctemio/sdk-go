//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A browser task runs confined as a non-root user of its own user
// namespace, may create the namespaces of a browser's renderer sandbox and
// no other, may write /proc, and keeps every other control. A task without
// the browser sandbox may do none of that.
func TestBrowserTaskSandbox(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "sensor-key")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newConfinedBackend(t, secret)

	plain := TaskSpec{ID: "plain"}
	if out, _ := runTool(t, b, plain, "clonens", "browser"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("a plain task made a user namespace: %q", out)
	}
	if out, _ := runTool(t, b, plain, "procwrite"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("a plain task wrote /proc: %q", out)
	}

	br := TaskSpec{ID: "browser", Browser: true}
	if out, _ := runTool(t, b, br, "uid"); out != "1000 1000" {
		t.Errorf("browser task ids: %q, want 1000 1000 (not root)", out)
	}
	if out, _ := runTool(t, b, br, "capeff"); out != "0000000000000000 0000000000000000" {
		t.Errorf("browser task capabilities: %q, want none", out)
	}
	if out, _ := runTool(t, b, br, "clonens", "browser"); out != "OK" {
		t.Errorf("browser task could not make its sandbox's namespaces: %q", out)
	}
	if out, _ := runTool(t, b, br, "clonens", "mount"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("browser task made a mount namespace: %q", out)
	}
	if out, _ := runTool(t, b, br, "unshare"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("browser task unshared a mount namespace: %q", out)
	}
	if out, _ := runTool(t, b, br, "mount", t.TempDir()); !strings.HasPrefix(out, "ERR") {
		t.Errorf("browser task mounted: %q", out)
	}
	if out, _ := runTool(t, b, br, "procwrite"); out != "OK" {
		t.Errorf("browser task could not write /proc: %q", out)
	}
	if out, _ := runTool(t, b, br, "read", secret); !strings.HasPrefix(out, "ERR") {
		t.Errorf("browser task read a protected file: %q", out)
	}
	if out, _ := runTool(t, b, br, "write", "/tmp/outside-"+t.Name()); !strings.HasPrefix(out, "ERR") {
		t.Errorf("browser task wrote outside its directory: %q", out)
	}
	if out, _ := runTool(t, b, br, "dial", "1.1.1.1:443"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("browser task reached the network around its forwarder: %q", out)
	}
}

// A browser task never runs unconfined: not on a sandbox that does not
// confine the network, not with the sandbox off.
func TestBrowserTaskNeedsConfinement(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModeAuto} {
		b, err := NewProcessBackend(Config{Mode: mode, WorkRoot: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		exe, _ := os.Executable()
		if _, err := b.Prepare(TaskSpec{Argv: []string{exe}, Browser: true}); !errors.Is(err, ErrBrowserNeedsConfinement) {
			t.Errorf("mode %s: browser task prepared unconfined: %v", mode, err)
		}
	}
}
