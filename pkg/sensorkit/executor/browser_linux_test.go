//go:build linux

package executor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// The other namespace kinds stay refused, by clone and by unshare, and
	// setns is refused whatever it targets.
	for _, ns := range []string{"uts", "ipc", "cgroup"} {
		if out, _ := runTool(t, b, br, "clonenswith", ns); !strings.HasPrefix(out, "ERR") {
			t.Errorf("browser task cloned a %s namespace: %q", ns, out)
		}
	}
	for _, ns := range []string{"uts", "ipc", "cgroup", "time"} {
		if out, _ := runTool(t, b, br, "unshareflag", ns); !strings.Contains(out, "operation not permitted") {
			t.Errorf("browser task unshared a %s namespace: %q", ns, out)
		}
	}
	if out, _ := runTool(t, b, br, "setns"); !strings.Contains(out, "operation not permitted") {
		t.Errorf("browser task called setns: %q", out)
	}
	// Raw link-layer, key and the netfilter and xfrm netlink sockets are
	// refused even from a user and network namespace the task made (where
	// it would hold the capabilities); NETLINK_ROUTE and a plain socket
	// stay allowed.
	const (
		afKey, afNetlink, afPacket = 15, 16, 17
		sockRaw, sockDgram         = 3, 2
	)
	for name, args := range map[string][]string{
		"AF_PACKET":         {strconv.Itoa(afPacket), strconv.Itoa(sockRaw), "0"},
		"AF_KEY":            {strconv.Itoa(afKey), strconv.Itoa(sockRaw), "2"},
		"NETLINK_NETFILTER": {strconv.Itoa(afNetlink), strconv.Itoa(sockRaw), "12"},
		"NETLINK_XFRM":      {strconv.Itoa(afNetlink), strconv.Itoa(sockRaw), "6"},
	} {
		if out, _ := runTool(t, b, br, "clonesocket", args...); !strings.HasPrefix(out, "ERR") {
			t.Errorf("browser task opened %s from its own namespaces: %q", name, out)
		}
		if out, _ := runTool(t, b, br, "socket", args...); !strings.HasPrefix(out, "ERR") {
			t.Errorf("browser task opened %s: %q", name, out)
		}
	}
	if out, _ := runTool(t, b, br, "clonesocket", strconv.Itoa(afNetlink), strconv.Itoa(sockRaw), "0"); out != "OK" {
		t.Errorf("browser task could not open a NETLINK_ROUTE socket: %q", out)
	}
	if out, _ := runTool(t, b, br, "socket", "2", strconv.Itoa(sockDgram), "0"); out != "OK" {
		t.Errorf("browser task could not open a UDP socket: %q", out)
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

// The browser seccomp filter on its own (no sandbox, no namespaces needed):
// raw link-layer, key management and the netfilter and xfrm netlink sockets
// are refused with EPERM; NETLINK_ROUTE and ordinary sockets still open.
func TestBrowserSeccompSocketRules(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = []string{"EXECUTOR_TEST_TOOL=seccompsocket"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tool: %v: %s", err, out)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(l, " ")
		got[k] = v
	}
	for _, k := range []string{"packet", "key", "netfilter", "xfrm"} {
		if got[k] != "operation not permitted" {
			t.Errorf("%s socket: %q, want operation not permitted", k, got[k])
		}
	}
	for _, k := range []string{"route", "udp"} {
		if got[k] != "ok" {
			t.Errorf("%s socket: %q, want ok", k, got[k])
		}
	}
}
