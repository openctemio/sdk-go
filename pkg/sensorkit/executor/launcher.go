package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// LauncherArg is the first argument that makes the sensor binary act as the
// launcher. It is not a user-facing command.
const LauncherArg = "__openctem-task"

// launchSpec is what the parent tells the launcher. It is passed as one
// base64 argument (visible in the process list: it holds paths and limits,
// never a secret).
type launchSpec struct {
	Workdir  string   `json:"workdir"`
	Cwd      string   `json:"cwd"`
	Limits   Limits   `json:"limits"`
	ReadDeny []string `json:"read_deny,omitempty"`
	// Private are paths a task may not read either, though its write
	// paths may lie beneath them: the root of every task directory, so a
	// task sees its own directory and no sibling's.
	Private    []string `json:"private,omitempty"`
	WritePaths []string `json:"write_paths,omitempty"`
	ReadPaths  []string `json:"read_paths,omitempty"`
	Binary     string   `json:"binary,omitempty"`
	// Confined: the launcher runs in its own user, network and mount
	// namespaces (made by the parent at clone time). It brings up
	// loopback, points the resolver at 127.0.0.1, relays the proxy and DNS
	// ports to the forwarder's sockets, and runs the tool as its child
	// with no capabilities.
	Confined    bool   `json:"confined,omitempty"`
	EgressProxy string `json:"egress_proxy,omitempty"`
	EgressDNS   string `json:"egress_dns,omitempty"`
	// Inner marks the launcher started inside the namespaces by the
	// confined launcher (which is a fresh, dumpable process: the sensor
	// itself is not, so it could not write the new namespace's id maps).
	Inner bool `json:"inner,omitempty"`
	// Probe makes the launcher apply everything, print its Status as JSON
	// and exit instead of running a tool.
	Probe bool `json:"probe,omitempty"`
}

func (s launchSpec) encode() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("executor: encode launch spec: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeLaunchSpec(s string) (launchSpec, error) {
	var ls launchSpec
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) > 1<<20 {
		return ls, errors.New("malformed launch spec")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ls); err != nil {
		return ls, fmt.Errorf("malformed launch spec: %w", err)
	}
	return ls, nil
}

// launcherExit is the exit code when the launcher cannot confine or start
// the tool (as a shell's "cannot execute").
const launcherExit = 126

// RunLauncherIfRequested turns this process into the launcher when it was
// started as one (first argument LauncherArg) and never returns then. A
// program that uses a sandboxing backend calls it first thing in main,
// before flags or anything else.
func RunLauncherIfRequested() {
	if len(os.Args) < 3 || os.Args[1] != LauncherArg {
		launcherWired.Store(true)
		return
	}
	os.Exit(runLauncher(os.Args[2:]))
}

// launcherWired is set once this program called RunLauncherIfRequested: only
// then is re-executing it as the launcher safe (another program would run
// its own main with the launcher's arguments).
var launcherWired atomic.Bool

// runLauncher confines this process as spec says and then replaces it with
// the tool (argv after "--"). It returns only on failure.
func runLauncher(args []string) int {
	// no_new_privs, Landlock and seccomp apply to the calling thread; the
	// tool is exec'd from this same thread, which keeps them (execve ends
	// every other thread).
	runtime.LockOSThread()
	ls, err := decodeLaunchSpec(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "openctem sandbox: %v\n", err)
		return launcherExit
	}
	if ls.Confined && !ls.Inner {
		return runConfined(ls, args[1:])
	}
	if ls.Confined {
		if err := setupNetwork(ls); err != nil {
			if ls.Probe {
				st := Status{Backend: "process", Missing: []string{"network: " + err.Error()}}
				_ = json.NewEncoder(os.Stdout).Encode(st)
				return 0
			}
			fmt.Fprintf(os.Stderr, "openctem sandbox: network: %v\n", err)
			return launcherExit
		}
	}
	st, err := confine(ls)
	st.NetworkEnforced = ls.Confined
	if ls.Probe {
		if err != nil {
			st.Missing = append(st.Missing, err.Error())
		}
		_ = json.NewEncoder(os.Stdout).Encode(st)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "openctem sandbox: %v\n", err)
		return launcherExit
	}
	rest := args[1:]
	if len(rest) < 2 || rest[0] != "--" {
		fmt.Fprintln(os.Stderr, "openctem sandbox: no command")
		return launcherExit
	}
	if ls.Confined {
		// The relay lives in this process: run the tool as a child.
		return superviseTool(ls.Binary, rest[1:], os.Environ())
	}
	if err := execTool(ls.Binary, rest[1:], os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "openctem sandbox: run %s: %v\n", ls.Binary, err)
	}
	return launcherExit
}

// probe runs the launcher in probe mode and returns what it enforced.
func probe(launcher string, deny []string, limits Limits, confined bool) (Status, error) {
	dir, err := os.MkdirTemp("", "openctem-probe-")
	if err != nil {
		return Status{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	enc, err := launchSpec{Workdir: dir, Cwd: dir, Limits: limits, ReadDeny: deny, WritePaths: []string{dir}, Probe: true, Confined: confined}.encode()
	if err != nil {
		return Status{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, launcher, LauncherArg, enc) //nolint:gosec // this program
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if err := cmd.Run(); err != nil {
		return Status{}, fmt.Errorf("probe: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	var st Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		return Status{}, fmt.Errorf("probe: the launcher answered %q (is RunLauncherIfRequested called first in main?)", strings.TrimSpace(out.String()))
	}
	if confined && !st.NetworkEnforced {
		return st, fmt.Errorf("%s", strings.Join(st.Missing, "; "))
	}
	return st, nil
}
