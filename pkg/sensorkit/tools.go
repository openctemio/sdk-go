package sensorkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/toolcompat"
)

// EnvAdapterDirs lists directories of operator-installed tools (each a
// tool.yaml with its program), separated by the OS path list separator.
const EnvAdapterDirs = "SENSOR_ADAPTER_DIRS"

// manifestFile is the manifest an adapter directory holds.
const manifestFile = "tool.yaml"

// maxAdapterTools bounds how many tools the adapter directories may add.
const maxAdapterTools = 256

// AddTool adds a tool of the tool contract (pkg/tool), compiled into the
// sensor: dispatched and scheduled scans for it run out of process (the
// sensor re-executes itself as "<sensor> __openctem-tool <name>" in the
// task sandbox), each task admitted against the local policy first, with
// only the credentials its manifest declares, and its output checked and
// stamped before it reaches the outbox. The heartbeat and the sensor
// manifest report it with its contract (manifest digest, class, tier,
// produces).
//
// The program must serve its tools in the child: call
// adapter.Dispatch(tools...) with the same tools at the top of main
// (after executor.RunLauncherIfRequested). A legacy core.Scanner is added
// the same way through toolcompat.FromScanner. Call before Run.
func (k *Kit) AddTool(t tool.Tool, opts ...ScannerOption) {
	if t == nil {
		return
	}
	k.AddScanner(toolcompat.AsScanner(t, toolcompat.ScannerConfig{
		Host: k.toolHost(), Mode: tool.Daemon, Credentials: k.toolCredentials(t.Manifest().Name),
	}), opts...)
}

// toolHost is the host every contract tool runs on: the kit's sandbox
// backend (executor.Current, set by New) and the local policy in force.
func (k *Kit) toolHost() *toolhost.Host {
	k.hostOnce.Do(func() {
		k.host = &toolhost.Host{
			Sensor:         k.s.name,
			RuntimeName:    firstNonEmpty(k.opts.ProductName, "openctem-sensor"),
			RuntimeVersion: k.opts.Version,
			Policy:         kitPolicy{k},
		}
	})
	return k.host
}

// kitPolicy is the local policy in force at each admission (SIGHUP and
// SetLocalPolicy replace it while the sensor runs).
type kitPolicy struct{ k *Kit }

func (p kitPolicy) AllowsTool(name string) bool { return p.k.LocalPolicy().AllowsTool(name) }
func (p kitPolicy) CheckTarget(ctx context.Context, target string) error {
	return p.k.LocalPolicy().CheckTarget(ctx, target)
}
func (p kitPolicy) CapTimeout(d time.Duration) time.Duration { return p.k.LocalPolicy().CapTimeout(d) }
func (p kitPolicy) KillSwitchEngaged() bool                  { return p.k.LocalPolicy().KillSwitchEngaged() }

func (k *Kit) toolCredentials(name string) func() map[string]string {
	if k.opts.ToolCredentials == nil {
		return nil
	}
	return func() map[string]string { return k.opts.ToolCredentials(name) }
}

// adapterDirs are the configured adapter directories.
func (k *Kit) adapterDirs() []string {
	if k.opts.AdapterDirs != nil {
		return k.opts.AdapterDirs
	}
	var out []string
	for _, d := range filepath.SplitList(os.Getenv(EnvAdapterDirs)) {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// loadAdapterTools adds the tools the operator installed in the adapter
// directories: <dir>/tool.yaml and <dir>/<name>/tool.yaml. The runtime
// trusts the manifest file, never the program's description of itself; a
// manifest is loaded only from a directory and a file no other user can
// change (owned by root or the sensor's user, not group- or
// world-writable, not a symbolic link), and only with a run section. A
// manifest that fails a check is reported and skipped; it never runs.
func (k *Kit) loadAdapterTools() {
	dirs := k.adapterDirs()
	if len(dirs) == 0 {
		return
	}
	taken := map[string]bool{}
	for _, e := range k.scanners {
		taken[strings.ToLower(e.s.Name())] = true
		if e.as != "" {
			taken[strings.ToLower(e.as)] = true
		}
	}
	added := 0
	for _, dir := range dirs {
		for _, mf := range adapterManifests(dir) {
			if added >= maxAdapterTools {
				k.adapterProblem(mf, fmt.Errorf("more than %d adapter tools; the rest are not loaded", maxAdapterTools))
				return
			}
			m, err := loadAdapterManifest(dir, mf)
			if err != nil {
				k.adapterProblem(mf, err)
				continue
			}
			if taken[m.Name] {
				k.adapterProblem(mf, fmt.Errorf("tool %s is already provided by the sensor", m.Name))
				continue
			}
			taken[m.Name] = true
			added++
			k.AddScanner(toolcompat.AsScanner(manifestTool{m}, toolcompat.ScannerConfig{
				Host: k.toolHost(), Mode: tool.Daemon, Dir: filepath.Dir(mf), Credentials: k.toolCredentials(m.Name),
			}))
			_, _ = fmt.Fprintf(k.out, "  Adapter tool: %s %s (%s)\n", m.Name, m.Version, mf)
		}
	}
}

func (k *Kit) adapterProblem(path string, err error) {
	_, _ = fmt.Fprintf(k.errw, "Warning: adapter tool %s not loaded: %v\n", path, err)
	k.ReportCheck(core.ConfigCheck{ID: "tools.adapter." + toolSegment(filepath.Base(filepath.Dir(path))), Status: core.CheckError,
		Code: "adapter_refused", Summary: err.Error(), Keys: []string{EnvAdapterDirs}})
}

// adapterManifests lists the manifest files of one adapter directory.
func adapterManifests(dir string) []string {
	var out []string
	if _, err := os.Lstat(filepath.Join(dir, manifestFile)); err == nil {
		out = append(out, filepath.Join(dir, manifestFile))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			p := filepath.Join(dir, e.Name(), manifestFile)
			if _, err := os.Lstat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// loadAdapterManifest reads one operator-installed manifest after the
// ownership checks of the adapter directory, the tool's directory, the
// manifest and a program shipped next to it.
func loadAdapterManifest(root, path string) (tool.Manifest, error) {
	dir := filepath.Dir(path)
	checks := []string{root, path}
	if filepath.Clean(dir) != filepath.Clean(root) {
		checks = []string{root, dir, path}
	}
	for _, p := range checks {
		if err := checkTrustedPath(p); err != nil {
			return tool.Manifest{}, err
		}
	}
	m, err := tool.LoadManifestFile(path)
	if err != nil {
		return tool.Manifest{}, err
	}
	if m.Run == nil || len(m.Run.Argv) == 0 {
		return tool.Manifest{}, errors.New("the manifest has no run section (only tools compiled into the sensor may omit it)")
	}
	prog := m.Run.Argv[0]
	if !filepath.IsAbs(prog) && strings.ContainsRune(prog, filepath.Separator) {
		if err := checkTrustedPath(filepath.Join(dir, prog)); err != nil {
			return tool.Manifest{}, err
		}
	}
	return m.Normalized(), nil
}

// manifestTool is an operator-installed tool: its manifest only; the
// runtime starts its program (it never runs in the sensor's process).
type manifestTool struct{ m tool.Manifest }

func (t manifestTool) Manifest() tool.Manifest { return t.m }
func (t manifestTool) Run(tool.Context, tool.Task) error {
	return tool.Failed(errors.New("an adapter tool runs only as its own program"))
}

// kitTools is the state AddTool shares across calls.
type kitTools struct {
	hostOnce sync.Once
	host     *toolhost.Host
}
