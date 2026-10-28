package sensorkit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
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
			Shared:         k.s.shared,
			// The content cache: a task reads only the packs its signed job
			// pins, wordlists as one composed file in its own directory.
			ContentRoot: k.contentRoot(),
			// Launches wait while the host is overloaded (research/318).
			Governor: k.ToolGovernor(),
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

// CapRate caps a tool's rate key by the policy's rate.max_rps.
func (p kitPolicy) CapRate(requested int) int { return p.k.LocalPolicy().CapRate(requested) }

// HTTPPolicy is the policy's http section (schema v3): a forced
// User-Agent, and whether a tool may skip TLS verification.
func (p kitPolicy) HTTPPolicy() (string, bool) { return p.k.LocalPolicy().HTTPPolicy() }

// AdmittedAddrs are the addresses the policy admitted for a host: a
// confined task's forwarder dials only those (no second lookup between
// the check and the dial).
func (p kitPolicy) AdmittedAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	return p.k.LocalPolicy().AdmittedAddrs(ctx, host)
}

// The host reads these optional policies by type assertion: a missing
// method would silently switch the feature off, so each is asserted here.
var (
	_ toolhost.Policy       = kitPolicy{}
	_ toolhost.RatePolicy   = kitPolicy{}
	_ toolhost.HTTPPolicy   = kitPolicy{}
	_ toolhost.HostResolver = kitPolicy{}
)

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
// directories: <dir>/tool.yaml and <dir>/<name>/tool.yaml. The decision
// (what loads, what is refused and why) is InspectAdapterDirs, the same
// function the "tools manifests" command shows the operator; the kit only
// registers what it returns and reports each refusal.
func (k *Kit) loadAdapterTools() {
	dirs := k.adapterDirs()
	if len(dirs) == 0 {
		return
	}
	var builtin []string
	for _, e := range k.scanners {
		builtin = append(builtin, e.s.Name())
		if e.as != "" {
			builtin = append(builtin, e.as)
		}
	}
	rep := inspectAdapterDirs(dirs, builtin)
	for _, l := range rep.loaded {
		k.AddScanner(toolcompat.AsScanner(manifestTool{l.m}, toolcompat.ScannerConfig{
			Host: k.toolHost(), Mode: tool.Daemon, Dir: filepath.Dir(l.path), Credentials: k.toolCredentials(l.m.Name),
		}))
		_, _ = fmt.Fprintf(k.out, "  Adapter tool: %s %s (%s)\n", l.m.Name, l.m.Version, l.path)
	}
	for _, r := range rep.Refused {
		k.adapterProblem(r.Manifest, errors.New(r.Reason))
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

// Bounds of the walk over a tool's own directory.
const (
	maxAdapterTreeDepth   = 4
	maxAdapterTreeEntries = 1024
)

// loadAdapterManifest reads one operator-installed manifest after the
// ownership checks of the adapter directory, of every file and directory
// of the tool's own directory (anything the tool may load: its program, a
// helper module, a mapping, a wordlist), or, for a manifest directly in
// the adapter directory, of the files the manifest references.
func loadAdapterManifest(root, path string) (tool.Manifest, error) {
	dir := filepath.Dir(path)
	own := filepath.Clean(dir) != filepath.Clean(root)
	if err := checkTrustedPath(root); err != nil {
		return tool.Manifest{}, err
	}
	if own {
		if err := checkTrustedTree(dir); err != nil {
			return tool.Manifest{}, err
		}
	} else if err := checkTrustedPath(path); err != nil {
		return tool.Manifest{}, err
	}
	m, err := tool.LoadManifestFile(path)
	if err != nil {
		return tool.Manifest{}, err
	}
	if m.Run == nil || len(m.Run.Argv) == 0 {
		return tool.Manifest{}, errors.New("the manifest has no run section (only tools compiled into the sensor may omit it)")
	}
	if !own {
		refs := []string{}
		if prog := m.Run.Argv[0]; !filepath.IsAbs(prog) && strings.ContainsRune(prog, filepath.Separator) {
			refs = append(refs, prog)
		}
		if m.Run.Output != nil && m.Run.Output.Mapping != "" {
			refs = append(refs, m.Run.Output.Mapping)
		}
		for _, r := range refs {
			if err := checkTrustedPath(filepath.Join(dir, r)); err != nil {
				return tool.Manifest{}, err
			}
		}
	}
	return m.Normalized(), nil
}

// checkTrustedTree applies checkTrustedPath to a directory and everything
// below it, bounded in depth and entries (a tree past a bound is refused,
// never partly checked). The directory must hold only what the tool needs.
func checkTrustedTree(dir string) error {
	entries := 0
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel != "." && strings.Count(rel, string(filepath.Separator)) >= maxAdapterTreeDepth {
			return fmt.Errorf("%s is deeper than %d levels below the tool directory", p, maxAdapterTreeDepth)
		}
		entries++
		if entries > maxAdapterTreeEntries {
			return fmt.Errorf("the tool directory %s holds more than %d entries; keep only what the tool needs", dir, maxAdapterTreeEntries)
		}
		return checkTrustedPath(p)
	})
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
