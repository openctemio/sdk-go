package toolcli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

// buildSDKVersion is the SDK version this CLI was built from (a variable
// for tests).
var buildSDKVersion = useragent.SDKVersion

// scaffoldSDKVersion is the SDK version a Go scaffold requires and its CI
// installs the CLI at: the version this CLI was built from (a release tag,
// or the pseudo-version of a main commit after go install ...@<commit>), so
// the scaffold reads every descriptor key this CLI writes. A CLI built from
// a local checkout has no module version and falls back to sdk.Version.
func scaffoldSDKVersion() string {
	v := buildSDKVersion()
	// Build metadata ("+dirty" from a modified checkout) is not a module
	// version: keep the commit's pseudo-version.
	v, _, _ = strings.Cut(v, "+")
	if v == "" || strings.Contains(v, "devel") {
		return sdk.Version
	}
	return v
}

// pinCLI pins the CI template's CLI install to the scaffold's SDK version
// instead of @latest: a tool's CI checks with the CLI it was written for,
// and a new release cannot change its checks without a commit.
func pinCLI(ci string) string {
	return strings.ReplaceAll(ci, "/cmd/openctem@latest", "/cmd/openctem@v"+scaffoldSDKVersion())
}

// Kinds of scaffold.
const (
	KindExecSARIF = "exec-sarif"
	KindExecCTIS  = "exec-ctis"
	KindExecJSON  = "exec-json"
	KindGo        = "go"
	KindPython    = "python"
)

var kinds = []string{KindExecSARIF, KindExecCTIS, KindExecJSON, KindGo, KindPython}

//go:embed templates/github-openctem-tool.yml
var githubCI string

//go:embed templates/gitlab-openctem-tool.yml
var gitlabCI string

// pythonHelper is openctem_tool.py, the Python tools' protocol helper
// (standard library only) a python scaffold gets.
//
//go:embed templates/openctem_tool.py
var pythonHelper string

// PythonHelper is openctem_tool.py.
func PythonHelper() string { return pythonHelper }

// GitHubCI and GitLabCI are the CI templates a scaffold gets (also in the
// repository's ci/ directory).
func GitHubCI() string { return githubCI }

// GitLabCI is the GitLab CI template.
func GitLabCI() string { return gitlabCI }

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flags("init", stderr)
	kind := fs.String("kind", "", "exec-sarif, exec-ctis, exec-json, go or python")
	capRef := fs.String("capability", "", "the capability the tool implements (id@major, see ctis docs/capabilities.md)")
	name := fs.String("name", "", "the tool name (default: my-<capability>)")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 || !slices.Contains(kinds, *kind) || *capRef == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	dir := first(pos)
	if dir == "" {
		dir = "."
	}
	files, m, err := Scaffold(*kind, *capRef, *name)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	if err := writeFiles(dir, files); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	if _, err := tool.LoadManifestFile(filepath.Join(dir, "tool.yaml")); err != nil {
		_, _ = fmt.Fprintf(stdout, "wrote %s; this SDK does not accept it yet: %v\n", dir, err)
		return ExitFail
	}
	if *kind != KindGo {
		// The stub runs as it is: record what its fixture produces through
		// the runtime (a go tool is built first; its expectation is the
		// empty report the stub emits).
		p := &printer{out: io.Discard}
		guarded(func() {
			conformance.RunToolSuite(p, filepath.Join(dir, "tool.yaml"), conformance.ToolSuiteOptions{Update: true})
		})
		if p.failed {
			_, _ = fmt.Fprintf(stdout, "wrote %s; the stub did not run here, so fixtures/expect.ctis.json is a prediction (openctem tool test --update rewrites it)\n", dir)
		}
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s (%s, implements %s)\nnext: openctem tool test %s\n", dir, m.Name, *capRef, dir)
	return ExitOK
}

// writeFiles writes a scaffold without overwriting a file that exists.
func writeFiles(dir string, files map[string]scaffoldFile) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s exists; init never overwrites", p)
		}
	}
	for _, n := range names {
		f := files[n]
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // a source tree
			return err
		}
		if err := os.WriteFile(p, []byte(f.content), f.mode); err != nil {
			return err
		}
	}
	return nil
}

type scaffoldFile struct {
	content string
	mode    os.FileMode
}

// sampleValues are fixture target values per CTIS asset type.
var sampleValues = map[string]string{
	"domain": "example.com", "subdomain": "www.example.com", "ip_address": "192.0.2.10", "host": "host.example.com",
	"open_port": "192.0.2.10:443", "service": "192.0.2.10:22", "http_service": "https://www.example.com",
	"discovered_url": "https://www.example.com/login", "website": "https://www.example.com", "api": "https://api.example.com",
	"web_application": "https://app.example.com", "repository": "fixtures/repo", "container": "registry.example.com/app:1.0",
	"cloud_account": "123456789012", "network": "192.0.2.0/24", "subnet": "192.0.2.0/24",
}

// Scaffold builds the files of a new tool implementing one capability: a
// tool.yaml pre-filled from the capability (implements, consumes, produces,
// tier floor, a config key for each standard param), a fixture task and
// its expected CTIS, a stub program that emits nothing yet, a Makefile and
// a CI workflow. The stub passes "openctem tool test" as it is.
func Scaffold(kind, capRef, name string) (map[string]scaffoldFile, tool.Manifest, error) {
	c, ok := capability.Lookup(capRef)
	if _, major, okRef := capability.ParseRef(capRef); !ok || !okRef || major == 0 {
		return nil, tool.Manifest{}, fmt.Errorf("%q is not a capability with its major (see docs/capabilities.md of ctis)", capRef)
	}
	if c.Status == capability.StatusLater {
		return nil, tool.Manifest{}, fmt.Errorf("%s is reserved and cannot be implemented yet", capRef)
	}
	if name == "" {
		name = "my-" + strings.NewReplacer(".", "-", "_", "-").Replace(c.ID)
	}
	m, err := scaffoldManifest(kind, c, name)
	if err != nil {
		return nil, tool.Manifest{}, err
	}
	task := tool.Task{ID: "selftest-sample"}
	if len(m.Consumes) > 0 {
		typ := m.Consumes[0]
		task.Targets = []tool.Target{{Ref: "t1", Type: typ, Value: sampleValues[typ]}}
	}
	taskJSON, _ := json.MarshalIndent(task, "", "  ")
	expect, err := emptyReport(m, task)
	if err != nil {
		return nil, tool.Manifest{}, err
	}
	files := map[string]scaffoldFile{
		"fixtures/task.json":                  {string(taskJSON) + "\n", 0o644},
		"fixtures/expect.ctis.json":           {string(expect), 0o644},
		".github/workflows/openctem-tool.yml": {pinCLI(githubCI), 0o644},
		"Makefile":                            {makefile(kind, name), 0o644},
	}
	if len(task.Targets) > 0 && task.Targets[0].Type == "repository" {
		files["fixtures/repo/README.md"] = scaffoldFile{"A sample repository for the self-test.\n", 0o644}
	}
	switch kind {
	case KindExecSARIF, KindExecCTIS, KindExecJSON:
		files["bin/"+name] = scaffoldFile{execStub(kind, name), 0o755}
		if kind == KindExecJSON {
			files["mapping.yaml"] = scaffoldFile{mappingStub(c), 0o644}
		}
	case KindGo:
		files["main.go"] = scaffoldFile{goMain(c), 0o644}
		files["go.mod"] = scaffoldFile{fmt.Sprintf("module example.com/%s\n\ngo 1.26\n\nrequire github.com/openctemio/sdk-go v%s\n", name, scaffoldSDKVersion()), 0o644}
	case KindPython:
		files[name+".py"] = scaffoldFile{pythonStub(name), 0o755}
		files["openctem_tool.py"] = scaffoldFile{pythonHelper, 0o644}
	}
	doc, err := manifestYAML(kind, m)
	if err != nil {
		return nil, tool.Manifest{}, err
	}
	files["tool.yaml"] = scaffoldFile{doc, 0o644}
	return files, m, nil
}

// scaffoldManifest is the manifest of a new tool, from the capability.
func scaffoldManifest(kind string, c capability.Capability, name string) (tool.Manifest, error) {
	m := tool.Manifest{APIVersion: tool.APIVersion, Name: name, Version: "0.1.0",
		Description: "TODO: what " + name + " does.", Class: tool.TargetScan,
		Tier:         tool.Tier(fmt.Sprintf("T%d", c.TierFloor)),
		Presentation: &tool.Presentation{DisplayName: name},
		Protocol:     tool.Range{Min: tool.ProtocolVersion}}
	for _, p := range c.InPorts {
		if pt, ok := capability.LookupPortType(p); ok {
			for _, t := range pt.Carries {
				if !slices.Contains(m.Consumes, t) {
					m.Consumes = append(m.Consumes, t)
				}
			}
		}
	}
	for _, p := range c.OutPorts {
		if p == capability.PortEndpoint {
			if !slices.Contains(m.Produces, tool.KindEndpoint) {
				m.Produces = append(m.Produces, tool.KindEndpoint)
			}
			continue
		}
		if p == capability.PortFinding {
			types := c.FindingTypes
			if len(types) == 0 {
				types = []string{"vulnerability"}
			}
			for _, ft := range types {
				m.Produces = append(m.Produces, "finding:"+ft)
			}
			continue
		}
		if pt, ok := capability.LookupPortType(p); ok {
			for _, t := range pt.Carries {
				if k := "asset:" + t; !slices.Contains(m.Produces, k) {
					m.Produces = append(m.Produces, k)
				}
			}
		}
	}
	for _, e := range c.ExtraOutputs {
		if e != "asset:*" && !slices.Contains(m.Produces, e) {
			m.Produces = append(m.Produces, e)
		}
	}
	if len(m.Produces) == 0 {
		m.Produces = []string{"finding:vulnerability"}
	}
	code := slices.Contains(m.Consumes, "repository") || slices.Contains(m.Consumes, "container")
	if code {
		m.Permissions = tool.Permissions{Network: tool.NetNone, Filesystem: tool.FSScanRootsReadOnly}
	} else {
		m.Permissions = tool.Permissions{Network: tool.NetTargets}
	}
	im := tool.Implementation{Capability: c.Ref(), Params: map[string]tool.ParamMapping{}}
	props := map[string]any{}
	for _, p := range c.Params {
		props[p.Name] = paramSchema(p)
		im.Params[p.Name] = tool.ParamMapping{}
	}
	if shapes := c.Shapes(); len(shapes) > 0 {
		im.OutputShape = shapes[0]
	}
	if len(im.Params) == 0 {
		im.Params = nil
	}
	m.Implements = []tool.Implementation{im}
	if _, ok := c.Param("rate"); ok {
		m.Safety = &tool.Safety{RateParam: "rate"}
	}
	if len(props) > 0 {
		raw, err := json.Marshal(map[string]any{"type": "object", "additionalProperties": false, "properties": props})
		if err != nil {
			return m, err
		}
		m.Config = raw
	}
	m.Selftest = []tool.Fixture{{Name: "sample", Task: "fixtures/task.json", Expect: "fixtures/expect.ctis.json"}}
	switch kind {
	case KindExecSARIF:
		m.Run = &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"./bin/" + name, "{{target.value}}"},
			Output: &tool.OutputSpec{Format: tool.OutputSARIF, From: "stdout"}}
		m.Engine = &tool.Engine{Name: name, VersionProbe: []string{"./bin/" + name, "--version"}}
	case KindExecCTIS:
		m.Run = &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"./bin/" + name, "{{target.value}}"},
			Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}}
		m.Engine = &tool.Engine{Name: name, VersionProbe: []string{"./bin/" + name, "--version"}}
	case KindExecJSON:
		// run.output.mapping needs an SDK with the json/jsonl formats; the
		// key is written in the YAML (manifestYAML).
		m.Run = &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"./bin/" + name, "{{target.value}}"},
			Output: &tool.OutputSpec{Format: "jsonl", From: "stdout"}}
		m.Engine = &tool.Engine{Name: name, VersionProbe: []string{"./bin/" + name, "--version"}}
	case KindGo:
		m.Run = &tool.RunSpec{Argv: []string{"./bin/" + name}}
	case KindPython:
		m.Run = &tool.RunSpec{Argv: []string{"./" + name + ".py"}}
	}
	return m, nil
}

// paramSchema is the config schema of a standard param.
func paramSchema(p capability.Param) map[string]any {
	s := map[string]any{"description": p.Description}
	switch p.Type {
	case capability.ParamString:
		s["type"] = "string"
		if len(p.Enum) > 0 {
			s["enum"] = p.Enum
		}
	case capability.ParamStringList:
		items := map[string]any{"type": "string"}
		if len(p.Enum) > 0 {
			items["enum"] = p.Enum
		}
		s["type"], s["items"] = "array", items
	case capability.ParamInteger:
		s["type"] = "integer"
		if p.Min != nil {
			s["minimum"] = *p.Min
		}
		if p.Max != nil {
			s["maximum"] = *p.Max
		}
	case capability.ParamBoolean:
		s["type"] = "boolean"
	case capability.ParamPortList:
		s["type"], s["pattern"], s["maxLength"] = "string", `^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$`, 2048
	}
	return s
}

// manifestYAML is the tool.yaml of a scaffold: YAML for every kind, JSON
// (which is YAML too) for Python so the program reads it with the standard
// library.
func manifestYAML(kind string, m tool.Manifest) (string, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if kind == KindExecJSON {
		run := doc["run"].(map[string]any)
		run["output"].(map[string]any)["mapping"] = "mapping.yaml"
	}
	if kind == KindPython {
		out, _ := json.MarshalIndent(doc, "", "  ")
		return string(out) + "\n", nil
	}
	return "# Generated by openctem tool init. The runtime trusts this file, never the program:\n" +
		"# keep it the single place the tool's facts are written.\n" + toYAML(doc, 0), nil
}

// emptyReport is the normalized CTIS a task of the stub produces (no
// records): the expected output of the scaffold's fixture.
func emptyReport(m tool.Manifest, task tool.Task) ([]byte, error) {
	asm := toolrt.NewAssembler(m, task, toolrt.NewChecker(m))
	for _, t := range task.Targets {
		_ = asm.Target(t.Ref, tool.StateDone, nil)
	}
	r := asm.Report(time.Now().UTC())
	toolrt.Stamp(r, toolrt.Provenance{Tool: m.Name})
	return testkit.Normalize(r)
}

func makefile(kind, name string) string {
	build := ""
	deps := ""
	if kind == KindGo {
		build = "build:\n\tgo mod tidy\n\tgo build -o bin/" + name + " .\n\n"
		deps = " build"
	}
	return ".PHONY: validate test conformance" + deps + "\n\n" + build +
		"validate:\n\topenctem tool validate .\n\n" +
		"# Self-tests and the protocol checks.\n" +
		"test:" + deps + " validate\n\topenctem tool test .\n\n" +
		"# The full kit: the capability suites on local fixtures, the scope check and\n" +
		"# parser fuzzing. The stub finds nothing, so it fails until the tool is real.\n" +
		"conformance:" + deps + " validate\n\topenctem tool test --capability --scope --fuzz 30s .\n"
}

func execStub(kind, name string) string {
	out := map[string]string{
		KindExecSARIF: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + name + `","rules":[]}},"results":[]}]}`,
		KindExecCTIS:  `{"version":"1.4","metadata":{"timestamp":"2026-01-01T00:00:00Z"}}`,
		KindExecJSON:  ``,
	}[kind]
	return "#!/bin/sh\n" +
		"# Stub for " + name + ": replace it with the real CLI (or point run.argv in tool.yaml at it).\n" +
		"# The runtime starts it with the target as its argument and reads its standard output.\n" +
		"if [ \"$1\" = \"--version\" ]; then echo \"" + name + " 0.1.0\"; exit 0; fi\n" +
		"printf '%s\\n' '" + out + "'\n"
}

func mappingStub(c capability.Capability) string {
	kind, set := "finding", "      type: {const: vulnerability}\n      title: /title\n      severity: {path: /severity, default: info}\n      rule_id: /id\n"
	if !slices.Contains(c.OutPorts, capability.PortFinding) {
		kind, set = "asset", "      type: {const: domain}\n      value: /value\n"
	}
	return "# Declarative mapping of the CLI's JSON Lines output to CTIS (ctis/importer/mapping).\n" +
		"apiVersion: openctem.io/mapping/v1\nsource: jsonl\nrecords:\n  - when: {path: /id, exists: true}\n    kind: " + kind + "\n    set:\n" + set
}

func goMain(c capability.Capability) string {
	return `// A tool implementing ` + c.Ref() + `. Its facts live in tool.yaml (embedded): the
// runtime trusts that file and checks the program describes itself the same.
package main

import (
	_ "embed"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

//go:embed tool.yaml
var manifest []byte

func main() {
	m, err := tool.LoadManifest(manifest)
	if err != nil {
		panic(err)
	}
	adapter.Serve(tool.New(m, run))
}

// run does one task. The runtime already admitted the targets, mapped the
// workflow's standard params onto cfg and sandboxed this process. Emit
// records with ctx.Emit().Finding(t, ...) or ctx.Emit().Asset(...).
func run(ctx tool.Context, task tool.Task, cfg map[string]any) error {
	for _, t := range task.Targets {
		ctx.TargetDone(t)
	}
	return nil
}
`
}

func pythonStub(name string) string {
	return `#!/usr/bin/env python3
"""` + name + `: an OpenCTEM tool in Python (standard library only).

openctem_tool.py, next to this file, speaks adapter protocol v1 for it: the
handshake, describe (from tool.yaml, kept in its JSON form), validate,
cancel, heartbeats and the result. This file only does the work. Standard
output is the protocol channel: use ctx.log, or print to stderr.
"""

import openctem_tool as ot


def run(ctx, task):
    for target in task.targets:
        ctx.check()  # stops here when the runtime cancels the task
        # Look at target.value (target.host_port() splits it). Report what
        # you find with ctx.asset(target, {...}) or ctx.finding(target, {...})
        # (CTIS); reach the network with ctx.connect(host, port), which goes
        # through the sensor's forwarder when the task is confined.
        ctx.done(target)


if __name__ == "__main__":
    raise SystemExit(ot.serve(run))
`
}
