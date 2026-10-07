package toolhost

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata goldens")

// portMapping is a YAML mapping of the jsonl-cli fixture's output.
const portMapping = `apiVersion: openctem.io/mapping/v1
source: jsonl
records:
  - when: {path: /port, exists: true}
    kind: asset
    set:
      type: {const: open_port}
      value: {template: "{ip}:{port}", vars: {ip: /ip, port: /port}}
      properties.host: /ip
      properties.port: {path: /port, as: integer}
      properties.protocol: {path: /protocol, lower: true, default: tcp}
`

// writeTool writes a tool directory (tool.yaml + mapping.yaml) for the
// exec fixture mode and loads it as the sensor does.
func writeTool(t *testing.T, format, mappingDoc string) (tool.Manifest, string) {
	t.Helper()
	exe, _ := os.Executable()
	dir := t.TempDir()
	out := fmt.Sprintf("{format: %s, from: stdout}", format)
	if mappingDoc != "" {
		out = fmt.Sprintf("{format: %s, from: stdout, mapping: mapping.yaml}", format)
		if err := os.WriteFile(filepath.Join(dir, "mapping.yaml"), []byte(mappingDoc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	doc := fmt.Sprintf(`apiVersion: openctem.io/tool/v1
name: acme-ports
version: 1.0.0
class: target-scan
tier: T1
implements: [{capability: scan.ports@1, output_shape: open_port_assets}]
consumes: [ip_address, domain]
produces: [asset:open_port]
permissions: {network: none}
run:
  profile: exec
  argv: [%q, "{{target.value}}"]
  output: %s
`, exe, out)
	if format == "nuclei" {
		doc = strings.Replace(doc, "implements: [{capability: scan.ports@1, output_shape: open_port_assets}]", "implements: [{capability: vuln.templates@1}]", 1)
		doc = strings.Replace(doc, "produces: [asset:open_port]", "produces: [finding:vulnerability, finding:misconfiguration]", 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "tool.yaml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := tool.LoadManifestFile(filepath.Join(dir, "tool.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

func runExecTool(t *testing.T, m tool.Manifest, dir, mode string, task tool.Task) *Outcome {
	t.Helper()
	if task.Targets == nil {
		task.Targets = []tool.Target{{Ref: "t1", Type: "ip_address", Value: "192.0.2.10"}}
	}
	out, err := testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Dir: dir, Env: map[string]string{"TOOLHOST_HOSTILE": mode}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A JSON Lines CLI with a mapping file and no code lands the golden CTIS,
// and satisfies its capability's contract.
func TestExecJSONLWithMapping(t *testing.T) {
	m, dir := writeTool(t, "jsonl", portMapping)
	if !strings.HasPrefix(m.Run.Output.MappingDigest, "sha256:") {
		t.Fatalf("the loader did not record the mapping digest: %+v", m.Run.Output)
	}
	out := runExecTool(t, m, dir, "jsonl-cli", tool.Task{Capability: "scan.ports@1"})
	if out.Status != tool.StatusOK || out.Stats.ContractViolations != 0 || len(out.Report.Assets) != 2 {
		t.Fatalf("status %s err %v stats %+v logs %+v stderr %s", out.Status, out.Err, out.Stats, out.Logs, out.Stderr)
	}
	got, err := testkit.Normalize(out.Report)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "exec-jsonl.golden.json")
	if *updateGolden {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("CTIS differs from %s (run with -update and review):\n%s", golden, got)
	}
	// The report's tool is the manifest's, never the output's.
	if out.Report.Tool == nil || out.Report.Tool.Name != "acme-ports" {
		t.Fatalf("tool %+v", out.Report.Tool)
	}
}

// SECURITY: a mapping file changed after the manifest was loaded is
// refused before the tool starts; so is a missing one.
func TestExecMappingTamperRefused(t *testing.T) {
	m, dir := writeTool(t, "jsonl", portMapping)
	if err := os.WriteFile(filepath.Join(dir, "mapping.yaml"), []byte(strings.Replace(portMapping, "open_port", "domain", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runExecTool(t, m, dir, "jsonl-cli", tool.Task{})
	if out.Status != tool.StatusFailed || out.Err == nil || !strings.Contains(out.Err.Detail, "changed since the manifest was loaded") {
		t.Fatalf("status %s err %+v", out.Status, out.Err)
	}
	if len(out.Report.Assets) != 0 {
		t.Fatal("the tool ran")
	}
	_ = os.Remove(filepath.Join(dir, "mapping.yaml"))
	if out := runExecTool(t, m, dir, "jsonl-cli", tool.Task{}); out.Status != tool.StatusFailed {
		t.Fatalf("missing mapping: %s", out.Status)
	}
	// A symlinked mapping is not a regular file.
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "mapping.yaml")); err == nil {
		if _, err := tool.LoadMappingFile(dir, "mapping.yaml", ""); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("symlink: %v", err)
		}
	}
}

func TestLoadManifestRefusesBadMappings(t *testing.T) {
	exe, _ := os.Executable()
	for name, tc := range map[string]struct{ mapping, out, want string }{
		"json without mapping": {"", "{format: json, from: stdout}", "needs a mapping file"},
		"mapping on ctis":      {"x", "{format: ctis, from: stdout, mapping: mapping.yaml}", "only for the json and jsonl formats"},
		"escaping path":        {"", "{format: jsonl, from: stdout, mapping: ../m.yaml}", "inside the manifest"},
		"invalid mapping":      {"apiVersion: openctem.io/mapping/v1\nsource: jsonl\nrecords: [{kind: shell}]\n", "{format: jsonl, from: stdout, mapping: mapping.yaml}", "/run/output/mapping"},
		"two documents":        {portMapping + "---\nx: 1\n", "{format: jsonl, from: stdout, mapping: mapping.yaml}", "more than one YAML document"},
		"unknown format":       {"", "{format: xlsx, from: stdout}", "/run/output/format"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.mapping != "" {
				_ = os.WriteFile(filepath.Join(dir, "mapping.yaml"), []byte(tc.mapping), 0o600)
			}
			doc := fmt.Sprintf("apiVersion: openctem.io/tool/v1\nname: x-tool\nversion: 1.0.0\nclass: target-scan\ntier: T1\nconsumes: [domain]\nproduces: [asset:open_port]\npermissions: {network: none}\nrun: {profile: exec, argv: [%q], output: %s}\n", exe, tc.out)
			_ = os.WriteFile(filepath.Join(dir, "tool.yaml"), []byte(doc), 0o600)
			_, err := tool.LoadManifestFile(filepath.Join(dir, "tool.yaml"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A CLI writing a named ctis/importer format needs no mapping and no code.
func TestExecNamedImporterFormat(t *testing.T) {
	m, dir := writeTool(t, "nuclei", "")
	out := runExecTool(t, m, dir, "nuclei-cli", tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "domain", Value: "a.example"}}, Capability: "vuln.templates@1"})
	if out.Status != tool.StatusOK || len(out.Report.Findings) != 1 {
		t.Fatalf("status %s err %v stats %+v logs %+v", out.Status, out.Err, out.Stats, out.Logs)
	}
	if f := out.Report.Findings[0]; f.RuleID != "tech-exposed" || f.Severity != "medium" {
		t.Fatalf("finding %+v", f)
	}
}
