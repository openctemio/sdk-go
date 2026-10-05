package importtool_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/importtool"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func input(name, path string) tool.Input {
	return tool.Input{Name: name, Path: path}
}

// Each format runs through the tool contract (the runtime's checks on
// every record, provenance stamping) and is pinned by a golden report.
func TestImportTool_Golden(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string // task path -> fixture
	}{
		{"nessus", map[string]string{"in/scan.nessus": "scan.nessus"}},
		{"qualys", map[string]string{"in/detections.xml": "detections.xml", "in/kb.xml": "detections.kb.xml"}},
		{"defectdojo", map[string]string{"in/findings.json": "findings.json"}},
		{"cyclonedx", map[string]string{"in/image.cdx.json": "image.cdx.json"}},
		{"spdx", map[string]string{"in/app.spdx.json": "app.spdx.json"}},
		{"osv", map[string]string{"in/osv.json": "lockfiles.osv.json"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string][]byte{}
			var inputs []tool.Input
			for p, fx := range c.files {
				files[p] = fixture(t, fx)
				inputs = append(inputs, input(fx, p))
			}
			res := testkit.Run(t, importtool.New(), tool.Task{Inputs: inputs}, testkit.Options{Files: files})
			res.RequireStatus(t, tool.StatusOK)
			if len(res.Report.Findings) == 0 && len(res.Report.Dependencies) == 0 {
				t.Fatal("no findings and no dependencies")
			}
			res.Golden(t, filepath.Join("testdata", c.name+".ctis.golden.json"))
		})
	}
}

func TestImportTool_MinSeverity(t *testing.T) {
	res := testkit.Run(t, importtool.New(), tool.Task{Inputs: []tool.Input{input("scan", "scan.nessus")}, Config: []byte(`{"min_severity":"critical"}`)},
		testkit.Options{Files: map[string][]byte{"scan.nessus": fixture(t, "scan.nessus")}})
	res.RequireStatus(t, tool.StatusOK)
	for _, f := range res.Report.Findings {
		if f.Severity != "critical" {
			t.Fatalf("kept a %s finding", f.Severity)
		}
	}
}

// Inputs are hostile: only regular files inside the task directory.
func TestImportTool_RefusesUnsafeInputs(t *testing.T) {
	scan := fixture(t, "scan.nessus")
	cases := map[string]struct {
		in    tool.Input
		files map[string][]byte
		setup func(t *testing.T)
	}{
		"traversal":     {in: input("x", "../../etc/passwd")},
		"absolute":      {in: input("x", "/etc/passwd")},
		"empty path":    {in: input("x", "")},
		"missing":       {in: input("x", "nope.nessus")},
		"directory":     {in: input("x", "dir"), files: map[string][]byte{"dir/a": scan}},
		"unknown":       {in: input("x", "a.txt"), files: map[string][]byte{"a.txt": []byte("hello")}},
		"zip":           {in: input("x", "a.zip"), files: map[string][]byte{"a.zip": []byte("PK\x03\x04rest")}},
		"xxe":           {in: input("x", "x.nessus"), files: map[string][]byte{"x.nessus": []byte(`<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&x;</NessusClientData_v2>`)}},
		"no inputs":     {},
		"deep nesting":  {in: input("x", "d.nessus"), files: map[string][]byte{"d.nessus": []byte(`<NessusClientData_v2>` + strings.Repeat("<a>", 500) + strings.Repeat("</a>", 500) + `</NessusClientData_v2>`)}},
		"invalid utf-8": {in: input("x", "u.json"), files: map[string][]byte{"u.json": []byte("{\"findings\": [{\"title\": \"\xff\"}]}")}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			task := tool.Task{}
			if c.in.Name != "" {
				task.Inputs = []tool.Input{c.in}
			}
			res := testkit.Run(t, importtool.New(), task, testkit.Options{Files: c.files})
			if res.Status != tool.StatusFailed || res.Err == nil || res.Err.Class != tool.InvalidInput {
				t.Fatalf("status %s err %v", res.Status, res.Err)
			}
			if len(res.Report.Findings) != 0 {
				t.Fatal("emitted findings")
			}
		})
	}
}

// A link inside the task directory is refused even when it points at a
// readable file: it could point anywhere.
func TestImportTool_RefusesLinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.nessus")
	if err := os.WriteFile(outside, fixture(t, "scan.nessus"), 0o600); err != nil {
		t.Fatal(err)
	}
	tl := importtool.New()
	// The testkit creates the task directory; a wrapper tool links the
	// input before the real run.
	wrapped := tool.New(tl.Manifest(), func(ctx tool.Context, task tool.Task, _ importtool.Config) error {
		if err := os.Symlink(outside, filepath.Join(ctx.Workdir(), "link.nessus")); err != nil {
			return err
		}
		return tl.Run(ctx, task)
	})
	res := testkit.Run(t, wrapped, tool.Task{Inputs: []tool.Input{input("x", "link.nessus")}})
	if res.Status != tool.StatusFailed || res.Err == nil || res.Err.Class != tool.InvalidInput || !strings.Contains(res.Err.Detail, "link") {
		t.Fatalf("status %s err %v", res.Status, res.Err)
	}
}

func TestImportTool_LogsIssuesWithLines(t *testing.T) {
	bad := []byte("{\"findings\": [\n{\"title\": \"ok\", \"severity\": \"High\"},\n{\"severity\": \"Low\"}\n]}")
	res := testkit.Run(t, importtool.New(), tool.Task{Inputs: []tool.Input{input("dd", "dd.json")}},
		testkit.Options{Files: map[string][]byte{"dd.json": bad}})
	res.RequireStatus(t, tool.StatusOK)
	found := false
	for _, l := range res.Logs {
		if l.Msg == "input problem" && l.Attrs["line"] == int64(3) || l.Msg == "input problem" && l.Attrs["line"] == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no problem logged at line 3: %+v", res.Logs)
	}
}

func TestImportTool_Manifest(t *testing.T) {
	m := importtool.New().Manifest()
	if m.Class != tool.Parser || m.Permissions.Network != tool.NetNone || m.Permissions.Filesystem != tool.FSWorkdir {
		t.Fatalf("manifest grants more than a parser needs: %+v", m.Permissions)
	}
	if len(m.Permissions.Credentials) != 0 {
		t.Fatal("a parser needs no credential")
	}
	if !bytes.Contains(m.Config, []byte(`"min_severity"`)) {
		t.Fatalf("config schema: %s", m.Config)
	}
}

// A VEX document produces no record: its statements go to the artifact,
// for the platform to apply under its VEX mode.
func TestImportTool_VEXGoesToTheArtifact(t *testing.T) {
	res := testkit.Run(t, importtool.New(), tool.Task{Inputs: []tool.Input{input("vex", "image-vex.json")}},
		testkit.Options{Files: map[string][]byte{"image-vex.json": fixture(t, "image-vex.json")}})
	res.RequireStatus(t, tool.StatusOK)
	if len(res.Report.Findings) != 0 || len(res.Report.Assets) != 0 {
		t.Fatalf("a VEX document emitted %d findings and %d assets", len(res.Report.Findings), len(res.Report.Assets))
	}
	var doc struct {
		Statements []struct {
			VEX struct {
				Status string `json:"status"`
			} `json:"vex"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(res.Artifacts[importtool.VEXArtifact], &doc); err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if len(doc.Statements) == 0 || doc.Statements[0].VEX.Status == "" {
		t.Fatalf("artifact holds no statement: %s", res.Artifacts[importtool.VEXArtifact])
	}
}
