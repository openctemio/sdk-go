package toolhost

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// An exec tool receives a capability's list params as repeated arguments,
// optional values only when set, and switches only when true: no param
// is silently dropped, and nothing empty reaches the tool's argv.
func TestExecArgvForms(t *testing.T) {
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "argv-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
		Consumes: []string{"repository"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetNone},
		Config: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
			"record_types":{"type":"array","items":{"type":"string","enum":["a","aaaa","mx"]}},
			"resolver":{"type":"string"},
			"wildcard":{"type":"boolean"}}}`),
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe,
			"{{config.record_types...}}", "-t={{config.record_types...}}", "-r={{config.resolver?}}", "{{config.wildcard?:-wd}}", "end"},
			Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		`{"record_types":["a","mx"],"resolver":"9.9.9.9","wildcard":true}`: "a|mx|-t=a,mx|-r=9.9.9.9|-wd|end",
		`{"record_types":[],"wildcard":false}`:                             "end",
		`{}`:                                                               "end",
		`{"resolver":"1.1.1.1"}`:                                           "-r=1.1.1.1|end",
	}
	for cfg, want := range cases {
		task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "github.com/acme/app"}}, Config: json.RawMessage(cfg)}
		out, err := testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != want {
			t.Errorf("config %s: argv %+v (status %s, err %v), want %q", cfg, out.Report.Findings, out.Status, out.Err, want)
		}
	}
	// SECURITY: a list item that would be a flag is refused, like any value.
	task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "x"}}, Config: json.RawMessage(`{"resolver":"-o=/etc/x"}`)}
	out, _ := testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if out.Status != tool.StatusFailed || out.Err.Class != tool.InvalidInput {
		t.Fatalf("flag injection through an optional value: %s %v", out.Status, out.Err)
	}
}
