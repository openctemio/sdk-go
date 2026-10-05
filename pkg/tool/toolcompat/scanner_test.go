package toolcompat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func TestAsScanner(t *testing.T) {
	ctx := context.Background()
	s := AsScanner(configured, ScannerConfig{Host: host(t)})
	if s.Name() != "legacy-config" || s.Version() != "2.4.1" || s.Capabilities()[0] != "misconfiguration" {
		t.Fatalf("identity %s %s %v", s.Name(), s.Version(), s.Capabilities())
	}
	if c := s.(core.ToolContractProvider).ToolContract(); c == nil || c.Digest != configured.Manifest().Digest() || c.Class != "target-scan" {
		t.Fatalf("contract %+v", c)
	}
	schema := s.(core.SettingsSchemaProvider).SettingsSchema()
	if schema == nil {
		t.Fatal("no settings schema from the manifest")
	}
	settings, err := schema.Resolve(core.SettingsLayer{Source: core.SettingSourceSensor, Values: map[string]any{"depth": json.Number("3")}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(ctx, "a.example", &core.ScanOptions{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.RawOutput), "depth 3") || res.ScannerName != "legacy-config" {
		t.Fatalf("result %+v", string(res.RawOutput))
	}
	// The raw output is CTIS the command executor's parsers read.
	p, err := core.NewParserRegistry().ForScanner(s.Name(), res.RawOutput)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := p.Parse(ctx, res.RawOutput, &core.ParseOptions{}); err != nil || len(r.Findings) != 1 {
		t.Fatalf("parse %v %+v", err, r)
	}

	// A task that fails is an error; a partial one is a result.
	if _, err := AsScanner(plain, ScannerConfig{Host: host(t)}).Scan(ctx, "down.example", nil); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("a failed task: %v", err)
	}
	ms := AsScanner(plain, ScannerConfig{Host: host(t)}).(core.MultiTargetScanner)
	res, err = ms.ScanTargets(ctx, []string{"a.example", "down.example"}, nil)
	if err != nil || !strings.Contains(string(res.RawOutput), "a.example") {
		t.Fatalf("a partial task: %v", err)
	}

	// Credentials come from the config, per task.
	calls := 0
	st := AsScanner(stateful, ScannerConfig{Host: host(t), Credentials: func() map[string]string {
		calls++
		return map[string]string{"token": "t-1"}
	}})
	res, err = st.Scan(ctx, "a.example", nil)
	if err != nil || calls != 1 || !strings.Contains(string(res.RawOutput), "authenticated") {
		t.Fatalf("credentials: %v calls=%d %s", err, calls, res.RawOutput)
	}
}

func TestAsScannerManifestTool(t *testing.T) {
	m := tool.Manifest{Name: "cli", Version: "0.1.0", Class: tool.TargetScan, Tier: tool.T1,
		Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetNone},
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"./missing-program"}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}}}
	s := AsScanner(manifestOnly{m}, ScannerConfig{Host: host(t), Dir: t.TempDir()})
	if ok, _, err := s.IsInstalled(context.Background()); ok || err == nil {
		t.Fatal("a tool whose program is missing reported installed")
	}
	m.Run.Argv = []string{"/bin/ls"}
	s = AsScanner(manifestOnly{m}, ScannerConfig{Host: host(t)})
	if ok, v, err := s.IsInstalled(context.Background()); !ok || v != "0.1.0" || err != nil {
		t.Fatalf("installed %v %s %v", ok, v, err)
	}
	if s.Version() != "0.1.0" || len(s.Capabilities()) != 0 {
		t.Fatalf("identity %s %v", s.Version(), s.Capabilities())
	}
}

func TestAsScannerPanics(t *testing.T) {
	for name, fn := range map[string]func(){
		"no host":          func() { AsScanner(plain, ScannerConfig{}) },
		"invalid manifest": func() { AsScanner(manifestOnly{tool.Manifest{Name: "X"}}, ScannerConfig{Host: host(t)}) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			fn()
		})
	}
}

type manifestOnly struct{ m tool.Manifest }

func (t manifestOnly) Manifest() tool.Manifest         { return t.m }
func (manifestOnly) Run(tool.Context, tool.Task) error { return nil }
