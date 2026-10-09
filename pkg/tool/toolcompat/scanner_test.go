package toolcompat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
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

// capTool implements scan.ports@1; the standard param top_n reaches it as
// its key top.
var capTool = tool.Define("cap-ports", "1.0.0").
	ImplementsWith(tool.Implementation{Capability: "scan.ports@1", Params: map[string]tool.ParamMapping{"top_n": {Key: "top"}}}).
	Targets("domain").Produces("asset:open_port").
	Params(tool.IntParam("top").Default(10).Range(1, 65535)).
	Manifest(func(m *tool.Manifest) { m.Permissions.Network = tool.NetNone }).
	BatchTargets(10).
	Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
		for _, t := range job.Targets() {
			a := ctis.Asset{Type: "open_port", Value: t.Value + ":443",
				Properties: ctis.Properties{"host": t.Value, "port": 443, "protocol": "tcp", "top": job.Param("top").Int()}}
			if err := emit.CTIS().Asset(a); err != nil {
				return err
			}
			ctx.TargetDone(t)
		}
		return nil
	}).MustBuild()

func TestCapabilityJobReachesTheTool(t *testing.T) {
	s := AsScanner(capTool, ScannerConfig{Host: host(t)})
	if !s.(core.CapabilityScanner).TakesCapabilityJobs() || AsScanner(plain, ScannerConfig{Host: host(t)}).(core.CapabilityScanner).TakesCapabilityJobs() {
		t.Fatal("TakesCapabilityJobs")
	}
	c := s.(core.ToolContractProvider).ToolContract()
	if c.Origin != core.ToolOriginBuiltin || len(c.Descriptor) == 0 || c.Implements[0] != "scan.ports@1" {
		t.Fatalf("contract %+v", c)
	}
	res, err := s.(core.MultiTargetScanner).ScanTargets(context.Background(), []string{"a.example"},
		&core.ScanOptions{Capability: "scan.ports@1", Params: map[string]json.RawMessage{"top_n": json.RawMessage("5")}, MaxTier: "T1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.RawOutput), `"top":5`) || !strings.Contains(string(res.RawOutput), `"capability":"scan.ports@1"`) {
		t.Fatalf("output %s", res.RawOutput)
	}
	// SECURITY: a tier ceiling below the tool fails the scan.
	if _, err := s.Scan(context.Background(), "a.example", &core.ScanOptions{Capability: "scan.ports@1", MaxTier: "T0"}); err == nil || !strings.Contains(err.Error(), "allows at most T0") {
		t.Fatalf("tier ceiling: %v", err)
	}
	// An operator-installed tool reports its origin as adapter.
	m := capTool.Manifest()
	m.Run = &tool.RunSpec{Argv: []string{"/bin/true"}}
	if AsScanner(manifestOnly{m}, ScannerConfig{Host: host(t)}).(core.ToolContractProvider).ToolContract().Origin != core.ToolOriginAdapter {
		t.Fatal("adapter origin")
	}
}

// The organization HTTP policy from the job reaches the tool host: a tool
// that skips TLS verification is refused when the organization forbids it.
// insecureTool skips TLS verification toward its targets (tool.yaml http).
var insecureTool = tool.Define("insecure-ports", "1.0.0").
	ImplementsWith(tool.Implementation{Capability: "scan.ports@1"}).
	Targets("domain").Produces("asset:open_port").
	Manifest(func(m *tool.Manifest) {
		m.Permissions.Network = tool.NetTargets
		m.HTTP = &tool.HTTPSpec{TLS: &tool.TLSSpec{InsecureSkipVerify: true}}
	}).
	Handle(func(ctx tool.Context, job *tool.Job, _ tool.Emit) error {
		for _, t := range job.Targets() {
			ctx.TargetDone(t)
		}
		return nil
	}).MustBuild()

func TestOrgHTTPPolicyReachesTheHost(t *testing.T) {
	s := AsScanner(insecureTool, ScannerConfig{Host: host(t)})
	no := false
	_, err := s.Scan(context.Background(), "a.example", &core.ScanOptions{Capability: "scan.ports@1", OrgHTTP: &core.OrgHTTPPolicy{AllowInsecureTLS: &no}})
	if err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("organization policy not applied: %v", err)
	}
	if _, err := s.Scan(context.Background(), "a.example", &core.ScanOptions{Capability: "scan.ports@1"}); err != nil {
		t.Fatalf("without the policy: %v", err)
	}
}
