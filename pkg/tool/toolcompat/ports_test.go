package toolcompat

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// oddPortsTool implements scan.ports@1 with its port list under the key
// svc_set and its top-N count under n_common: names only its manifest ties
// to the standard params ports and top_n.
var oddPortsTool = tool.Define("odd-ports", "1.0.0").
	ImplementsWith(tool.Implementation{Capability: "scan.ports@1", Params: map[string]tool.ParamMapping{
		"ports": {Key: "svc_set"}, "top_n": {Key: "n_common"}, "protocol": {}}}).
	Targets("domain_name").Produces("asset:service").
	Params(tool.StringParam("svc_set").PerScan().MaxLength(256), tool.IntParam("n_common").Default(100).Range(1, 65535).PerScan(),
		tool.StringParam("protocol").OneOf("tcp").Default("tcp")).
	Manifest(func(m *tool.Manifest) { m.Permissions.Network = tool.NetNone }).
	Handle(func(ctx tool.Context, job *tool.Job, _ tool.Emit) error {
		for _, t := range job.Targets() {
			ctx.TargetDone(t)
		}
		return nil
	}).MustBuild()

// The scanner says which of its config keys name ports from its manifest's
// mapping of the capability's standard params, so ports.allow follows the
// key wherever the tool puts it.
func TestToolScannerPortSettings(t *testing.T) {
	got := AsScanner(oddPortsTool, ScannerConfig{Host: host(t)}).(core.PortSettingsProvider).PortSettings()
	want := map[string]core.PortSettingKind{"svc_set": core.PortSettingList, "n_common": core.PortSettingTopN}
	if !maps.Equal(got, want) {
		t.Fatalf("port settings %v, want %v", got, want)
	}
	// A tool that implements no capability, or one without port params,
	// declares none (its settings are judged by their names).
	if got := AsScanner(plain, ScannerConfig{Host: host(t)}).(core.PortSettingsProvider).PortSettings(); len(got) != 0 {
		t.Fatalf("plain tool: %v", got)
	}
	if got := AsScanner(capTool, ScannerConfig{Host: host(t)}).(core.PortSettingsProvider).PortSettings(); !maps.Equal(got, map[string]core.PortSettingKind{"top": core.PortSettingTopN}) {
		t.Fatalf("capTool: %v", got)
	}
}

// End to end: a manifest tool whose port list is called svc_set cannot be
// handed ports outside the sensor's ports.allow by a settings layer of the
// job (the tenant's layer reaches the tool's config), nor run its default
// top-N list; a list inside runs.
func TestManifestToolPortsStayInsideLocalPolicy(t *testing.T) {
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\nports:\n  allow: \"80,443\"\n"),
		core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	e := core.NewDefaultCommandExecutor(nil)
	e.AddScanner(AsScanner(oddPortsTool, ScannerConfig{Host: host(t)}))
	e.SetLocalPolicy(lp)
	e.SetScanTargetPolicy(&core.ScanTargetPolicy{})
	run := func(payload string) error {
		raw := `{"scanner":"odd-ports","target":"203.0.113.9",` + payload + `}`
		_, err := e.Execute(context.Background(), &core.Command{ID: "c", Type: "scan", Payload: json.RawMessage(raw)})
		return err
	}
	for name, payload := range map[string]string{
		"layer, outside":     `"settings_layers":{"tenant":{"svc_set":"1-65535"}}`,
		"layer, one outside": `"settings_layers":{"sensor":{"svc_set":"80,22"}}`,
		"default top-N":      `"config":{}`,
	} {
		if err := run(payload); !errors.Is(err, core.ErrRefusedByLocalPolicy) {
			t.Errorf("%s: err %v, want a local policy refusal", name, err)
		}
	}
	if err := run(`"settings_layers":{"tenant":{"svc_set":"80,443"}}`); err != nil {
		t.Errorf("ports inside ports.allow: %v", err)
	}
}

// bareScanPortsTool implements scan.ports with no default port list or
// top-N count: run without ports, it scans whatever its own default is.
var bareScanPortsTool = tool.Define("bare-ports", "1.0.0").
	ImplementsWith(tool.Implementation{Capability: "scan.ports@1", Params: map[string]tool.ParamMapping{"ports": {}}}).
	Targets("domain_name").Produces("asset:service").
	Params(tool.StringParam("ports").PerScan().MaxLength(256), tool.IntParam("rate").Range(1, 1000).PerScan()).
	Manifest(func(m *tool.Manifest) { m.Permissions.Network = tool.NetNone }).
	Handle(func(ctx tool.Context, job *tool.Job, _ tool.Emit) error {
		for _, t := range job.Targets() {
			ctx.TargetDone(t)
		}
		return nil
	}).MustBuild()

// A job for a tool whose manifest implements scan.ports is a port scan even
// when the job names no capability or another one: under ports.allow it
// must name its ports.
func TestPortScannerJobWithoutCapabilityMustNamePorts(t *testing.T) {
	if !AsScanner(bareScanPortsTool, ScannerConfig{Host: host(t)}).(core.PortScanImplementer).ImplementsPortScan() {
		t.Fatal("a scan.ports tool does not say it is a port scanner")
	}
	if AsScanner(plain, ScannerConfig{Host: host(t)}).(core.PortScanImplementer).ImplementsPortScan() {
		t.Fatal("a tool without scan.ports says it is a port scanner")
	}
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\nports:\n  allow: \"80,443\"\n"),
		core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	e := core.NewDefaultCommandExecutor(nil)
	e.AddScanner(AsScanner(bareScanPortsTool, ScannerConfig{Host: host(t)}))
	e.SetLocalPolicy(lp)
	e.SetScanTargetPolicy(&core.ScanTargetPolicy{})
	run := func(payload string) error {
		raw := `{"scanner":"bare-ports","target":"203.0.113.9",` + payload + `}`
		_, err := e.Execute(context.Background(), &core.Command{ID: "c", Type: "scan", Payload: json.RawMessage(raw)})
		return err
	}
	for name, payload := range map[string]string{
		"no capability":    `"config":{"rate":10}`,
		"other capability": `"capability":"probe.http@1","config":{"rate":10}`,
	} {
		if err := run(payload); !errors.Is(err, core.ErrRefusedByLocalPolicy) {
			t.Errorf("%s: err %v, want a local policy refusal", name, err)
		}
	}
	if err := run(`"config":{"ports":"443"}`); err != nil {
		t.Errorf("ports inside ports.allow: %v", err)
	}
}
