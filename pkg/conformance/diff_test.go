package conformance

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

func baseDiffManifest() tool.Manifest {
	return tool.Manifest{Name: "ports", Version: "1.2.0", Class: tool.TargetScan, Tier: tool.T1,
		Implements: []tool.Implementation{{Capability: "scan.ports@1", OutputShape: "open_port_assets",
			Params: map[string]tool.ParamMapping{"ports": {}, "protocol": {Values: []string{"tcp"}}, "rate": {Max: intp(5000)}}}},
		Consumes: []string{"ip_address", "domain"}, Produces: []string{"asset:open_port", "asset:ip_address"},
		Config:      json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"ports":{"type":"string"},"protocol":{"type":"string"},"rate":{"type":"integer"}}}`),
		Permissions: tool.Permissions{Network: tool.NetTargets}}
}

func intp(n int) *int { return &n }

func TestDiffManifests(t *testing.T) {
	cases := map[string]struct {
		edit    func(m *tool.Manifest)
		version string
		bump    Bump
		ok      bool
		want    string
	}{
		"unchanged":                {func(*tool.Manifest) {}, "1.2.0", BumpNone, true, ""},
		"description patch":        {func(m *tool.Manifest) { m.Description = "faster" }, "1.2.1", BumpPatch, true, ""},
		"description no bump":      {func(m *tool.Manifest) { m.Description = "faster" }, "1.2.0", BumpPatch, false, "need a patch"},
		"narrowed produces":        {func(m *tool.Manifest) { m.Produces = []string{"asset:open_port"} }, "1.3.0", BumpMajor, false, "no longer produces asset:ip_address"},
		"narrowed produces, major": {func(m *tool.Manifest) { m.Produces = []string{"asset:open_port"} }, "2.0.0", BumpMajor, true, ""},
		"narrowed consumes":        {func(m *tool.Manifest) { m.Consumes = []string{"ip_address"} }, "1.3.0", BumpMajor, false, "no longer consumes domain"},
		"dropped capability":       {func(m *tool.Manifest) { m.Implements = nil }, "1.3.0", BumpMajor, false, "no longer implements scan.ports@1"},
		"dropped param":            {func(m *tool.Manifest) { delete(m.Implements[0].Params, "ports") }, "1.3.0", BumpMajor, false, "no longer takes the param ports"},
		"narrowed values": {func(m *tool.Manifest) {
			m.Implements[0].Params["protocol"] = tool.ParamMapping{Values: []string{"udp"}}
		}, "1.3.0", BumpMajor, false, `no longer supports "tcp"`},
		"narrowed bound":  {func(m *tool.Manifest) { m.Implements[0].Params["rate"] = tool.ParamMapping{Max: intp(100)} }, "1.3.0", BumpMajor, false, "bounds narrowed"},
		"new value limit": {func(m *tool.Manifest) { m.Implements[0].Params["ports"] = tool.ParamMapping{Values: []string{"x"}} }, "1.3.0", BumpMajor, false, "now supports only"},
		"shape changed":   {func(m *tool.Manifest) { m.Implements[0].OutputShape = "ip_ports" }, "1.3.0", BumpMajor, false, "output shape changed"},
		"tier raised":     {func(m *tool.Manifest) { m.Tier = tool.T2 }, "1.3.0", BumpMajor, false, "minimum tier raised"},
		"side effect": {func(m *tool.Manifest) {
			m.Tier = tool.T2
			m.Safety = &tool.Safety{SideEffects: []string{"ioc_in_logs"}}
		}, "2.0.0", BumpMajor, true, ""},
		"class changed": {func(m *tool.Manifest) { m.Class = tool.Connector }, "1.3.0", BumpMajor, false, "class changed"},
		"config removed": {func(m *tool.Manifest) {
			m.Config = json.RawMessage(`{"type":"object","properties":{"ports":{"type":"string"},"protocol":{"type":"string"}}}`)
		}, "1.3.0", BumpMajor, false, "config key rate removed"},
		"config required": {func(m *tool.Manifest) {
			m.Config = json.RawMessage(strings.Replace(string(m.Config), `"type":"object"`, `"type":"object","required":["ports"]`, 1))
		}, "1.3.0", BumpMajor, false, "now required"},
		"added consumes":   {func(m *tool.Manifest) { m.Consumes = append(m.Consumes, "subdomain") }, "1.3.0", BumpMinor, true, ""},
		"added consumes p": {func(m *tool.Manifest) { m.Consumes = append(m.Consumes, "subdomain") }, "1.2.1", BumpMinor, false, "need a minor"},
		"added capability": {func(m *tool.Manifest) {
			m.Implements = append(m.Implements, tool.Implementation{Capability: "probe.http@1"})
		}, "1.3.0", BumpMinor, true, ""},
		"added param": {func(m *tool.Manifest) { m.Implements[0].Params["top_n"] = tool.ParamMapping{} }, "1.3.0", BumpMinor, true, ""},
		"added config": {func(m *tool.Manifest) {
			m.Config = json.RawMessage(strings.Replace(string(m.Config), `"rate":`, `"extra":{"type":"string"},"rate":`, 1))
		}, "1.3.0", BumpMinor, true, ""},
		"renamed":       {func(m *tool.Manifest) { m.Name = "other" }, "1.2.0", BumpPatch, false, "another tool"},
		"older version": {func(m *tool.Manifest) { m.Description = "x" }, "1.1.0", BumpPatch, false, "older than"},
		"bad version":   {func(m *tool.Manifest) { m.Description = "x" }, "latest", BumpPatch, false, "not both semantic versions"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			oldM := baseDiffManifest()
			newM := baseDiffManifest()
			newM.Implements = slices.Clone(newM.Implements)
			params := map[string]tool.ParamMapping{}
			for k, v := range oldM.Implements[0].Params {
				params[k] = v
			}
			newM.Implements[0].Params = params
			tc.edit(&newM)
			newM.Version = tc.version
			d := DiffManifests(oldM, newM)
			all := strings.Join(append(append(d.Breaking, d.Additions...), d.Problems...), "; ")
			if d.Required != tc.bump || d.OK() != tc.ok || (tc.want != "" && !strings.Contains(all, tc.want)) {
				t.Fatalf("bump %s ok %v: %s", d.Required, d.OK(), all)
			}
		})
	}
	if BumpMajor.String() != "major" {
		t.Fatal("String")
	}
}
