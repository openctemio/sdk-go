package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// capScanner is a scanner on the tool contract.
type capScanner struct {
	fakeScanner
	takes bool
}

func (c *capScanner) TakesCapabilityJobs() bool { return c.takes }

func (c *capScanner) ToolContract() *ToolContract {
	desc := json.RawMessage(`{"name":"ports"}`)
	sum := sha256.Sum256(desc)
	return &ToolContract{APIVersion: "openctem.io/tool/v1", Digest: "sha256:" + hex.EncodeToString(sum[:]), Version: "1.0.0",
		Class: "target-scan", Tier: "T1", Produces: []string{"asset:open_port"},
		Implements: []string{"scan.ports@1"}, Batch: true, Origin: ToolOriginBuiltin, Descriptor: desc}
}

func TestApplyCapabilityJob(t *testing.T) {
	ports := &capScanner{fakeScanner: fakeScanner{name: "ports"}, takes: true}
	params := map[string]json.RawMessage{"top_n": json.RawMessage(`100`)}
	opts := &ScanOptions{}
	if err := applyCapabilityJob(opts, ports, &ScanCommandPayload{Scanner: "ports", Capability: "scan.ports@1", Params: params, MaxTier: "T1"}); err != nil {
		t.Fatal(err)
	}
	if opts.Capability != "scan.ports@1" || string(opts.Params["top_n"]) != "100" || opts.MaxTier != "T1" {
		t.Fatalf("opts %+v", opts)
	}
	// A plain job is untouched, for any scanner.
	if err := applyCapabilityJob(&ScanOptions{}, &fakeScanner{name: "legacy"}, &ScanCommandPayload{Scanner: "legacy"}); err != nil {
		t.Fatal(err)
	}

	big := map[string]json.RawMessage{}
	for i := 0; i < 65; i++ {
		big[strings.Repeat("k", i+1)] = json.RawMessage(`1`)
	}
	cases := map[string]struct {
		s    Scanner
		p    ScanCommandPayload
		want string
	}{
		// SECURITY: settings a scanner cannot apply are never dropped.
		"legacy scanner":          {&fakeScanner{name: "legacy"}, ScanCommandPayload{Scanner: "legacy", Capability: "scan.ports@1"}, "does not run capability jobs"},
		"scanner that declines":   {&capScanner{takes: false}, ScanCommandPayload{Scanner: "x", Params: params}, "does not run capability jobs"},
		"legacy with a tier only": {&fakeScanner{name: "legacy"}, ScanCommandPayload{Scanner: "legacy", MaxTier: "T0"}, "does not run capability jobs"},
		"no major":                {ports, ScanCommandPayload{Capability: "scan.ports"}, "want id@major"},
		"look-alike":              {ports, ScanCommandPayload{Capability: "Scan.Ports@1"}, "want id@major"},
		"params without ref":      {ports, ScanCommandPayload{Params: params}, "need the job's capability"},
		"bad tier":                {ports, ScanCommandPayload{Capability: "scan.ports@1", MaxTier: "T9"}, "invalid max_tier"},
		"too many params":         {ports, ScanCommandPayload{Capability: "scan.ports@1", Params: big}, "at most 64"},
		"huge param": {ports, ScanCommandPayload{Capability: "scan.ports@1",
			Params: map[string]json.RawMessage{"ports": json.RawMessage(`"` + strings.Repeat("1", 20000) + `"`)}}, "too large"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			opts := &ScanOptions{}
			err := applyCapabilityJob(opts, tc.s, &tc.p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if opts.Capability != "" || opts.Params != nil {
				t.Fatal("options set on a refused job")
			}
		})
	}
}

// A tool on the contract serves the capabilities it implements; its full
// descriptor travels in the manifest, never on the heartbeat.
func TestManifestCarriesTheDescriptor(t *testing.T) {
	r := NewToolRegistry()
	if err := r.RegisterScanner(&capScanner{fakeScanner: fakeScanner{name: "ports"}, takes: true}); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(context.Background())
	if len(rep.Tools) != 1 || !slices.Contains(rep.Tools[0].Capabilities, "scan.ports") {
		t.Fatalf("tool capabilities %+v", rep.Tools)
	}
	hb, _ := json.Marshal(rep.Tools[0])
	if strings.Contains(string(hb), "descriptor") || strings.Contains(string(hb), "implements") {
		t.Fatalf("the heartbeat form carries the contract: %s", hb)
	}

	status := &SensorStatus{Tools: rep.Tools, Capabilities: rep.Capabilities}
	m := BuildManifest(status, nil, "")
	c := m.Tools[0].Contract
	if c == nil || c.Origin != ToolOriginBuiltin || !c.Batch || !slices.Equal(c.Implements, []string{"scan.ports@1"}) {
		t.Fatalf("contract %+v", c)
	}
	sum := sha256.Sum256(c.Descriptor)
	if c.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("the descriptor does not hash to the digest")
	}
	raw, _ := json.Marshal(m)
	if !strings.Contains(string(raw), `"descriptor":{"name":"ports"}`) || !strings.Contains(string(raw), `"origin":"builtin"`) {
		t.Fatalf("manifest %s", raw)
	}
	// The manifest's copy is not shared with the registry.
	c.Implements[0] = "x"
	c.Descriptor[0] = 'x'
	again := BuildManifest(status, nil, "").Tools[0].Contract
	if again.Implements[0] != "scan.ports@1" || again.Descriptor[0] != '{' {
		t.Fatal("BuildManifest shares the contract")
	}
	if (*ToolContract)(nil).capabilityIDs() != nil {
		t.Fatal("nil contract")
	}
}

// The descriptors of one manifest stay within their budget: the largest are
// left out (their digest and contract fields stay), deterministically.
func TestManifestDescriptorBudget(t *testing.T) {
	big := func(n int) json.RawMessage { return json.RawMessage(`"` + strings.Repeat("a", n) + `"`) }
	tools := []ManifestTool{
		{Name: "a", Contract: &ToolContract{Digest: "sha256:a", Descriptor: big(60 << 10)}},
		{Name: "b", Contract: &ToolContract{Digest: "sha256:b", Descriptor: big(60 << 10)}},
		{Name: "c", Contract: &ToolContract{Digest: "sha256:c", Descriptor: big(20 << 10)}},
		{Name: "d"},
	}
	budgetDescriptors(tools)
	kept := 0
	for _, tl := range tools {
		if tl.Contract != nil && len(tl.Contract.Descriptor) > 0 {
			kept += len(tl.Contract.Descriptor)
		}
	}
	if kept > MaxManifestDescriptorBytes || tools[0].Contract.Descriptor != nil || tools[1].Contract.Descriptor == nil || tools[2].Contract.Descriptor == nil {
		t.Fatalf("kept %d bytes; a=%d b=%d c=%d", kept, len(tools[0].Contract.Descriptor), len(tools[1].Contract.Descriptor), len(tools[2].Contract.Descriptor))
	}
	if tools[0].Contract.Digest != "sha256:a" {
		t.Fatal("the digest must stay when the descriptor is left out")
	}
	small := []ManifestTool{{Name: "x", Contract: &ToolContract{Descriptor: big(10)}}}
	budgetDescriptors(small)
	if small[0].Contract.Descriptor == nil {
		t.Fatal("a manifest within the budget is unchanged")
	}
}
