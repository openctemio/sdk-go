package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type contractScanner struct{ fakeContractScanner }

type fakeContractScanner struct{}

func (fakeContractScanner) Name() string           { return "httpx" }
func (fakeContractScanner) Version() string        { return "v1" }
func (fakeContractScanner) Capabilities() []string { return []string{"recon"} }
func (fakeContractScanner) Scan(context.Context, string, *ScanOptions) (*ScanResult, error) {
	return nil, nil
}
func (fakeContractScanner) IsInstalled(context.Context) (bool, string, error) { return true, "v1", nil }

func (contractScanner) ToolContract() *ToolContract {
	return &ToolContract{APIVersion: "openctem.io/tool/v1", Digest: "sha256:abc", Version: "1.0.0",
		Class: "target-scan", Tier: "T1", Network: "targets", Produces: []string{"asset:http_service"}}
}

// A scanner ported to the tool contract is reported with its contract in
// the manifest (not on the heartbeat); others are reported as before.
func TestManifestCarriesToolContract(t *testing.T) {
	r := NewToolRegistry()
	if err := r.RegisterScanner(contractScanner{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ToolSpec{Name: "semgrep"}); err != nil {
		t.Fatal(err)
	}
	tools := r.Installed(context.Background())
	m := BuildManifest(&SensorStatus{Tools: tools}, nil, "")
	b, _ := json.Marshal(m)
	if !strings.Contains(string(b), `"contract":{"api_version":"openctem.io/tool/v1","digest":"sha256:abc"`) {
		t.Fatalf("manifest %s", b)
	}
	if strings.Count(string(b), `"contract"`) != 1 {
		t.Fatalf("a tool without a contract got one: %s", b)
	}
	hb, _ := json.Marshal(tools)
	if strings.Contains(string(hb), "contract") {
		t.Fatalf("the contract is on the heartbeat: %s", hb)
	}
}
