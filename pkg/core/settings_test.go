package core

import (
	"encoding/json"
	"strings"
	"testing"
)

// The schema contract itself is tested in github.com/openctemio/ctis/settings;
// here only what the SDK adds: the manifest names a schema by digest.

const testNucleiSchema = `{
  "x-octm-schema-version": 3,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 150, "x-octm-scope": "scan"},
    "concurrency": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
    "severity": {"type": "array", "uniqueItems": true, "items": {"enum": ["low", "medium", "high", "critical"]}, "default": ["high", "critical"], "x-octm-scope": "scan"},
    "timeout": {"type": "string", "format": "duration", "default": "10s"},
    "net": {"type": "object", "additionalProperties": false, "properties": {
      "retries": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1, "x-octm-scope": "scan"}
    }}
  }
}`

func TestSettingsManifestCarriesDigestNotSchema(t *testing.T) {
	s := MustParseSettingsSchema(testNucleiSchema)
	r := NewToolRegistry()
	if err := r.Register(ToolSpec{Name: "nuclei", Settings: s}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ToolSpec{Name: "trivy"}); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(t.Context())
	status := &SensorStatus{Tools: rep.Tools, Capabilities: rep.Capabilities}
	m := BuildManifest(status, nil, "")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `"settings":{"schema_version":3,"digest":"` + s.Digest() + `"}`
	if !strings.Contains(string(raw), want) || strings.Count(string(raw), `"settings"`) != 1 {
		t.Fatalf("manifest = %s, want one %s", raw, want)
	}
	if strings.Contains(string(raw), "rate_limit") {
		t.Fatal("the manifest carries the schema itself")
	}
	// The heartbeat's tool inventory does not carry it.
	hb, _ := json.Marshal(rep.Tools)
	if strings.Contains(string(hb), "settings") {
		t.Fatalf("heartbeat tools carry settings: %s", hb)
	}
	if r.SettingsSchema("NUCLEI") != s || r.SettingsSchema("trivy") != nil {
		t.Fatal("registry lookup")
	}
	if got := r.SettingsSchemas(); len(got) != 1 || got["nuclei"] != s {
		t.Fatalf("SettingsSchemas = %v", got)
	}
}
