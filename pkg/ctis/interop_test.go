package ctis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The CTIS interoperability members and their normalizers are reachable
// through pkg/ctis, and a report that uses them validates.
func TestInteropMembersReExported(t *testing.T) {
	sev, ok := NormalizeNativeSeverity(NativeSchemeQualys, "5")
	if !ok || sev != SeverityCritical {
		t.Fatalf("qualys 5 = %q, %v", sev, ok)
	}
	if _, state, ok := NormalizeNativeStatus(NativeSchemeQualys, "Re-Opened"); !ok || state != SourceStateReopened {
		t.Fatalf("qualys Re-Opened = %q, %v", state, ok)
	}
	if j, ok := NormalizeVEXJustification("code_not_reachable"); !ok || j != VEXJustificationVulnerableCodeNotInExecutePath {
		t.Fatalf("justification = %q, %v", j, ok)
	}

	r := NewReport()
	r.Metadata.GeneratedAt = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	r.Assets = []Asset{{ID: "h1", Type: AssetTypeHost, Value: "app.example.com"}}
	v := 8.1
	f := Finding{
		Type: FindingTypeVulnerability, Title: "t", Severity: SeverityHigh, AssetRef: "h1",
		Native:        &NativeIdentity{Scheme: NativeSchemeNessus, VulnID: "201194", Severity: "3"},
		Scores:        []Score{{System: ScoreSystemCVSS, Version: "3.1", Value: &v, Source: "nvd"}},
		VEX:           &VEX{Status: VEXStatusNotAffected, Justification: VEXJustificationComponentNotPresent},
		Vulnerability: &VulnerabilityDetails{IDs: []VulnerabilityID{{Type: VulnerabilityIDCVE, ID: "CVE-2024-6387"}}},
	}
	if !SetSourceExtra(&f, "plugin_type", "remote") {
		t.Fatal("SetSourceExtra refused a small entry")
	}
	r.Findings = []Finding{f}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := LocationKey(&Finding{Network: &NetworkLocation{Port: 22}}); got != "net:22/tcp" {
		t.Errorf("LocationKey = %q", got)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
}

// The SDK produces CTIS 2.0 only: the module supports 2.x and nothing of
// 1.x, and a 1.x document does not decode.
func TestSupportedVersionsReExported(t *testing.T) {
	if SchemaVersion != "2.0" || !IsSupportedVersion("2.0") || IsSupportedVersion("1.6") {
		t.Fatalf("supported %v, current %s", SupportedSchemaVersions(), SchemaVersion)
	}
	legacy := `{"version":"1` + `.6","metadata":{"time` + `stamp":"2026-10-02T00:00:00Z"}}`
	if _, _, err := Decode(strings.NewReader(legacy)); err == nil {
		t.Fatal("a 1.x report decoded")
	}
}
