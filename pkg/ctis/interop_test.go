package ctis

import (
	"encoding/json"
	"testing"
	"time"
)

// The CTIS 1.4 interoperability members and their normalizers are reachable
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
	r.Metadata.Timestamp = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	v := 8.1
	f := Finding{
		Type: FindingTypeVulnerability, Title: "t", Severity: SeverityHigh,
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

// The version bump keeps older reports readable: every supported version
// decodes and validates, 1.3 included.
func TestSupportedVersionsReExported(t *testing.T) {
	vs := SupportedSchemaVersions()
	if len(vs) == 0 || vs[len(vs)-1] != SchemaVersion || SchemaVersion != "1.4" {
		t.Fatalf("supported %v, current %s", vs, SchemaVersion)
	}
	if !IsSupportedVersion("1.3") || IsSupportedVersion("1.5") {
		t.Fatal("IsSupportedVersion")
	}
	var r Report
	if err := json.Unmarshal([]byte(`{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high"}]}`), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("a 1.3 report no longer validates: %v", err)
	}
}
