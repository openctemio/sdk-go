package sarif

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

var sampleSARIFJSON = []byte(`{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "TestScanner",
          "version": "1.0.0",
          "semanticVersion": "1.0.0",
          "organization": "TestOrg",
          "rules": [
            {
              "id": "rule-001",
              "name": "SQL Injection",
              "shortDescription": {"text": "SQL Injection vulnerability detected"},
              "fullDescription": {"text": "User input is used directly in SQL query without sanitization"},
              "helpUri": "https://owasp.org/Top10/A03_2021-Injection/",
              "help": {"text": "Use parameterized queries", "markdown": "Use [parameterized queries](https://owasp.org/sqli)"},
              "defaultConfiguration": {"level": "error"},
              "properties": {
                "tags": ["CWE-89: SQL Injection", "OWASP-A03:2021 - Injection", "security", "high"],
                "precision": "high"
              }
            },
            {
              "id": "rule-002",
              "name": "Hardcoded Secret",
              "shortDescription": {"text": "Hardcoded credential detected"},
              "defaultConfiguration": {"level": "warning"},
              "properties": {"tags": ["CWE-798: Use of Hard-coded Credentials", "security"]}
            },
            {
              "id": "rule-003",
              "name": "Info Disclosure",
              "shortDescription": {"text": "Information disclosure"},
              "defaultConfiguration": {"level": "note"}
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "rule-001",
          "level": "error",
          "message": {"text": "SQL injection in login handler"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/auth/login.go"},
                "region": {"startLine": 42, "endLine": 42, "startColumn": 10, "endColumn": 55, "snippet": {"text": "db.Query(\"SELECT * FROM users WHERE id=\" + userInput)"}}
              }
            }
          ],
          "fingerprints": {"matchBasedId/v1": "abc123def456"},
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/auth/login.go"}, "region": {"startLine": 38}}}},
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/auth/login.go"}, "region": {"startLine": 40}}}},
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/auth/login.go"}, "region": {"startLine": 42}}}}
                  ]
                }
              ]
            }
          ]
        },
        {
          "ruleId": "rule-002",
          "level": "warning",
          "message": {"text": "Hardcoded API key found"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/config/keys.go"},
                "region": {"startLine": 15, "startColumn": 1}
              }
            }
          ]
        },
        {
          "ruleId": "rule-003",
          "level": "note",
          "message": {"text": "Debug endpoint exposed"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/debug/handler.go"},
                "region": {"startLine": 8}
              }
            }
          ]
        }
      ]
    }
  ]
}`)

func TestAdapterName(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "sarif" {
		t.Errorf("expected name 'sarif', got %q", a.Name())
	}
}

func TestAdapterInputFormats(t *testing.T) {
	a := NewAdapter()
	formats := a.InputFormats()
	if len(formats) != 2 || formats[0] != "sarif" || formats[1] != "json" {
		t.Errorf("unexpected input formats: %v", formats)
	}
}

func TestAdapterOutputFormat(t *testing.T) {
	a := NewAdapter()
	if a.OutputFormat() != "ctis" {
		t.Errorf("expected output format 'ctis', got %q", a.OutputFormat())
	}
}

func TestCanConvert_ValidSARIF(t *testing.T) {
	a := NewAdapter()
	if !a.CanConvert(sampleSARIFJSON) {
		t.Error("expected CanConvert to return true for valid SARIF JSON with schema field")
	}
}

func TestCanConvert_ValidSARIFVersionOnly(t *testing.T) {
	a := NewAdapter()
	input := []byte(`{"version": "2.1.0", "runs": []}`)
	if !a.CanConvert(input) {
		t.Error("expected CanConvert to return true for SARIF JSON with only version field")
	}
}

func TestCanConvert_InvalidJSON(t *testing.T) {
	a := NewAdapter()
	if a.CanConvert([]byte(`not json at all`)) {
		t.Error("expected CanConvert to return false for invalid JSON")
	}
}

func TestCanConvert_NotSARIF(t *testing.T) {
	a := NewAdapter()
	if a.CanConvert([]byte(`{"name": "something", "results": []}`)) {
		t.Error("expected CanConvert to return false for valid JSON without schema or version")
	}
}

func TestConvert_Success(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
}

func TestConvert_FindingLocation(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loc := report.Findings[0].Location
	if loc == nil {
		t.Fatal("expected non-nil location")
	}

	if loc.Path != "src/auth/login.go" {
		t.Errorf("expected path 'src/auth/login.go', got %q", loc.Path)
	}

	if loc.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", loc.StartLine)
	}

	if loc.EndLine != 42 {
		t.Errorf("expected end line 42, got %d", loc.EndLine)
	}

	if loc.StartColumn != 10 {
		t.Errorf("expected start column 10, got %d", loc.StartColumn)
	}

	if loc.EndColumn != 55 {
		t.Errorf("expected end column 55, got %d", loc.EndColumn)
	}

	expectedSnippet := `db.Query("SELECT * FROM users WHERE id=" + userInput)`
	if loc.Snippet != expectedSnippet {
		t.Errorf("expected snippet %q, got %q", expectedSnippet, loc.Snippet)
	}
}

func TestConvertWithMinSeverity(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		Repository:  testRepo.Repository,
		MinSeverity: "high",
	}
	report, err := a.Convert(context.Background(), sampleSARIFJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the error-level (high) finding should pass
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding with min severity high, got %d", len(report.Findings))
	}

	if len(report.Findings) > 0 && report.Findings[0].Severity != ctis.SeverityHigh {
		t.Errorf("expected high severity finding, got %q", report.Findings[0].Severity)
	}
}

func TestConvertWithMinSeverityMedium(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		Repository:  testRepo.Repository,
		MinSeverity: "medium",
	}
	report, err := a.Convert(context.Background(), sampleSARIFJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// error (high) + warning (medium) should pass, note (low) should not
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings with min severity medium, got %d", len(report.Findings))
	}
}

func TestConvert_InvalidJSON(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(`not json`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConvert_EmptyRuns(t *testing.T) {
	a := NewAdapter()
	input := []byte(`{"version": "2.1.0", "runs": []}`)
	report, err := a.Convert(context.Background(), input, testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings for empty runs, got %d", len(report.Findings))
	}
}

func TestParseToCTIS(t *testing.T) {
	report, err := ParseToCTIS(sampleSARIFJSON, &core.ParseOptions{
		AssetValue: "github.com/org/repo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if len(report.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(report.Findings))
	}
}

// A SARIF log with results and no repository (no options, no
// versionControlProvenance, not in CI) has no asset to file its findings on:
// it is an error, never findings without an asset or on a shared fake one.
func TestParseToCTIS_NilOptions(t *testing.T) {
	report, err := ParseToCTIS(sampleSARIFJSON, nil)
	if !errors.Is(err, ctis.ErrNoAssetForFindings) {
		t.Fatalf("err = %v, want ctis.ErrNoAssetForFindings", err)
	}
	if report != nil {
		t.Errorf("report = %+v, want nil", report)
	}
	if _, err := NewAdapter().Convert(context.Background(), sampleSARIFJSON, nil); !errors.Is(err, ctis.ErrNoAssetForFindings) {
		t.Fatalf("Convert err = %v, want ctis.ErrNoAssetForFindings", err)
	}
}

// Inside CI the repository of the job names the asset.
func TestConvert_RepositoryFromCI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "org/from-ci")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_SHA", "c0ffee")
	t.Setenv("GITHUB_EVENT_PATH", "")
	report, err := NewAdapter().Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Assets) != 1 || report.Assets[0].Value != "github.com/org/from-ci" {
		t.Fatalf("assets = %+v, want the CI repository", report.Assets)
	}
	if report.Assets[0].Properties["commit_sha"] != "c0ffee" {
		t.Errorf("commit_sha = %v, want c0ffee", report.Assets[0].Properties["commit_sha"])
	}
	if err := ctis.CheckFindingAssets(report); err != nil {
		t.Fatal(err)
	}
}

// versionControlProvenance in the log names the repository when the
// options do not, and wins over CI.
func TestConvert_RepositoryFromProvenance(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "org/from-ci")
	input := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},
		"versionControlProvenance":[{"repositoryUri":"https://github.com/org/app","revisionId":"abc123","branch":"refs/heads/main"}],
		"results":[{"ruleId":"r1","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`)
	report, err := NewAdapter().Convert(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Assets) != 1 || report.Assets[0].Value != "https://github.com/org/app" {
		t.Fatalf("assets = %+v, want the provenance repository", report.Assets)
	}
	if report.Findings[0].AssetRef != report.Assets[0].ID {
		t.Errorf("asset_ref = %q, want %q", report.Findings[0].AssetRef, report.Assets[0].ID)
	}
}

func TestParseToCTIS_WithBranchInfo(t *testing.T) {
	report, err := ParseToCTIS(sampleSARIFJSON, &core.ParseOptions{
		BranchInfo: &ctis.BranchInfo{
			RepositoryURL: "https://github.com/org/repo",
			Name:          "main",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.Metadata.Scope == nil || report.Metadata.Scope.Name != "https://github.com/org/repo" {
		t.Errorf("expected scope name from BranchInfo.RepositoryURL, got %v", report.Metadata.Scope)
	}
}

func TestParseJSONBytes(t *testing.T) {
	sarif, err := ParseJSONBytes(sampleSARIFJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sarif == nil {
		t.Fatal("expected non-nil SARIF report")
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %q", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	if sarif.Runs[0].Tool.Driver.Name != "TestScanner" {
		t.Errorf("expected driver name 'TestScanner', got %q", sarif.Runs[0].Tool.Driver.Name)
	}

	if len(sarif.Runs[0].Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(sarif.Runs[0].Results))
	}

	if len(sarif.Runs[0].Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(sarif.Runs[0].Tool.Driver.Rules))
	}
}

func TestParseJSONBytes_InvalidJSON(t *testing.T) {
	_, err := ParseJSONBytes([]byte(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConvert_SourceTypeMetadata(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Metadata.SourceType != "scanner" {
		t.Errorf("expected source type 'scanner', got %q", report.Metadata.SourceType)
	}
}

func TestConvert_WithRepository(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		Repository: "github.com/org/repo",
	}
	report, err := a.Convert(context.Background(), sampleSARIFJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Metadata.Scope == nil {
		t.Fatal("expected non-nil scope when repository is set")
	}

	if report.Metadata.Scope.Name != "github.com/org/repo" {
		t.Errorf("expected scope name 'github.com/org/repo', got %q", report.Metadata.Scope.Name)
	}
}

func TestConvert_SemanticVersionFallback(t *testing.T) {
	// Test that semanticVersion is used when version is empty
	input := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "FallbackTool",
					"semanticVersion": "2.5.0"
				}
			},
			"results": []
		}]
	}`)

	a := NewAdapter()
	report, err := a.Convert(context.Background(), input, testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Version != "2.5.0" {
		t.Errorf("expected version '2.5.0' from semanticVersion, got %q", report.Tool.Version)
	}
}

func TestConvert_FindingType(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, testRepo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, f := range report.Findings {
		if f.Type != ctis.FindingTypeVulnerability {
			t.Errorf("finding[%d]: expected type vulnerability, got %q", i, f.Type)
		}
	}
}

// testRepo names the scanned repository: a code scan's findings are filed
// on it, and converting them with no repository is an error.
var testRepo = &core.AdapterOptions{Repository: "github.com/example/app"}

// The adapter used to copy result.kind and result.baselineState verbatim, so a
// sensor sent "notApplicable" (the SARIF spelling), which the CTIS schema and
// the platform's findings.kind CHECK reject; the platform only stored it
// because its ingest normalizes. The adapter now sends the CTIS vocabulary.
func TestConvert_NormalizesKindAndBaselineState(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"checkov","rules":[{"id":"R1"}]}},"results":[
		{"ruleId":"R1","kind":"notApplicable","baselineState":"Unchanged","message":{"text":"a"}},
		{"ruleId":"R1","kind":"pass","message":{"text":"b"}},
		{"ruleId":"R1","kind":"warning","baselineState":"modified","message":{"text":"c"}}]}]}`)
	report, err := NewAdapter().Convert(context.Background(), input, testRepo)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ kind, baseline string }{
		{"not_applicable", "unchanged"},
		{"pass", ""},
		{"", ""},
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d", len(report.Findings), len(want))
	}
	for i, w := range want {
		f := report.Findings[i]
		if f.Kind != w.kind || f.BaselineState != w.baseline {
			t.Errorf("finding %d: kind=%q baseline_state=%q, want %q/%q", i, f.Kind, f.BaselineState, w.kind, w.baseline)
		}
	}
}

// The adapter picks the same fingerprint for the same result every time.
func TestPickResultFingerprint_Deterministic(t *testing.T) {
	fps := map[string]string{"c/v1": "ccc", "a/v1": "aaa", "b/v1": "bbb", "0/v1": "requires login"}
	for i := 0; i < 200; i++ {
		if got := pickResultFingerprint(fps); got != "aaa" {
			t.Fatalf("run %d picked %q, want the lowest usable key's value", i, got)
		}
	}
	if got := pickResultFingerprint(map[string]string{"matchBasedId/v1": "m", "a/v1": "aaa"}); got != "m" {
		t.Fatalf("matchBasedId/v1 not preferred: %q", got)
	}
	if got := pickResultFingerprint(map[string]string{"matchBasedId/v1": "requires login", "b/v1": "bbb"}); got != "bbb" {
		t.Fatalf("unusable matchBasedId not skipped: %q", got)
	}
	if got := pickResultFingerprint(map[string]string{"a": "requires login"}); got != "" {
		t.Fatalf("no usable value should give empty, got %q", got)
	}
}
