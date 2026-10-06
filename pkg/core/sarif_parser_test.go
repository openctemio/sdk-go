package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// The SARIF parser converts through the ctis importer. These tests pin what
// the SDK adds (the asset rule, the branch, the options) and that the
// module's mapping reaches the report unchanged.

func parseSARIF(t *testing.T, data []byte, opts *core.ParseOptions) *ctis.Report {
	t.Helper()
	r, err := (&core.SARIFParser{}).Parse(context.Background(), data, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("report does not validate: %v", err)
	}
	if err := ctis.CheckFindingAssets(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func noCI(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
}

const provLog = `{"version":"2.1.0","runs":[{"versionControlProvenance":[{"repositoryUri":" https://github.com/example/shop ","revisionId":"abc123","branch":"main"}],
  "tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`

// The asset: options, then branch info, then versionControlProvenance, then
// the CI job; none of them with results is ErrNoAssetForFindings. The asset
// carries no criticality.
func TestSARIFParser_AssetRule(t *testing.T) {
	noCI(t)
	r := parseSARIF(t, []byte(provLog), nil)
	a := r.Assets[0]
	if a.Value != "https://github.com/example/shop" || a.Type != ctis.AssetTypeRepository {
		t.Errorf("provenance asset = %+v", a)
	}
	if a.Properties["commit_sha"] != "abc123" || a.Properties["branch"] != "main" || a.Properties["source"] != "sarif_version_control_provenance" {
		t.Errorf("provenance properties = %v", a.Properties)
	}
	if a.Criticality != "" {
		t.Errorf("asset criticality %q: the receiver decides", a.Criticality)
	}
	if r.Findings[0].AssetRef != a.ID {
		t.Errorf("finding asset_ref %q, asset id %q", r.Findings[0].AssetRef, a.ID)
	}

	r = parseSARIF(t, []byte(provLog), &core.ParseOptions{AssetValue: "github.com/example/other", Branch: "dev", CommitSHA: "def"})
	if len(r.Assets) != 1 || r.Assets[0].Value != "github.com/example/other" || r.Assets[0].Type != ctis.AssetTypeRepository {
		t.Errorf("option asset = %+v", r.Assets)
	}
	if b := r.Metadata.Branch; b == nil || b.Name != "dev" || b.CommitSHA != "def" {
		t.Errorf("branch = %+v", b)
	}

	bi := &ctis.BranchInfo{Name: "dev", RepositoryURL: "github.com/example/branchrepo", IsDefaultBranch: true, CommitSHA: "fff"}
	r = parseSARIF(t, []byte(provLog), &core.ParseOptions{BranchInfo: bi})
	if r.Assets[0].Value != "github.com/example/branchrepo" {
		t.Errorf("branch-info asset = %+v", r.Assets[0])
	}
	// The caller's branch info is the report's branch: IsDefaultBranch
	// gates auto-resolve on the platform.
	if b := r.Metadata.Branch; b == nil || !reflect.DeepEqual(*b, *bi) || b == bi {
		t.Errorf("branch = %+v, want a copy of %+v", b, bi)
	}

	// Any other asset type takes every finding.
	r = parseSARIF(t, []byte(provLog), &core.ParseOptions{AssetValue: "registry.example.test/app", AssetType: ctis.AssetTypeContainer})
	if len(r.Assets) != 1 || r.Assets[0].Type != ctis.AssetTypeContainer || r.Assets[0].Value != "registry.example.test/app" {
		t.Errorf("container asset = %+v", r.Assets)
	}

	if _, err := (&core.SARIFParser{}).Parse(context.Background(), []byte(`{"runs":[{`), nil); err == nil {
		t.Error("malformed log: no error")
	}
}

func TestSARIFParser_FindingsNeedARepository(t *testing.T) {
	noCI(t)
	log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},
		"results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}`)
	if r, err := (&core.SARIFParser{}).Parse(context.Background(), log, nil); !errors.Is(err, ctis.ErrNoAssetForFindings) || r != nil {
		t.Fatalf("no repository = %v, %v; want nil, ErrNoAssetForFindings", r, err)
	}
	// In CI, the job's repository.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "example/ci-repo")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
	r := parseSARIF(t, log, nil)
	if len(r.Assets) != 1 || !strings.Contains(r.Assets[0].Value, "example/ci-repo") {
		t.Errorf("CI asset = %+v", r.Assets)
	}
	noCI(t)
	// No results: nothing to file, no error, no asset.
	empty := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}`)
	r = parseSARIF(t, empty, nil)
	if len(r.Assets) != 0 {
		t.Errorf("empty log assets = %+v", r.Assets)
	}
}

// A repository URL in versionControlProvenance never carries its user and
// password into the asset (the bare converter kept them).
func TestSARIFParser_ProvenanceCredentialsStripped(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[{"versionControlProvenance":[{"repositoryUri":"https://ci-user:not-a-token@git.example.com/team/app.git"}],
	  "tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`)
	r := parseSARIF(t, log, nil)
	if v := r.Assets[0].Value; strings.Contains(v, "not-a-token") || strings.Contains(v, "ci-user") {
		t.Errorf("asset value keeps credentials: %q", v)
	}
}

// ToolType and DefaultConfidence reach the conversion.
func TestSARIFParser_ToolTypeAndConfidence(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"some-new-sast","rules":[{"id":"r1"}]}},
	  "results":[{"ruleId":"r1","message":{"text":"m"}}]}]}`)
	repo := "github.com/example/shop"
	r := parseSARIF(t, log, &core.ParseOptions{AssetValue: repo})
	if r.Findings[0].Type == ctis.FindingTypeSecret || slicesContain(r.Tool.Capabilities, "secret") {
		t.Errorf("unknown tool typed secret: %s %v", r.Findings[0].Type, r.Tool.Capabilities)
	}
	if r.Findings[0].Confidence != 90 {
		t.Errorf("default confidence = %d, want 90", r.Findings[0].Confidence)
	}
	r = parseSARIF(t, log, &core.ParseOptions{AssetValue: repo, ToolType: "secret", DefaultConfidence: 40})
	if r.Findings[0].Type != ctis.FindingTypeSecret || !reflect.DeepEqual(r.Tool.Capabilities, []string{"secret"}) {
		t.Errorf("ToolType secret: type %s, capabilities %v", r.Findings[0].Type, r.Tool.Capabilities)
	}
	if r.Findings[0].Confidence != 40 {
		t.Errorf("confidence = %d, want 40", r.Findings[0].Confidence)
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The module's mapping reaches the report: rule-level severity, the lowest
// fingerprint key, partialFingerprints, kind and baselineState of every run,
// tags, and secret findings with masked snippets.
func TestSARIFParser_ModuleMapping(t *testing.T) {
	repo := &core.ParseOptions{AssetValue: "github.com/example/shop"}

	sev := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"demo","rules":[
	    {"id":"RULE-ERR","defaultConfiguration":{"level":"error"}},
	    {"id":"RULE-NOTE","defaultConfiguration":{"level":"note"}}]}},
	  "results":[
	    {"ruleId":"RULE-ERR","message":{"text":"rule error"},
	     "fingerprints":{"c/v1":"cccccccccccccccc","a/v1":"aaaaaaaaaaaaaaaa"},
	     "partialFingerprints":{"primaryLocationLineHash":"39fa2ee980eb94b0:1"}},
	    {"ruleId":"RULE-NOTE","message":{"text":"rule note"}},
	    {"ruleId":"RULE-ERR","level":"warning","message":{"text":"result level wins"}}]}]}`)
	r := parseSARIF(t, sev, repo)
	for i, w := range []ctis.Severity{ctis.SeverityHigh, ctis.SeverityLow, ctis.SeverityMedium} {
		if r.Findings[i].Severity != w {
			t.Errorf("finding %d: severity %s, want %s", i, r.Findings[i].Severity, w)
		}
	}
	if r.Findings[0].Fingerprint != "aaaaaaaaaaaaaaaa" {
		t.Errorf("fingerprint = %q, want the lowest key", r.Findings[0].Fingerprint)
	}
	if r.Findings[0].PartialFingerprints["primaryLocationLineHash"] != "39fa2ee980eb94b0:1" || r.Findings[1].PartialFingerprints != nil {
		t.Errorf("partial fingerprints = %v / %v", r.Findings[0].PartialFingerprints, r.Findings[1].PartialFingerprints)
	}

	kinds, err := os.ReadFile(filepath.Join("testdata", "sarif", "kinds.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	r = parseSARIF(t, kinds, repo)
	if len(r.Findings) != 8 {
		t.Fatalf("kinds: %d findings, want 8 (two runs of four)", len(r.Findings))
	}
	for i, w := range []struct{ kind, baseline string }{{"fail", "new"}, {"review", "unchanged"}, {"not_applicable", ""}, {"pass", "absent"}} {
		if f := r.Findings[i]; f.Kind != w.kind || f.BaselineState != w.baseline {
			t.Errorf("finding %d: kind=%q baseline_state=%q, want %q/%q", i, f.Kind, f.BaselineState, w.kind, w.baseline)
		}
	}

	leaks, err := os.ReadFile(filepath.Join("testdata", "sarif", "betterleaks.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	r = parseSARIF(t, leaks, repo)
	if len(r.Findings) != 2 {
		t.Fatalf("betterleaks: %d findings, want 2", len(r.Findings))
	}
	for i, w := range [][]string{{"key", "verified", "cloud", "aws"}, {"entropy"}} {
		if got := r.Findings[i].Tags; !reflect.DeepEqual(got, w) {
			t.Errorf("finding %d tags = %q, want %q", i, got, w)
		}
		if r.Findings[i].Type != ctis.FindingTypeSecret {
			t.Errorf("finding %d type = %s, want secret", i, r.Findings[i].Type)
		}
	}
	if !reflect.DeepEqual(r.Tool.Capabilities, []string{"secret"}) {
		t.Errorf("capabilities = %v", r.Tool.Capabilities)
	}

	// A secret scanner's raw match never reaches the report.
	raw := "AKIAZXCVBNMQWERTYUIO"
	secret := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"aws-access-token"}]}},
	  "results":[{"ruleId":"aws-access-token","message":{"text":"AWS access key"},
	    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"cfg.env"},"region":{"startLine":3,"snippet":{"text":"KEY=` + raw + `"}}}}]}]}]}`)
	r = parseSARIF(t, secret, repo)
	if b, _ := json.Marshal(r); strings.Contains(string(b), raw) {
		t.Errorf("raw secret in the report: %s", b)
	}

	trivy := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[
	  {"id":"CVE-2099-0001","properties":{"tags":["vulnerability","security","HIGH"]}},
	  {"id":"AVD-AWS-0001","properties":{"tags":["misconfiguration","terraform"]}}]}},
	  "results":[
	    {"ruleId":"CVE-2099-0001","level":"error","message":{"text":"pkg 1.0 vulnerable"}},
	    {"ruleId":"AVD-AWS-0001","level":"warning","message":{"text":"bucket public"}}]}]}`)
	r = parseSARIF(t, trivy, &core.ParseOptions{AssetValue: "registry.example.test/app", AssetType: ctis.AssetTypeContainer})
	if r.Findings[0].Type != ctis.FindingTypeVulnerability || r.Findings[1].Type != ctis.FindingTypeMisconfiguration {
		t.Errorf("trivy types = %s, %s", r.Findings[0].Type, r.Findings[1].Type)
	}
}
