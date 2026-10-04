package ctis

import (
	"reflect"
	"strings"
	"testing"

	upstream "github.com/openctemio/ctis"
)

// pkg/ctis re-exports the module: the types are the module's, not copies,
// so values pass between the two without conversion.
func TestTypesAreTheModuleTypes(t *testing.T) {
	// Compiles only while the types are identical.
	takeModule := func(r *upstream.Report) *upstream.Report { return r }
	takeSDK := func(r *Report) *Report { return r }
	r := takeSDK(upstream.NewReport())
	u := takeModule(NewReport())
	if reflect.TypeOf(r) != reflect.TypeOf(u) {
		t.Fatal("pkg/ctis.Report is not github.com/openctemio/ctis.Report")
	}
	if SchemaVersion != upstream.SchemaVersion {
		t.Fatalf("schema version %s, module %s", SchemaVersion, upstream.SchemaVersion)
	}
	if NewReport().Version != upstream.SchemaVersion {
		t.Errorf("NewReport stamps %q, want the module's %q", NewReport().Version, upstream.SchemaVersion)
	}
}

// The hand copy wrote recon scope type "web" and the raw recon type as a
// capability; neither is in the schema enum. Recon output now validates.
func TestConvertReconToCTIS_OutputValidates(t *testing.T) {
	for _, typ := range []string{"subdomain", "dns", "port", "http_probe", "url_crawl"} {
		in := &ReconToCTISInput{
			ScannerName: "fake-recon",
			ReconType:   typ,
			Target:      "example.test",
			Subdomains:  []SubdomainInput{{Host: "a.example.test"}},
			LiveHosts:   []LiveHostInput{{URL: "https://a.example.test", Host: "a.example.test", StatusCode: 200}},
			OpenPorts:   []OpenPortInput{{Host: "a.example.test", IP: "192.0.2.10", Port: 443, Protocol: "tcp"}},
		}
		r, err := ConvertReconToCTIS(in, nil)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: recon report does not validate: %v", typ, err)
		}
		if r.Metadata.Scope != nil && r.Metadata.Scope.Type == "web" {
			t.Errorf("%s: scope type web is not in the schema", typ)
		}
		if r.Tool != nil {
			for _, c := range r.Tool.Capabilities {
				if c == typ && (typ == "port" || typ == "url_crawl") {
					t.Errorf("%s: raw recon type used as capability", typ)
				}
			}
		}
	}
}

// The hand copy typed every Trivy result a misconfiguration. A CVE rule
// tagged "vulnerability" is a vulnerability.
func TestFromSARIF_TrivyCVEIsVulnerability(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[
	  {"id":"CVE-2099-0001","properties":{"tags":["vulnerability","security","HIGH"]}},
	  {"id":"AVD-AWS-0001","properties":{"tags":["misconfiguration","terraform"]}}]}},
	  "results":[
	    {"ruleId":"CVE-2099-0001","level":"error","message":{"text":"pkg 1.0 vulnerable"}},
	    {"ruleId":"AVD-AWS-0001","level":"warning","message":{"text":"bucket public"}}]}]}`)
	r, err := FromSARIF(log, &ConvertOptions{AssetValue: "registry.example.test/app", AssetType: AssetTypeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if r.Findings[0].Type != FindingTypeVulnerability {
		t.Errorf("CVE finding type = %s, want vulnerability", r.Findings[0].Type)
	}
	if r.Findings[1].Type != FindingTypeMisconfiguration {
		t.Errorf("misconfiguration finding type = %s", r.Findings[1].Type)
	}
}

// The hand copy gave an unknown tool capabilities [vulnerability secret],
// and OpenCTEM takes the technique from the first recognized capability, so
// SAST from an unknown tool could be filed as secret.
func TestFromSARIF_UnknownToolIsNotSecret(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"some-new-sast"}},
	  "results":[{"ruleId":"r1","message":{"text":"m"}}]}]}`)
	r, err := FromSARIF(log, &ConvertOptions{AssetValue: "github.com/example/shop"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Tool.Capabilities {
		if c == "secret" {
			t.Fatalf("unknown tool got capability secret: %q", r.Tool.Capabilities)
		}
	}
	if r.Findings[0].Type == FindingTypeSecret {
		t.Error("unknown tool's finding typed secret")
	}
	if err := r.Validate(); err != nil {
		t.Errorf("report does not validate: %v", err)
	}
}

// The SDK's asset rule on top of the module: options, then branch info, then
// versionControlProvenance; the asset carries no criticality.
func TestFromSARIF_AssetRule(t *testing.T) {
	const prov = `{"version":"2.1.0","runs":[{"versionControlProvenance":[{"repositoryUri":" https://github.com/example/shop ","revisionId":"abc123","branch":"main"}],
	  "tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`
	r, err := FromSARIF([]byte(prov), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Assets[0]
	if a.Value != "https://github.com/example/shop" || a.Type != AssetTypeRepository {
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

	r, err = FromSARIF([]byte(prov), &ConvertOptions{AssetValue: "github.com/example/other"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Assets[0].Value != "github.com/example/other" || r.Assets[0].Type != AssetTypeRepository || r.Assets[0].Properties != nil {
		t.Errorf("option asset = %+v", r.Assets[0])
	}

	r, err = FromSARIF([]byte(prov), &ConvertOptions{BranchInfo: &BranchInfo{Name: "dev", RepositoryURL: "github.com/example/branchrepo"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Assets[0].Value != "github.com/example/branchrepo" || r.Metadata.Branch == nil {
		t.Errorf("branch-info asset = %+v, branch %+v", r.Assets[0], r.Metadata.Branch)
	}

	if _, err := FromSARIF([]byte("{"), nil); err == nil || !strings.Contains(err.Error(), "parse sarif") {
		t.Errorf("malformed log: err = %v", err)
	}
}
