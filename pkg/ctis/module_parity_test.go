package ctis

import (
	"reflect"
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
