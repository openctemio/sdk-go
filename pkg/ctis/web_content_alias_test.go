package ctis

import "testing"

// The web content property reaches the report through the alias types.
func TestWebContentAliases(t *testing.T) {
	in := &ReconToCTISInput{
		ScannerName: "fake-recon", ReconType: "http_probe", Target: "a.example.test",
		LiveHosts: []LiveHostInput{{
			URL: "https://a.example.test/", Host: "a.example.test", Scheme: "https",
			WebContent: []WebCaptureInput{{URL: "https://a.example.test/", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}},
		}},
	}
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Assets {
		if _, ok := a.Properties[WebContentProperty]; ok {
			return
		}
	}
	t.Fatal("no web_content property")
}
