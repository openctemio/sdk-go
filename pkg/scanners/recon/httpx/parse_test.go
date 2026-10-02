package httpx

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/scanners/recon/internal/flagcheck"
)

// Real httpx 1.12.0 output (https://example.com). "a" and "cname" are
// arrays; decoding them into strings dropped every line.
func TestParseOutput_Real(t *testing.T) {
	data, err := os.ReadFile(flagcheck.Testdata("httpx-1.12.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	hosts, techs, err := NewScanner().parseOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("live hosts = %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.URL != "https://example.com" || h.Host != "example.com" || h.StatusCode != 200 || h.Port != 443 ||
		h.Title != "Example Domain" || h.IP != "172.66.147.243" || h.TLSVersion != "tls13" || h.CDN != "cloudflare" {
		t.Fatalf("live host = %+v", h)
	}
	if len(techs) == 0 {
		t.Fatal("no technologies")
	}
}
