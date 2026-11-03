package tool

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestInferTargetType(t *testing.T) {
	for v, want := range map[string]ctis.AssetType{
		"https://a.example/x":  ctis.AssetTypeWebOrigin,
		"http://10.0.0.1:8080": ctis.AssetTypeWebOrigin,
		"10.0.0.1":             ctis.AssetTypeIPAddress,
		"2001:db8::1":          ctis.AssetTypeIPAddress,
		"10.0.0.0/8":           ctis.AssetTypeIPRange,
		"a.example:443":        ctis.AssetTypeService,
		"10.0.0.1:22/tcp":      ctis.AssetTypeService,
		"www.example.com":      ctis.AssetTypeDomainName,
		"/src/repo":            "",
		"localhost":            "",
		"ftp://a.example":      "",
		"":                     "",
	} {
		if got := InferTargetType(v); got != want {
			t.Errorf("InferTargetType(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestTargetServiceValue(t *testing.T) {
	tg := Target{Type: "service", Value: "10.0.0.1:22/tcp"}
	if tg.Host() != "10.0.0.1" || tg.Port() != 22 || tg.Transport() != "tcp" {
		t.Fatalf("host %q port %d transport %q", tg.Host(), tg.Port(), tg.Transport())
	}
	if (Target{Value: "https://a.example"}).Transport() != "" {
		t.Fatal("a URL has no transport")
	}
}
