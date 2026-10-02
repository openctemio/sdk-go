package core

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

var proxyBase = []string{
	"PATH=/usr/bin",
	"HTTPS_PROXY=http://corp-proxy:3128",
	"http_proxy=http://corp-proxy:3128",
	"ALL_PROXY=socks5://corp-proxy:1080",
	"NO_PROXY=.corp",
	"OPENCTEM_API_KEY=secret",
}

func TestParseScannerProxyMode(t *testing.T) {
	for in, want := range map[string]ScannerProxyMode{"": ScannerProxyInherit, "inherit": ScannerProxyInherit, " Direct ": ScannerProxyDirect} {
		got, err := ParseScannerProxyMode(in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	if _, err := ParseScannerProxyMode("off"); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestScannerEnviron_ProxyInheritIsDefault(t *testing.T) {
	if ScannerProxy() != ScannerProxyInherit {
		t.Fatalf("default mode %q, want inherit (owner decision O2)", ScannerProxy())
	}
	got := envMap(scannerEnviron(proxyBase))
	for _, k := range []string{"HTTPS_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY"} {
		if got[k] == "" {
			t.Errorf("inherit dropped %s", k)
		}
	}
}

func TestScannerEnviron_ProxyDirectStripsSensorProxy(t *testing.T) {
	SetScannerProxyMode(ScannerProxyDirect)
	t.Cleanup(func() { SetScannerProxyMode(ScannerProxyInherit) })

	got := envMap(scannerEnviron(proxyBase, map[string]string{"HTTPS_PROXY": "http://127.0.0.1:4000"}))
	for _, k := range []string{"http_proxy", "ALL_PROXY", "NO_PROXY"} {
		if _, ok := got[k]; ok {
			t.Errorf("direct kept %s", k)
		}
	}
	// A variable the caller passes explicitly is still passed.
	if got["HTTPS_PROXY"] != "http://127.0.0.1:4000" {
		t.Errorf("explicit HTTPS_PROXY = %q", got["HTTPS_PROXY"])
	}
	if got["PATH"] == "" || got["OPENCTEM_API_KEY"] != "" {
		t.Errorf("allowlist changed: %v", got)
	}
	if ScannerProxySummary() != "direct" {
		t.Errorf("summary %q", ScannerProxySummary())
	}
}

func TestContentEnviron_FollowsContentProxy(t *testing.T) {
	// Environment: the sensor's variables, even when scanners are direct.
	SetScannerProxyMode(ScannerProxyDirect)
	t.Cleanup(func() { SetScannerProxyMode(ScannerProxyInherit) })
	got := envMap(contentEnviron(proxyBase, httpsec.ProxySetting{}))
	if got["HTTPS_PROXY"] != "http://corp-proxy:3128" {
		t.Errorf("environment: HTTPS_PROXY = %q", got["HTTPS_PROXY"])
	}

	direct, _ := httpsec.ParseProxySetting("direct", "")
	got = envMap(contentEnviron(proxyBase, direct))
	for _, k := range httpsec.ProxyEnvVars {
		if _, ok := got[k]; ok {
			t.Errorf("direct kept %s", k)
		}
	}

	explicit, _ := httpsec.ParseProxySetting("http://u:p@content-proxy:8080", ".internal")
	env := contentEnviron(proxyBase, explicit, map[string]string{"TRIVY_X": "1"})
	got = envMap(env)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if got[k] != "http://u:p@content-proxy:8080" {
			t.Errorf("%s = %q", k, got[k])
		}
	}
	if got["NO_PROXY"] != ".internal" || got["no_proxy"] != ".internal" || got["TRIVY_X"] != "1" {
		t.Errorf("env = %v", got)
	}
	if n := strings.Count(strings.Join(env, "\n"), "HTTPS_PROXY="); n != 1 {
		t.Errorf("HTTPS_PROXY appears %d times", n)
	}
}
