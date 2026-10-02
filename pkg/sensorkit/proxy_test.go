package sensorkit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, n := range append([]string{EnvControlProxy, EnvContentProxy, EnvScanProxy, core.EnvScannerProxy}, httpsec.ProxyEnvVars...) {
		t.Setenv(n, "")
	}
}

func TestResolveProxies_Precedence(t *testing.T) {
	clearProxyEnv(t)

	// Nothing set: everything follows the environment, scanners inherit.
	p, err := ResolveProxies(ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Control.Mode != httpsec.ProxyEnvironment || p.Content.Mode != httpsec.ProxyEnvironment || p.Scan != core.ScannerProxyInherit {
		t.Fatalf("defaults = %+v", p)
	}

	// SENSOR_CONTROL_PROXY sets control, and content follows it.
	t.Setenv(EnvControlProxy, "http://ctl:3128")
	t.Setenv("NO_PROXY", ".corp")
	p, err = ResolveProxies(ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Control.String() != "http://ctl:3128" || p.Content.String() != "http://ctl:3128" || p.Control.NoProxy != ".corp" {
		t.Fatalf("control only: %+v", p)
	}

	// SENSOR_CONTENT_PROXY overrides content; an option overrides both.
	t.Setenv(EnvContentProxy, "direct")
	t.Setenv(EnvScanProxy, "direct")
	p, err = ResolveProxies(ProxyOptions{Control: "socks5h://opt:1080"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Control.String() != "socks5h://opt:1080" || p.Content.Mode != httpsec.ProxyDirect || p.Scan != core.ScannerProxyDirect {
		t.Fatalf("overrides: %+v", p)
	}
	p, err = ResolveProxies(ProxyOptions{Scan: "inherit"})
	if err != nil || p.Scan != core.ScannerProxyInherit {
		t.Fatalf("scan option: %+v %v", p, err)
	}
}

func TestResolveProxies_BadValuesAreUsageErrors(t *testing.T) {
	for _, c := range []struct{ env, val string }{
		{EnvControlProxy, "ftp://x:21"},
		{EnvContentProxy, "http://169.254.169.254"},
		{EnvScanProxy, "sometimes"},
	} {
		clearProxyEnv(t)
		t.Setenv(c.env, c.val)
		_, err := ResolveProxies(ProxyOptions{})
		if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), c.env) {
			t.Errorf("%s=%s: err = %v (exit %d)", c.env, c.val, err, ExitCode(err))
		}
	}
}

func TestProxies_ApplyAndReport(t *testing.T) {
	clearProxyEnv(t)
	t.Cleanup(func() { Proxies{Scan: core.ScannerProxyInherit}.Apply() })
	t.Setenv("HTTPS_PROXY", "http://user:pw@corp:3128")

	p, err := ResolveProxies(ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Apply()
	var out, errw bytes.Buffer
	p.report(&out, &errw, ProxyOptions{})
	if !strings.Contains(out.String(), "scanners=inherit (HTTPS_PROXY=http://user:xxxxx@corp:3128)") {
		t.Errorf("summary = %q", out.String())
	}
	if !strings.Contains(errw.String(), "SENSOR_SCAN_PROXY=direct") || strings.Contains(errw.String()+out.String(), "pw@") {
		t.Errorf("warning = %q", errw.String())
	}

	// An explicit choice silences the warning but keeps the summary line.
	t.Setenv(EnvScanProxy, "inherit")
	errw.Reset()
	p.report(&out, &errw, ProxyOptions{})
	if errw.Len() != 0 {
		t.Errorf("explicit inherit still warned: %q", errw.String())
	}

	// direct is applied to scanner processes.
	t.Setenv(EnvScanProxy, "direct")
	p, _ = ResolveProxies(ProxyOptions{})
	p.Apply()
	if core.ScannerProxy() != core.ScannerProxyDirect || p.ScanWarning() != "" {
		t.Fatalf("direct not applied: %q", core.ScannerProxy())
	}
	ctl, _ := httpsec.ParseProxySetting("http://ctl:1", "")
	Proxies{Control: ctl, Content: ctl, Scan: core.ScannerProxyInherit}.Apply()
	if httpsec.APIProxy().String() != "http://ctl:1" || httpsec.ContentProxy().String() != "http://ctl:1" {
		t.Fatal("control/content not applied")
	}
	Proxies{}.Apply()
}
