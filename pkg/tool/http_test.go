package tool

import (
	"strings"
	"testing"
	"time"
)

func TestHTTPSpecValidation(t *testing.T) {
	ok := &HTTPSpec{UserAgent: "acme-scanner/1.2 (+https://acme.example/scanner)", Headers: map[string]string{"X-Scan-Id": "42"},
		Timeout: Duration(30 * time.Second), TLS: &TLSSpec{InsecureSkipVerify: true, MinVersion: "1.2"}}
	var errs []string
	add := func(p, f string, a ...any) { errs = append(errs, p) }
	ok.validate(NetTargets, add)
	if len(errs) > 0 {
		t.Fatalf("valid spec refused: %v", errs)
	}
	cases := map[string]struct {
		h   *HTTPSpec
		net Network
	}{
		"/http/user_agent":               {&HTTPSpec{UserAgent: "a\r\nX-Injected: 1"}, NetTargets},
		"/http/headers/Authorization":    {&HTTPSpec{Headers: map[string]string{"Authorization": "Bearer x"}}, NetTargets},
		"/http/headers/Cookie":           {&HTTPSpec{Headers: map[string]string{"Cookie": "s=1"}}, NetTargets},
		"/http/headers/Proxy-Foo":        {&HTTPSpec{Headers: map[string]string{"Proxy-Foo": "1"}}, NetTargets},
		"/http/headers/X-Ok":             {&HTTPSpec{Headers: map[string]string{"X-Ok": "line\nbreak"}}, NetTargets},
		"/http/timeout":                  {&HTTPSpec{Timeout: Duration(time.Hour)}, NetTargets},
		"/http/tls/min_version":          {&HTTPSpec{TLS: &TLSSpec{MinVersion: "1.4"}}, NetTargets},
		"/http/tls/insecure_skip_verify": {&HTTPSpec{TLS: &TLSSpec{InsecureSkipVerify: true}}, NetVendor},
	}
	for want, c := range cases {
		errs = nil
		c.h.validate(c.net, add)
		if !strings.Contains(strings.Join(errs, " "), want) {
			t.Errorf("%s: not refused (%v)", want, errs)
		}
	}
	if s := ok.String(); !strings.Contains(s, "headers=X-Scan-Id") || strings.Contains(s, "42") || !strings.Contains(s, "tls_verify=off") {
		t.Errorf("log summary %q (header values must not be logged)", s)
	}
}

// tool.yaml carries the http block through the strict loader.
func TestHTTPSpecLoads(t *testing.T) {
	m, err := LoadManifest([]byte(baseYAML + "http:\n  user_agent: \"acme-scanner/2.0\"\n  headers: {X-Scan-Id: run}\n  timeout: 30s\n  tls: {insecure_skip_verify: true, min_version: \"1.2\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.HTTP == nil || m.HTTP.UserAgent != "acme-scanner/2.0" || m.HTTP.TLS.TLSMinVersion() == 0 || time.Duration(m.HTTP.Timeout) != 30*time.Second {
		t.Fatalf("http %+v", m.HTTP)
	}
	if _, err := LoadManifest([]byte(baseYAML + "http:\n  headers: {Authorization: \"Bearer x\"}\n")); err == nil {
		t.Fatal("an Authorization header in tool.yaml was accepted")
	}
}
