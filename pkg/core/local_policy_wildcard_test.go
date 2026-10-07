package core

import (
	"context"
	"strings"
	"testing"
)

// The sensor-local policy reads "*.x" as x and every name below it, the
// same as the platform's scope patterns (api RFC-054 §4.1).
func TestDomainPatternWildcardCoversApex(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.com", "example.com", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.c.example.com", true},
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "example.com.evil.net", false},
		{"*.example.com", "evilexample.com", false},
		{"*.example.com", "com", false},
		{"*.example.com", "EXAMPLE.com.", true},
		{"*.Example.COM.", "api.example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false},
		{"Example.com", "example.com.", true},
		{"*.bücher.example", "xn--bcher-kva.example", true},
		{"*.bücher.example", "shop.bücher.example", true},
		{"*.xn--bcher-kva.example", "bücher.example", true},
	}
	for _, c := range cases {
		d, err := parseDomainPattern(c.pattern)
		if err != nil {
			t.Fatalf("parse %q: %v", c.pattern, err)
		}
		if got := d.matches(c.host); got != c.want {
			t.Errorf("%q matches %q = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestLocalPolicyWildcardAllowAndDenyCoverApex(t *testing.T) {
	answers := map[string][]string{
		"corp.example.com":        {"192.0.2.10"},
		"www.corp.example.com":    {"192.0.2.11"},
		"prod.corp.example.com":   {"192.0.2.12"},
		"x.prod.corp.example.com": {"192.0.2.13"},
		"notcorp.example.com":     {"192.0.2.14"},
	}
	lp, err := ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\n"+
		"targets: {allow: [\"*.corp.example.com\"], deny: [\"*.prod.corp.example.com\"]}\n"),
		LocalPolicyOptions{LookupEnv: privateOn, LookupIP: fakeDNS(answers)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := context.Background()
	want := map[string]string{
		"corp.example.com":        "",              // apex of an allow wildcard
		"www.corp.example.com":    "",              // below it
		"prod.corp.example.com":   "targets.deny",  // apex of a deny wildcard
		"x.prod.corp.example.com": "targets.deny",  // below it
		"notcorp.example.com":     "targets.allow", // suffix trick: not under the pattern
		"CORP.example.com.":       "",              // case and trailing dot
	}
	for host, rule := range want {
		err := lp.CheckTarget(ctx, host)
		if rule == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", host, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), rule) {
			t.Errorf("%s: err = %v, want a %s refusal", host, err, rule)
		}
	}
}
