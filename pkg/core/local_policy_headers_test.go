package core

import (
	"strings"
	"testing"
)

const headersHead = "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"*\"]\n"

func headersPolicy(t *testing.T, http string) (*LocalPolicy, error) {
	t.Helper()
	return ParseLocalPolicy([]byte(headersHead+http), LocalPolicyOptions{LookupEnv: privateOn, LookupIP: policyDNS})
}

// The sensor owner's identification headers (policy v1) are read, kept in
// order, and only their names reach the report.
func TestLocalPolicyHeadersHeaders(t *testing.T) {
	lp, err := headersPolicy(t, "http:\n  user_agent: dc1-scan\n  headers:\n    - {name: X-Netops, value: dc1}\n    - {name: ATTT, value: is-here}\n")
	if err != nil {
		t.Fatal(err)
	}
	hs := lp.HTTPHeaders()
	if len(hs) != 2 || hs[0].Name != "X-Netops" || hs[1].Value != "is-here" {
		t.Fatalf("headers %+v", hs)
	}
	if ua, _ := lp.HTTPPolicy(); ua != "dc1-scan" {
		t.Fatalf("v1 keeps its keys: ua %q", ua)
	}
	r := lp.Report()
	if r.Schema != "v1" || len(r.Summary.HTTPHeaderNames) != 2 || r.Summary.HTTPHeaderNames[0] != "X-Netops" {
		t.Fatalf("report %+v", r)
	}
	// The returned list is a copy.
	hs[0].Value = "changed"
	if lp.HTTPHeaders()[0].Value != "dc1" {
		t.Fatal("HTTPHeaders returned the policy's own slice")
	}
	var none *LocalPolicy
	if none.HTTPHeaders() != nil {
		t.Fatal("no policy, no headers")
	}
}

// Validation is the platform's: token name, printable value, refused names,
// at most four, no duplicates, and v3 files never carry headers.
func TestLocalPolicyHeadersHeaderValidation(t *testing.T) {
	five := "http:\n  headers:\n"
	for _, n := range []string{"A1", "A2", "A3", "A4", "A5"} {
		five += "    - {name: " + n + ", value: v}\n"
	}
	cases := []struct {
		name, doc, want string
	}{
		{"cap", five, "at most 4"},
		{"space in name", "http:\n  headers:\n    - {name: \"X Bad\", value: v}\n", "not a header name"},
		{"colon in name", "http:\n  headers:\n    - {name: \"X:Bad\", value: v}\n", "not a header name"},
		{"empty name", "http:\n  headers:\n    - {name: \"\", value: v}\n", "not a header name"},
		{"long name", "http:\n  headers:\n    - {name: " + strings.Repeat("a", 65) + ", value: v}\n", "not a header name"},
		{"newline value", "http:\n  headers:\n    - {name: X-A, value: \"a\\nb\"}\n", "printable ASCII"},
		{"non-ascii value", "http:\n  headers:\n    - {name: X-A, value: \"café\"}\n", "printable ASCII"},
		{"long value", "http:\n  headers:\n    - {name: X-A, value: " + strings.Repeat("v", 201) + "}\n", "printable ASCII"},
		{"authorization", "http:\n  headers:\n    - {name: Authorization, value: x}\n", "refused"},
		{"cookie", "http:\n  headers:\n    - {name: cookie, value: x}\n", "refused"},
		{"host", "http:\n  headers:\n    - {name: HOST, value: x}\n", "refused"},
		{"proxy", "http:\n  headers:\n    - {name: Proxy-Foo, value: x}\n", "refused"},
		{"duplicate", "http:\n  headers:\n    - {name: X-A, value: 1}\n    - {name: x-a, value: 2}\n", "listed twice"},
	}
	for _, c := range cases {
		_, err := headersPolicy(t, c.doc)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
	// A 4-header policy and a 200-byte value are fine.
	if _, err := headersPolicy(t, "http:\n  headers:\n    - {name: A1, value: "+strings.Repeat("v", 200)+"}\n"); err != nil {
		t.Errorf("200 bytes: %v", err)
	}
	// Only v1 exists.
	for _, v := range []string{"v2", "v3", "v4"} {
		doc := "apiVersion: openctem.io/sensor-policy/" + v + "\nhttp:\n  headers:\n    - {name: X-A, value: v}\n"
		if _, err := ParseLocalPolicy([]byte(doc), LocalPolicyOptions{LookupEnv: privateOn, LookupIP: policyDNS}); err == nil {
			t.Errorf("%s accepted", v)
		}
	}
}
