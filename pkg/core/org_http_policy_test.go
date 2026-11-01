package core

import (
	"fmt"
	"strings"
	"testing"
)

func TestOrgHTTPPolicyValidate(t *testing.T) {
	ok := []*OrgHTTPPolicy{
		nil,
		{},
		{UserAgent: "acme-research"},
		{Headers: map[string]string{"X-Bug-Bounty": "jdoe", "X-Request-Purpose": "Research"}},
	}
	for i, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	many := map[string]string{}
	for i := 0; i < 11; i++ {
		many[fmt.Sprintf("X-H%d", i)] = "v"
	}
	bad := []*OrgHTTPPolicy{
		{UserAgent: "ua\r\nX: y"},
		{UserAgent: strings.Repeat("a", 257)},
		{Headers: many},
		{Headers: map[string]string{"X Bad": "v"}},
		{Headers: map[string]string{"X-A": "v\r\nInjected: 1"}},
		{Headers: map[string]string{"X-A": strings.Repeat("v", 201)}},
		// SECURITY: credentials and connection headers never come from the platform.
		{Headers: map[string]string{"Authorization": "Bearer x"}},
		{Headers: map[string]string{"cookie": "a=b"}},
		{Headers: map[string]string{"Host": "evil.example"}},
		{Headers: map[string]string{"Proxy-Foo": "x"}},
		{Headers: map[string]string{"Transfer-Encoding": "chunked"}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d must be refused: %+v", i, p)
		}
	}
}

func TestOrgHTTPPolicyLockedAndQuery(t *testing.T) {
	ok := &OrgHTTPPolicy{Headers: map[string]string{"X-A": "1"}, LockedHeaders: []string{"x-a"}, UserAgentLocked: true,
		Query: &HTTPQuery{Name: "scan", Value: "acme_01.x~y-z"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []*OrgHTTPPolicy{
		{Query: &HTTPQuery{Name: "a b", Value: "v"}},
		{Query: &HTTPQuery{Name: "a&b", Value: "v"}},
		{Query: &HTTPQuery{Name: "a", Value: "v=1"}},
		{Query: &HTTPQuery{Name: "a", Value: ""}},
		{Query: &HTTPQuery{Name: "a", Value: strings.Repeat("v", 65)}},
		{Query: &HTTPQuery{Name: "a", Value: "x\r\ny"}},
		{LockedHeaders: []string{"bad name"}},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// 11 job headers are refused by Validate, accepted merged (up to 16).
	p := &OrgHTTPPolicy{Headers: map[string]string{}}
	for i := 0; i < 12; i++ {
		p.Headers["X-H"+strings.Repeat("a", i+1)] = "v"
	}
	if p.Validate() == nil || p.ValidateMerged() != nil {
		t.Fatal("job cap 10, merged cap 16")
	}
	for i := 0; i < 5; i++ {
		p.Headers["X-Z"+strings.Repeat("b", i+1)] = "v"
	}
	if p.ValidateMerged() == nil {
		t.Fatal("17 headers must be refused")
	}
}

func TestHTTPIdentityInResultMetadata(t *testing.T) {
	r := &ScanResult{}
	if CoverageGapsMetadata(r) != nil {
		t.Fatal("nothing to report")
	}
	r.HTTPIdentity = map[string]any{"tool": "nuclei"}
	if m := CoverageGapsMetadata(r); m[MetaHTTPIdentity] == nil {
		t.Fatalf("meta %v", m)
	}
}
