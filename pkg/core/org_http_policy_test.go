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
