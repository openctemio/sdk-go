package webscope

import (
	"slices"
	"testing"
)

// Exclusions the platform stored escaped, with "*" segments, and spellings
// a lenient server reads as an excluded path are all refused.
func TestAllowsDenyForms(t *testing.T) {
	s := &Scope{DenyPaths: []string{"/files/My%20Docs", "/tenants/*/admin", "/secret", "/kibana", "/admin"}}
	for _, p := range []string{
		"/files/My%20Docs/a.bak", "/files/My Docs/a.bak", "/files/my%20docs",
		"/tenants/acme/admin", "/tenants/acme/admin/x", "/Tenants/x/ADMIN",
		"/x/%252e%252e/admin", "/%2561dmin", "/%C5%BFecret", "/%E2%84%AAibana", "/admin./x", "/admin%20/x",
	} {
		if err := s.Allows("GET", mustURL(t, "https://t.example.com"+p), []string{"t.example.com"}); err == nil {
			t.Errorf("%s is allowed", p)
		}
	}
	for _, p := range []string{"/files/other", "/tenants/acme/users", "/public", "/s3cret"} {
		if err := s.Allows("GET", mustURL(t, "https://t.example.com"+p), []string{"t.example.com"}); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// Validate adds the clean form of an escaped deny path, once, so a tool
// that reads the deny list itself gets both.
func TestValidateAddsCleanDenyPaths(t *testing.T) {
	s := &Scope{DenyPaths: []string{"/files/My%20Docs", "/admin", "/%61pi", "/api"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"/files/My%20Docs", "/files/My Docs", "/admin", "/%61pi", "/api"}
	if !slices.Equal(s.DenyPaths, want) {
		t.Errorf("deny paths %q, want %q", s.DenyPaths, want)
	}
	if err := s.Validate(); err != nil || !slices.Equal(s.DenyPaths, want) {
		t.Errorf("second Validate: %v, %q", err, s.DenyPaths)
	}
}
