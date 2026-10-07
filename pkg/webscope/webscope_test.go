package webscope

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAllows(t *testing.T) {
	s := &Scope{Hosts: []string{"*.example.com"}, PathPrefixes: []string{"/app"}, DenyPaths: []string{"/app/logout", "/app/admin"}}
	cases := []struct {
		method, url string
		ok          bool
	}{
		{"GET", "https://example.com/app", true},
		{"GET", "https://www.example.com/app/page?x=1", true},
		{"HEAD", "http://a.b.example.com/app/", true},
		{"GET", "https://example.com/application", false}, // segment boundary
		{"GET", "https://example.com/other", false},
		{"GET", "https://evil.com/app", false},
		{"GET", "https://example.com.evil.com/app", false},
		{"GET", "https://notexample.com/app", false},
		// SECURITY: deny paths win, whatever the spelling.
		{"GET", "https://example.com/app/logout", false},
		{"GET", "https://example.com/app/LOGOUT", false},
		{"GET", "https://example.com/app/x/../logout", false},
		{"GET", "https://example.com/app/%6cogout", false},
		{"GET", "https://example.com/app//admin", false},
		{"GET", "https://example.com/app/admin.php", false}, // deny is a plain prefix
		{"GET", "https://example.com/app%2fadmin", false},   // encoded slash refused
		{"GET", "https://example.com/app/x%00", false},
		{"GET", "https://example.com/app/..%5cadmin", false},
		// SECURITY: methods default to the safe ones.
		{"POST", "https://example.com/app/form", false},
		{"DELETE", "https://example.com/app/x", false},
		// Only http(s), no user info.
		{"GET", "ftp://example.com/app", false},
		{"GET", "https://user:pw@example.com/app", false},
	}
	for _, c := range cases {
		err := s.Allows(c.method, mustURL(t, c.url), nil)
		if (err == nil) != c.ok {
			t.Errorf("%s %s: err %v, want ok=%v", c.method, c.url, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrOutOfScope) {
			t.Errorf("%s %s: error %v is not ErrOutOfScope", c.method, c.url, err)
		}
	}
}

func TestAllowsDefaults(t *testing.T) {
	var none *Scope
	if err := none.Allows("DELETE", mustURL(t, "https://anything/x"), nil); err != nil {
		t.Fatal("no scope restricts nothing here")
	}
	s := &Scope{Methods: []string{"GET", "POST"}}
	if err := s.Allows("POST", mustURL(t, "https://t.example.com/login"), []string{"t.example.com"}); err != nil {
		t.Fatal(err)
	}
	// Without hosts, the target hosts; no target: nothing.
	if s.Allows("GET", mustURL(t, "https://other.example.com/"), []string{"t.example.com"}) == nil {
		t.Fatal("a host outside the targets")
	}
	if s.Allows("GET", mustURL(t, "https://t.example.com/"), nil) == nil {
		t.Fatal("no hosts and no targets must allow nothing")
	}
}

func TestValidate(t *testing.T) {
	good := &Scope{Hosts: []string{"*.example.com", "10.0.0.1"}, PathPrefixes: []string{"/"}, DenyPaths: []string{"/logout"}, Methods: []string{"GET"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []*Scope{
		{Hosts: []string{"a.*.example.com"}},
		{Hosts: []string{"*example.com"}},
		{Hosts: []string{"example.com/path"}},
		{Hosts: []string{""}},
		{PathPrefixes: []string{"app"}},
		{PathPrefixes: []string{"/app/../admin"}},
		{DenyPaths: []string{"/x?y"}},
		{DenyPaths: []string{"/x\n"}},
		{Methods: []string{"TRACE"}},
		{Methods: []string{"get"}},
		{DenyPaths: []string{"/" + strings.Repeat("a", 600)}},
		{Hosts: make([]string, 65)},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, s)
		}
	}
}

func FuzzAllowsDenied(f *testing.F) {
	for _, s := range []string{"/admin", "/x/../admin", "/ADMIN/", "/%61dmin", "//admin", "/a/./admin"} {
		f.Add(s)
	}
	s := &Scope{Hosts: []string{"example.com"}, DenyPaths: []string{"/admin"}}
	f.Fuzz(func(t *testing.T, p string) {
		u, err := url.Parse("https://example.com" + p)
		if err != nil || u.Host != "example.com" {
			return
		}
		if s.Allows("GET", u, nil) != nil {
			return
		}
		// Allowed: what the server sees must not be under /admin.
		c, err := CleanPath(u)
		if err != nil || strings.HasPrefix(strings.ToLower(c), "/admin") {
			t.Fatalf("allowed %q (server path %q)", p, c)
		}
	})
}
