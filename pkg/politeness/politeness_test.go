package politeness

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestTargetKeys(t *testing.T) {
	cases := []struct {
		target string
		want   []string
	}{
		// Names, URLs and services lease their host.
		{"www.Example.com", []string{"www.example.com"}},
		{"www.example.com.", []string{"www.example.com"}},
		{"https://www.example.com:8443/a/b?q=1", []string{"www.example.com"}},
		{"https://user@www.example.com/", []string{"www.example.com"}},
		{"www.example.com:443:tcp", []string{"www.example.com"}},
		{"www.example.com:443/udp", []string{"www.example.com"}},
		{"www.example.com:443", []string{"www.example.com"}},
		{"www.example.com/login/form", []string{"www.example.com"}},
		// Addresses: canonical form and the bucket marker.
		{"203.0.113.5", []string{"203.0.113.5", "in:203.0.113.0/24"}},
		{"::ffff:203.0.113.5", []string{"203.0.113.5", "in:203.0.113.0/24"}},
		{"203.0.113.5/32", []string{"203.0.113.5", "in:203.0.113.0/24"}},
		{"http://203.0.113.5:8080/", []string{"203.0.113.5", "in:203.0.113.0/24"}},
		{"203.0.113.5:443:tcp", []string{"203.0.113.5", "in:203.0.113.0/24"}},
		{"[2001:DB8::1]:443", []string{"2001:db8::1", "in:2001:db8::/120"}},
		{"2001:db8::1:443:tcp", []string{"2001:db8::1", "in:2001:db8::/120"}},
		{"2001:db8:0:0::1", []string{"2001:db8::1", "in:2001:db8::/120"}},
		// Ranges: one range key per bucket.
		{"203.0.113.0/24", []string{"net:203.0.113.0/24"}},
		{"203.0.113.128/25", []string{"net:203.0.113.0/24"}},
		{"10.0.0.0/22", []string{"net:10.0.0.0/24", "net:10.0.1.0/24", "net:10.0.2.0/24", "net:10.0.3.0/24"}},
		{"10.0.0.250-10.0.1.3", []string{"net:10.0.0.0/24", "net:10.0.1.0/24"}},
		{"2001:db8::/119", []string{"net:2001:db8::/120", "net:2001:db8::100/120"}},
		// Wider than MaxKeys buckets: the widest covering prefixes.
		{"10.0.0.0/8", []string{"net:10.0.0.0/8"}},
		// Repositories in scp form, local paths.
		{"git@GitHub.com:Owner/repo.git", []string{"github.com/owner"}},
		{"https://github.com/Acme/api.git", []string{"github.com/acme"}},
		{"ssh://git@github.com/acme/api.git", []string{"github.com/acme"}},
		{"https://github.com/acme/api", []string{"github.com"}},
		{"https://example.com/app.git", []string{"example.com"}},
		{"/src/App", []string{"/src/App"}},
		{"./src", []string{"./src"}},
		{`C:\src`, []string{`C:\src`}},
		// Nothing to read.
		{"", nil},
		{"   ", nil},
		{"https://[::1", nil},
	}
	for _, c := range cases {
		if got := TargetKeys(c.target, ""); !slices.Equal(got, c.want) {
			t.Errorf("TargetKeys(%q) = %q, want %q", c.target, got, c.want)
		}
	}
}

// A single-letter host with a port is a host, not a drive path.
func TestTargetKeys_SingleLetterHostIsNotAPath(t *testing.T) {
	if got := TargetKeys("a:80", ""); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("a:80 = %q", got)
	}
}

// Overlapping private ranges at two sites are two sets of hosts; the same
// site is one; public hosts are one host from every network.
func TestTargetKeys_NetworkContext(t *testing.T) {
	const siteA, siteB = "0b0f3d2e-1c4a-4e8f-9a51-2f6b7c8d9e01", "7d1e2f30-4b5c-4d6e-8f70-819a2b3c4d5e"
	a := TargetKeys("10.0.0.5", siteA)
	if want := []string{"10.0.0.5#" + siteA, "in:10.0.0.0/24#" + siteA}; !slices.Equal(a, want) {
		t.Fatalf("site A keys = %q, want %q", a, want)
	}
	b := TargetKeys("10.0.0.5", siteB)
	if conflict(a, b) {
		t.Fatalf("10.0.0.5 at two sites conflict: %q vs %q", a, b)
	}
	if !conflict(a, TargetKeys("10.0.0.5", strings.ToUpper(siteA))) {
		t.Fatal("10.0.0.5 at one site does not conflict with itself")
	}
	// Range scan of a site's bucket vs an address in it: conflict only on
	// the same site.
	rA, rB := TargetKeys("10.0.0.0/24", siteA), TargetKeys("10.0.0.0/24", siteB)
	if !conflict(a, rA) || conflict(a, rB) || conflict(rA, rB) {
		t.Fatalf("range/address across sites: a=%q rA=%q rB=%q", a, rA, rB)
	}
	// Every private kind carries the network; public addresses never do.
	for _, ip := range []string{"192.168.1.1", "172.16.0.1", "100.64.0.1", "127.0.0.1", "169.254.0.1", "fd00::1", "fe80::1"} {
		for _, k := range TargetKeys(ip, siteA) {
			if !strings.HasSuffix(k, "#"+siteA) {
				t.Errorf("%s: key %q has no network", ip, k)
			}
		}
	}
	for _, ip := range []string{"203.0.113.5", "8.8.8.8", "2001:db8::1", "203.0.113.0/24"} {
		pa, pb := TargetKeys(ip, siteA), TargetKeys(ip, siteB)
		if !slices.Equal(pa, TargetKeys(ip, "")) || !conflict(pa, pb) {
			t.Errorf("public %s is scoped to a network: %q / %q", ip, pa, pb)
		}
	}
	// Names belong to the network the work names.
	if n := TargetKeys("intranet.corp", siteA); !slices.Equal(n, []string{"intranet.corp#" + siteA}) || conflict(n, TargetKeys("intranet.corp", siteB)) {
		t.Fatalf("names across sites: %q", n)
	}
	// An id that cannot be read leaves the keys global (stricter, never
	// looser).
	for _, bad := range []string{"a#b", "a b", "../x", strings.Repeat("a", 65), "net:x"} {
		if got := TargetKeys("10.0.0.5", bad); !slices.Equal(got, TargetKeys("10.0.0.5", "")) {
			t.Errorf("network %q: keys %q", bad, got)
		}
	}
}

// Addresses vs ranges vs names, in both directions.
func TestConflicts(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.5", "10.0.0.5", true},
		{"10.0.0.5", "http://10.0.0.5:8080/x", true},
		{"10.0.0.5", "::ffff:10.0.0.5", true},
		{"10.0.0.5", "10.0.0.6", false}, // two addresses of one bucket
		{"10.0.0.5", "10.0.0.0/24", true},
		{"10.0.0.5", "10.0.0.0/22", true},
		{"10.0.0.5", "10.0.1.0/24", false},
		{"10.0.0.0/24", "10.0.0.128/25", true},
		{"10.0.0.0/25", "10.0.0.128/25", true}, // one bucket, scanned twice
		{"10.0.0.0/24", "10.0.1.0/24", false},
		{"www.example.com", "https://WWW.example.com./x", true},
		{"www.example.com", "api.example.com", false},
		{"www.example.com", "www.example.com:443:tcp", true},
		{"2001:db8::1", "2001:db8::/120", true},
		{"2001:db8::1", "2001:db8::2", false},
	}
	for _, c := range cases {
		ka, kb := TargetKeys(c.a, ""), TargetKeys(c.b, "")
		if got := conflict(ka, kb); got != c.want {
			t.Errorf("%s vs %s: conflict=%v, want %v (keys %q / %q)", c.a, c.b, got, c.want, ka, kb)
		}
		if conflict(kb, ka) != conflict(ka, kb) {
			t.Errorf("%s vs %s: not symmetric", c.a, c.b)
		}
	}
}

func TestKeys(t *testing.T) {
	got := Keys([]string{"b.example.com", "10.0.0.5", "a.example.com", "B.example.com", "10.0.0.6"}, "")
	want := []string{"10.0.0.5", "10.0.0.6", "a.example.com", "b.example.com", "in:10.0.0.0/24"}
	if !slices.Equal(got, want) {
		t.Fatalf("Keys = %q, want %q", got, want)
	}
	if Keys(nil, "") != nil || Keys([]string{"", " "}, "") != nil {
		t.Fatal("no host must give nil keys")
	}
	many := make([]string, 0, 2*MaxKeys)
	for i := range 2 * MaxKeys {
		many = append(many, fmt.Sprintf("h%d.example.com", i))
	}
	if n := len(Keys(many, "")); n != MaxKeys {
		t.Fatalf("Keys of %d hosts = %d keys, want %d", len(many), n, MaxKeys)
	}
}

func TestLock(t *testing.T) {
	if Lock("in:10.0.0.0/24") != Lock("net:10.0.0.0/24") || Lock("in:10.0.0.0/24#a") != "b:10.0.0.0/24#a" || Lock("x.example.com") != "x.example.com" {
		t.Fatal("bucket marker and bucket range must share one lock")
	}
	if Lock("in:10.0.0.0/24#a") == Lock("in:10.0.0.0/24#b") {
		t.Fatal("buckets of two networks must not share a lock")
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://Example.COM./x":  "example.com",
		"[2001:db8::1]:443":       "2001:db8::1",
		"10.0.0.0/24":             "10.0.0.0/24",
		"10.0.0.7/24":             "10.0.0.0/24",
		"git@github.com:org/repo": "github.com/org",
		"example.com:99999":       "example.com",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func conflict(a, b []string) bool {
	held := map[string]bool{}
	for _, k := range a {
		held[k] = true
	}
	for _, k := range Conflicts(b) {
		if held[k] {
			return true
		}
	}
	return false
}
