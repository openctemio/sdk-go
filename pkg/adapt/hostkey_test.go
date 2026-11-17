package adapt

import "testing"

// Every spelling of one host reduces to one key, so no spelling gets a
// budget of its own.
func TestCanonicalHostAliasForms(t *testing.T) {
	groups := map[string][]string{
		"a.example.com":         {"a.example.com", "A.Example.COM", "a.example.com.", " a.example.com "},
		"xn--bcher-kva.example": {"bücher.example", "BÜCHER.example", "xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE", "bücher.example."},
		"192.0.2.1": {"192.0.2.1", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]", "::ffff:c000:201", "0xc0000201", "3221225985",
			"0300.0.2.1", "192.0.513", "0xC0.0.2.1"},
		"127.0.0.1":   {"127.0.0.1", "2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0x7f.1"},
		"2001:db8::1": {"2001:db8::1", "2001:DB8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "[2001:db8::1]", "2001:db8:0:0::1", "2001:db8::1%eth0"},
	}
	for want, forms := range groups {
		for _, f := range forms {
			if got := CanonicalHost(f); got != want {
				t.Errorf("CanonicalHost(%q) = %q, want %q", f, got, want)
			}
		}
	}
	// Not addresses, and not rewritten into one.
	for _, name := range []string{"1.2.3.4.5", "0x.example.com", "256.example.com", "a_b.example.com"} {
		if got := CanonicalHost(name); got != name {
			t.Errorf("CanonicalHost(%q) = %q", name, got)
		}
	}
	if CanonicalHost("") != "" || CanonicalHost(" . ") != "" {
		t.Error("an empty host has a key")
	}
}

// HostKey of a target is the canonical host whatever the scheme, port,
// path and spelling; the hosts of a list are counted by it.
func TestHostKeyAliasForms(t *testing.T) {
	groups := map[string][]string{
		"xn--bcher-kva.example": {"https://bücher.example/a", "http://XN--BCHER-KVA.example:8080/", "bücher.example:443", "xn--bcher-kva.example."},
		"192.0.2.1":             {"https://192.0.2.1/", "https://[::ffff:192.0.2.1]:8443/x", "http://0xc0000201/", "http://3221225985:8080/", "192.0.2.1:22"},
		"2001:db8::1":           {"https://[2001:db8::1]/", "https://[2001:DB8:0:0:0:0:0:1]:8443/", "2001:db8::1"},
	}
	for want, targets := range groups {
		for _, target := range targets {
			if got := HostKey(target); got != want {
				t.Errorf("HostKey(%q) = %q, want %q", target, got, want)
			}
		}
		if hosts, most := CountHosts(targets); hosts != 1 || most != len(targets) {
			t.Errorf("%v: %d hosts, the largest with %d targets; want one host", targets, hosts, most)
		}
	}
	// What is not a network host keeps its politeness key.
	for target, want := range map[string]string{"/srv/code": "/srv/code", "10.0.0.0/24": "10.0.0.0/24", "": ""} {
		if got := HostKey(target); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", target, got, want)
		}
	}
}
