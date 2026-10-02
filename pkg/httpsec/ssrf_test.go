package httpsec

import (
	"net"
	"strings"
	"testing"
)

// The test set is a near-copy of api/pkg/httpsec/ssrf_test.go. Mirror
// both files when updating; scripts/security-lint.sh cross-checks
// that the underlying blocklists agree.

// The httpsec package exposes AllowLoopback for consumers' unit tests
// (httptest.NewServer binds to 127.0.0.1). Our own tests assert the
// production posture, so pin AllowLoopback=false regardless of any
// OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK env var set by the harness.
func TestMain(m *testing.M) {
	AllowLoopback = false
	m.Run()
}

// TestValidateURL_BlockedCategories asserts the guard rejects every
// public-wrong category an SDK caller might point a webhook at. Each
// line is a named threat; a failure here means the SSRF door is open.
func TestValidateURL_BlockedCategories(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string // substring of the error
	}{
		{"loopback ipv4", "http://127.0.0.1/", "blocked"},
		{"loopback ipv6", "http://[::1]/", "blocked"},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/", "blocked"},
		{"metadata alias", "http://metadata.google.internal/", "blocked hostname"},
		{"localhost alias", "http://localhost:8080/", "blocked hostname"},
		{"file scheme", "file:///etc/passwd", "unsupported scheme"},
		{"gopher scheme", "gopher://evil/", "unsupported scheme"},
		{"unix scheme", "unix:///var/run/docker.sock", "unsupported scheme"},
		{"no host", "http:///just-a-path", "no host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateURL(tc.url)
			if err == nil {
				t.Fatalf("expected %q to be rejected, but got nil error", tc.url)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing expected substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestIsIPBlocked_Ranges asserts the CIDR table expands to the exact
// IPs we care about. Pinned in sync with the api-side copy.
func TestIsIPBlocked_Ranges(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.255",
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"0.0.0.1",
		"224.1.2.3",
	}
	for _, ip := range blocked {
		if !IsIPBlocked(net.ParseIP(ip)) {
			t.Fatalf("expected %s to be blocked", ip)
		}
	}

	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"140.82.114.3", // github.com
	}
	for _, ip := range public {
		if IsIPBlocked(net.ParseIP(ip)) {
			t.Fatalf("unexpectedly blocked public IP %s", ip)
		}
	}
}

// TestIsIPBlocked_IPv6MetadataAlwaysBlocked: the AWS (fd00:ec2::254) and GCP
// (fd20:ce::254) metadata services over IPv6 are inside the ULA range
// (fc00::/7) that the allow-private opt-in opens. They must stay blocked
// in every mode, like 169.254.169.254.
func TestIsIPBlocked_IPv6MetadataAlwaysBlocked(t *testing.T) {
	for _, s := range []string{"fd00:ec2::254", "fd20:ce::254"} {
		ip := net.ParseIP(s)
		for _, allowPriv := range []bool{false, true} {
			if !IsIPBlockedWith(ip, allowPriv, false) {
				t.Errorf("IsIPBlockedWith(%s, allowPrivate=%v) = false, want true", s, allowPriv)
			}
		}
	}
	// The rest of the ULA range still follows the opt-in.
	if IsIPBlockedWith(net.ParseIP("fd00:ec2::253"), true, false) {
		t.Error("fd00:ec2::253 blocked with allow-private; only the metadata address should be")
	}
}
