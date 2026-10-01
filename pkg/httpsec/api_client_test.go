package httpsec

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The API base URL is operator configuration, so the API client must reach
// a platform on loopback or a private network without any env opt-in.
func TestNewAPIClient_ReachesLoopbackPlatform(t *testing.T) {
	if AllowLoopback {
		t.Skip("loopback already allowed process-wide; the default posture is what is under test")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resp, err := NewAPIClient(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("API client refused the configured loopback platform: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	// The general-purpose client keeps refusing the same address.
	if _, err := SafeHTTPClient(5 * time.Second).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("SafeHTTPClient reached loopback; err = %v", err)
	}
}

func TestNewAPIClient_StillRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := NewAPIClient(5 * time.Second).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "refusing to follow redirect") {
		t.Fatalf("redirect was followed or failed oddly: %v", err)
	}
}

func TestIsAPIDestinationBlocked(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":       false, // single-host install
		"::1":             false,
		"10.96.0.10":      false, // Kubernetes service IP
		"172.18.0.5":      false, // Docker network
		"192.168.1.20":    false,
		"fd00::1":         false, // IPv6 ULA
		"100.100.1.1":     false, // Tailscale / CGNAT
		"203.0.113.10":    false, // public
		"169.254.169.254": true,  // cloud metadata
		"fe80::1":         true,
		"0.0.0.0":         true,
		"::":              true,
		"224.0.0.1":       true,
		"ff02::1":         true,
		"240.0.0.1":       true,
		"255.255.255.255": true,
	}
	for s, want := range cases {
		if got := isAPIDestinationBlocked(net.ParseIP(s)); got != want {
			t.Errorf("isAPIDestinationBlocked(%s) = %v, want %v", s, got, want)
		}
	}
	if !isAPIDestinationBlocked(nil) {
		t.Error("nil IP must be blocked")
	}
}
