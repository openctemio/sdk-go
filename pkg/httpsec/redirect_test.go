package httpsec

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustReq(t *testing.T, raw string, headers map[string]string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{URL: u, Header: http.Header{}}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

var credHeaders = map[string]string{
	"Authorization": "Bearer oct_secret",
	"X-API-Key":     "k",
	"X-Agent-Key":   "k",
	"X-ApiKeys":     "accessKey=a;secretKey=b",
	"Cookie":        "s=1",
	"X-Agent-ID":    "agent-1",
}

func TestSafeCheckRedirect(t *testing.T) {
	cases := []struct {
		name      string
		from, to  string
		wantErr   bool
		wantCreds bool // credentials still present on the redirected request
	}{
		{"https to http same host refused", "https://api.example.com/x", "http://api.example.com/x", true, false},
		{"https to http other host refused", "https://api.example.com/x", "http://evil.example.net/x", true, false},
		{"same origin keeps creds", "https://api.example.com/x", "https://api.example.com/y", false, true},
		{"default port is same origin", "https://api.example.com/x", "https://api.example.com:443/y", false, true},
		{"other host strips creds", "https://api.example.com/x", "https://evil.example.net/x", false, false},
		{"subdomain strips creds", "https://example.com/x", "https://cdn.example.com/x", false, false},
		{"other port strips creds", "https://api.example.com/x", "https://api.example.com:8443/x", false, false},
		{"http to https upgrade strips creds (origin change)", "http://api.example.com/x", "https://api.example.com/x", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			via := []*http.Request{mustReq(t, tc.from, credHeaders)}
			req := mustReq(t, tc.to, credHeaders)
			err := SafeCheckRedirect(req, via)
			if tc.wantErr {
				if err == nil {
					t.Fatal("redirect allowed, want refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, h := range []string{"Authorization", "X-API-Key", "X-Agent-Key", "X-ApiKeys", "Cookie"} {
				has := req.Header.Get(h) != ""
				if has != tc.wantCreds {
					t.Errorf("header %s present=%v, want %v", h, has, tc.wantCreds)
				}
			}
			if req.Header.Get("X-Agent-ID") == "" {
				t.Error("non-credential header should be kept")
			}
		})
	}

	// Redirect budget.
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = mustReq(t, "https://api.example.com/x", nil)
	}
	if err := SafeCheckRedirect(mustReq(t, "https://api.example.com/y", nil), via); err == nil {
		t.Error("redirect chain longer than the budget allowed")
	}
}

func TestRefuseRedirectsAndClients(t *testing.T) {
	if err := RefuseRedirects(mustReq(t, "https://elsewhere.example/", nil), nil); err == nil {
		t.Error("RefuseRedirects followed a redirect")
	}
	if SafeHTTPClient(0).CheckRedirect == nil {
		t.Error("SafeHTTPClient has no redirect policy")
	}
	c := NewAPIClient(0)
	if c.CheckRedirect == nil || c.CheckRedirect(mustReq(t, "https://x.example/", nil), nil) == nil {
		t.Error("NewAPIClient must refuse redirects")
	}
}

func TestIsIPBlockedWith_ExtraRanges(t *testing.T) {
	blocked := []string{"::", "0.0.0.0", "ff02::1", "ff05::2", "224.0.0.251", "fe80::1", "169.254.169.254", "::ffff:169.254.169.254", "127.0.0.1", "::1"}
	for _, s := range blocked {
		if !IsIPBlockedWith(net.ParseIP(s), true, false) {
			t.Errorf("%s not blocked (allow-private on)", s)
		}
	}
	if IsIPBlockedWith(net.ParseIP("10.0.0.1"), true, false) {
		t.Error("private should pass when allowed")
	}
	if !IsIPBlockedWith(net.ParseIP("10.0.0.1"), false, false) {
		t.Error("private should be blocked by default")
	}
	if IsIPBlockedWith(net.ParseIP("127.0.0.1"), false, true) {
		t.Error("loopback should pass when allowLoopback")
	}
	if !IsIPBlockedWith(net.ParseIP("169.254.169.254"), true, true) {
		t.Error("IMDS must stay blocked with every toggle on")
	}
	if !IsIPBlockedWith(nil, true, true) {
		t.Error("nil IP must be treated as blocked")
	}
}

func TestCheckAPIBaseURL(t *testing.T) {
	cases := []struct {
		raw         string
		wantErr     bool
		wantWarning bool
	}{
		{"https://api.openctem.io", false, false},
		{"https://api.openctem.io/", false, false},
		{"http://localhost:8080", false, false},
		{"http://127.0.0.1:8080", false, false},
		{"http://[::1]:8080", false, false},
		{"http://api.internal:8080", false, true},
		{"http://203.0.113.10", false, true},
		{"", true, false},
		{"ftp://api.example.com", true, false},
		{"file:///etc/passwd", true, false},
		{"api.example.com", true, false},
		{"https://", true, false},
		{"https://user:pass@api.example.com", true, false},
	}
	for _, tc := range cases {
		warn, err := CheckAPIBaseURL(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("CheckAPIBaseURL(%q) err=%v, wantErr=%v", tc.raw, err, tc.wantErr)
		}
		if (warn != "") != tc.wantWarning {
			t.Errorf("CheckAPIBaseURL(%q) warning=%q, wantWarning=%v", tc.raw, warn, tc.wantWarning)
		}
		if err != nil && strings.Contains(err.Error(), ":pass@") {
			t.Errorf("error leaks URL credentials: %v", err)
		}
	}
}
