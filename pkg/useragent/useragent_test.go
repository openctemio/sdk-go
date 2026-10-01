package useragent

import (
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionFromBuildInfo(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"no build info", nil, false, "devel"},
		{"sdk as a dependency", &debug.BuildInfo{
			Main: debug.Module{Path: "github.com/openctemio/agent", Version: "v0.3.1"},
			Deps: []*debug.Module{
				{Path: "golang.org/x/net", Version: "v0.40.0"},
				{Path: sdkModule, Version: "v0.7.4"},
			},
		}, true, "0.7.4"},
		{"sdk replaced", &debug.BuildInfo{
			Main: debug.Module{Path: "example.com/x"},
			Deps: []*debug.Module{{Path: sdkModule, Version: "v0.7.4", Replace: &debug.Module{Path: "../sdk-go"}}},
		}, true, "devel"},
		{"sdk is the main module", &debug.BuildInfo{
			Main: debug.Module{Path: sdkModule, Version: "v0.8.0-0.20261001000000-abcdef123456"},
		}, true, "0.8.0-0.20261001000000-abcdef123456"},
		{"main module devel", &debug.BuildInfo{
			Main: debug.Module{Path: sdkModule, Version: "(devel)"},
		}, true, "devel"},
		{"sdk not linked", &debug.BuildInfo{Main: debug.Module{Path: "example.com/x", Version: "v1.0.0"}}, true, "devel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionFromBuildInfo(tt.info, tt.ok); got != tt.want {
				t.Errorf("versionFromBuildInfo = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProduct(t *testing.T) {
	tests := []struct {
		name, product, version, want string
	}{
		{"name and version", "openctemio-sensor", "0.3.1", "openctemio-sensor/0.3.1"},
		{"leading v dropped", "openctemio-sensor", "v0.3.1", "openctemio-sensor/0.3.1"},
		{"no version", "openctemio-sensor", "", "openctemio-sensor"},
		{"empty name", "", "1.0", ""},
		{"CR LF and spaces removed", "evil\r\nX-Injected: 1", "1.0\r\n", "evilX-Injected1/1.0"},
		{"slash in name removed", "a/b", "1", "ab/1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Product(tt.product, tt.version); got != tt.want {
				t.Errorf("Product(%q, %q) = %q, want %q", tt.product, tt.version, got, tt.want)
			}
		})
	}
	if got := Product(strings.Repeat("a", 500), "1"); len(got) > maxProductLen {
		t.Errorf("Product not bounded: %d bytes", len(got))
	}
}

func TestWithProduct(t *testing.T) {
	sdk := "openctem-sdk-go/" + SDKVersion()
	tests := []struct{ in, want string }{
		{"", sdk},
		{"openctemio-sensor/0.3.1", "openctemio-sensor/0.3.1 " + sdk},
		{"a/1 b/2", "a/1 b/2 " + sdk},
		{"x/1\r\nInjected: yes", "x/1 Injected yes " + sdk},
	}
	for _, tt := range tests {
		got := WithProduct(tt.in)
		if got != tt.want {
			t.Errorf("WithProduct(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("WithProduct(%q) contains CR/LF", tt.in)
		}
	}
	if got := WithProduct(strings.Repeat("a/1 ", 200)); len(got) > maxProductLen+len(sdk)+1 {
		t.Errorf("WithProduct not bounded: %d bytes", len(got))
	}
}

func TestSetProductAndTransport(t *testing.T) {
	t.Cleanup(func() { product.Store("") })

	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	c := &http.Client{Transport: Transport(nil)}
	do := func(ua string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if req.Header.Get("User-Agent") != ua {
			t.Errorf("Transport modified the caller's request")
		}
	}

	sdk := "openctem-sdk-go/" + SDKVersion()
	do("")
	SetProduct("openctemio-sensor", "v0.3.1")
	do("")
	do("explicit/1")

	want := []string{sdk, "openctemio-sensor/0.3.1 " + sdk, "explicit/1"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("User-Agents sent = %q, want %q", got, want)
	}
}
