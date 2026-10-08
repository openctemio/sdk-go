package toolrt

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// tool.yaml http sets the tool's User-Agent and headers (a request's own
// values win), and TLS toward its targets.
func TestHTTPOverridesFromTheDescriptor(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s", r.UserAgent(), r.Header.Get("X-Scan-Id"))
	}))
	defer srv.Close()
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Value: srv.URL}}}

	m := httpTool
	plain := NewHTTPClient(m, task)
	if _, err := plain.Get(srv.URL); err == nil {
		t.Fatal("a self-signed target was accepted without tls.insecure_skip_verify")
	}

	m.HTTP = &tool.HTTPSpec{UserAgent: "acme-scanner/2.0", Headers: map[string]string{"X-Scan-Id": "run-7"},
		Timeout: tool.Duration(10 * time.Second), TLS: &tool.TLSSpec{InsecureSkipVerify: true}}
	c := NewHTTPClient(m, task)
	if c.Timeout != 10*time.Second {
		t.Fatalf("timeout %v", c.Timeout)
	}
	if got, err := get(t, c, srv.URL, ""); err != nil || got != "acme-scanner/2.0|run-7" {
		t.Fatalf("descriptor values: %q %v", got, err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "per-request/1")
	req.Header.Set("X-Scan-Id", "mine")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != "per-request/1|mine" {
		t.Fatalf("a request's own values must win: %q", b)
	}

	// SECURITY: a vendor tool's TLS is always verified.
	v := m
	v.Permissions = tool.Permissions{Network: tool.NetVendor, VendorHosts: []string{"127.0.0.1"}}
	if _, err := NewHTTPClient(v, task).Get(srv.URL); err == nil {
		t.Fatal("a vendor tool skipped certificate verification")
	}
}
