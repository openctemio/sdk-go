package toolhost

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: the task's interaction server (RunOptions.OOB) reaches the
// task's forwarder only, which carries the interaction API and adds the
// token; without one the same request is refused.
func TestTaskForwarderCarriesTheInteractionServer(t *testing.T) {
	var auth []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	h := &Host{Backend: statusBackend{st: executor.Status{NetworkEnforced: true}},
		lookupVendor: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	m := tool.Manifest{Name: "nuclei", Permissions: tool.Permissions{Network: tool.NetTargets}}
	task := tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "domain_name", Value: "victim.example"}}}
	oob := &egress.OOBServer{Host: "example.com", Port: port, Authorization: "tok", PrivateOK: true, RootCAs: pool}

	post := func(p *prepared) int {
		t.Helper()
		eg, err := h.startEgress(context.Background(), h.backend(), p)
		if err != nil || eg == nil {
			t.Fatalf("forwarder: %v", err)
		}
		defer eg.stop()
		c := &http.Client{Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "forwarder"}),
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", eg.proxyPath())
			},
		}}
		resp, err := c.Post("http://example.com/register", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(&prepared{m: m, task: task, oob: oob}); code != http.StatusOK {
		t.Fatalf("with the server: %d", code)
	}
	if code := post(&prepared{m: m, task: task}); code != http.StatusForbidden {
		t.Fatalf("without a server: %d", code)
	}
	if strings.Join(auth, ",") != "tok" {
		t.Fatalf("the server saw %v", auth)
	}
}
