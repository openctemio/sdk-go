package toolrt

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func uaServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.UserAgent())
	}))
	t.Cleanup(srv.Close)
	return srv
}

var httpTool = tool.Manifest{Name: "acme-probe", Version: "v1.2.0", Permissions: tool.Permissions{Network: tool.NetTargets}}

func get(t *testing.T, c *http.Client, url, ua string) (string, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

// A tool's requests carry "openctem-<tool>/<version>" unless the tool sets
// its own User-Agent.
func TestHTTPUserAgent(t *testing.T) {
	srv := uaServer(t)
	c := NewHTTPClient(httpTool, tool.Task{Targets: []tool.Target{{Ref: "a", Value: srv.URL}}})
	if got, err := get(t, c, srv.URL, ""); err != nil || got != "openctem-acme-probe/1.2.0" {
		t.Fatalf("default: %q %v", got, err)
	}
	if got, err := get(t, c, srv.URL, "my-scanner/9"); err != nil || got != "my-scanner/9" {
		t.Fatalf("override: %q %v", got, err)
	}
}

// On a confined sensor the tool's client goes through the task's
// forwarder (its only way out) and still refuses other hosts before
// anything is sent.
func TestHTTPThroughTheForwarder(t *testing.T) {
	srv := uaServer(t)
	fw := egress.New(egress.Scope{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, egress.Limits{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fw.Serve(ctx, ln) }()
	t.Setenv(tool.EnvEgressProxy, "http://"+ln.Addr().String())

	c := NewHTTPClient(httpTool, tool.Task{Targets: []tool.Target{{Ref: "a", Value: srv.URL}}})
	if got, err := get(t, c, srv.URL, ""); err != nil || got != "openctem-acme-probe/1.2.0" {
		t.Fatalf("through the forwarder: %q %v", got, err)
	}
	recs, _ := fw.Records()
	if len(recs) != 1 || recs[0].Verdict != egress.Allowed {
		t.Fatalf("the request did not go through the forwarder: %+v", recs)
	}
	if _, err := get(t, c, "http://other.example/", ""); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("other host: %v", err)
	}
	if recs, _ := fw.Records(); len(recs) != 1 {
		t.Fatalf("a refused host reached the forwarder: %+v", recs)
	}
}
