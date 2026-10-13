package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/netctx"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// networkServer is a v2 platform listing features whose egress echo answers
// echo (status 200) and that records registered manifests.
func networkServer(t *testing.T, features []string, echo string) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var manifests []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		switch r.URL.Path {
		case protov2.PathPrefix + protov2.HelloPath:
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: features,
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
		case protov2.PathPrefix + protov2.EgressEchoPath:
			_, _ = io.WriteString(w, echo)
		case protov2.PathPrefix + protov2.ManifestPath:
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			mu.Lock()
			manifests = append(manifests, m)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(protov2.ManifestResponse{ManifestDigest: "sha256:x"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any { mu.Lock(); defer mu.Unlock(); return manifests }
}

func TestEgressEcho(t *testing.T) {
	ctx := context.Background()
	newClient := func(url string) *Client {
		return New(&Config{BaseURL: url, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	}
	srv, _ := networkServer(t, []string{protov2.FeatureHeartbeat, protov2.FeatureNetwork}, `{"address":"2001:db8::7"}`)
	a, err := newClient(srv.URL).EgressEcho(ctx)
	if err != nil || a.String() != "2001:db8::7" {
		t.Fatalf("echo = %v, %v", a, err)
	}
	srv, _ = networkServer(t, []string{protov2.FeatureHeartbeat, protov2.FeatureNetwork}, `{"address":"::ffff:198.51.100.7"}`)
	if a, err = newClient(srv.URL).EgressEcho(ctx); err != nil || a.String() != "198.51.100.7" {
		t.Fatalf("mapped echo = %v, %v", a, err)
	}
	// Not listed: no request, unsupported.
	srv, _ = networkServer(t, []string{protov2.FeatureHeartbeat}, `{"address":"198.51.100.7"}`)
	if _, err = newClient(srv.URL).EgressEcho(ctx); !errors.Is(err, netctx.ErrEchoUnsupported) {
		t.Fatalf("unlisted: %v", err)
	}
	// Anything but an address is an error.
	for _, body := range []string{`{"address":"platform.example"}`, `{"address":""}`, `{"address":"fe80::1%eth0"}`} {
		srv, _ = networkServer(t, []string{protov2.FeatureNetwork}, body)
		if _, err = newClient(srv.URL).EgressEcho(ctx); err == nil || errors.Is(err, netctx.ErrEchoUnsupported) {
			t.Fatalf("%s: %v", body, err)
		}
	}
}

func TestPutManifest_NetworkOnlyWhenListed(t *testing.T) {
	ctx := context.Background()
	m := &core.Manifest{Schema: core.ManifestSchema, Tools: []core.ManifestTool{},
		Network: &netctx.Report{V: 1, Mode: netctx.ModeSummary, Fingerprint: "sha256:a", Internet: netctx.InternetNone}}
	for _, listed := range []bool{true, false} {
		features := []string{protov2.FeatureHeartbeat, protov2.FeatureManifest}
		if listed {
			features = append(features, protov2.FeatureNetwork)
		}
		srv, got := networkServer(t, features, "")
		c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
		if _, err := c.PutManifest(ctx, m); err != nil {
			t.Fatal(err)
		}
		ms := got()
		if len(ms) != 1 {
			t.Fatalf("%d manifests", len(ms))
		}
		if _, has := ms[0]["network"]; has != listed {
			t.Fatalf("listed %v: manifest has network %v", listed, has)
		}
	}
	if m.Network == nil {
		t.Fatal("PutManifest modified the caller's manifest")
	}
}
