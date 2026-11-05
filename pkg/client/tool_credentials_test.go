package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// A tool's source keys are asked for the command under the lease the
// sensor holds, on v2 HTTPS, naming the tool.
func TestToolCredentials(t *testing.T) {
	var gotEpoch, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: []string{protov2.FeatureCommands},
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
			return
		}
		switch r.URL.Path {
		case protov2.PathPrefix + "/commands/c1/start":
			_, _ = w.Write([]byte(`{"id":"c1","status":"running","lease_epoch":4}`))
		case protov2.PathPrefix + "/commands/c1/" + protov2.ToolCredentialsAction:
			b, _ := io.ReadAll(r.Body)
			gotEpoch, gotBody = r.Header.Get(protov2.HeaderLeaseEpoch), string(b)
			_, _ = w.Write([]byte(`{"credentials":[{"name":"shodan","value":"k1"},{"name":"empty","value":""}],"local_fallback":true}`))
		case protov2.PathPrefix + "/commands/c2/" + protov2.ToolCredentialsAction:
			w.Header().Set("Content-Type", protov2.MediaTypeProblem)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"type":"https://openctem.io/problems/ingest/command-not-found","title":"gone","status":404}`))
		default:
			w.Header().Set("Content-Type", "text/plain")
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	ctx := context.Background()
	if err := c.StartCommand(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	set, err := c.ToolCredentials(ctx, "c1", "subfinder")
	if err != nil || len(set.Values) != 1 || set.Values["shodan"] != "k1" || !set.LocalFallback {
		t.Fatalf("set %+v %v", set, err)
	}
	if gotEpoch != "4" || !strings.Contains(gotBody, `"tool":"subfinder"`) {
		t.Fatalf("request epoch %q body %s", gotEpoch, gotBody)
	}
	// A refusal is an error, never "the platform has none".
	if _, err := c.ToolCredentials(ctx, "c2", "subfinder"); err == nil || errors.Is(err, core.ErrToolCredentialsUnsupported) {
		t.Fatalf("refusal: %v", err)
	}
	// A platform without the route: the sensor keeps its own.
	if _, err := c.ToolCredentials(ctx, "c3", "subfinder"); !errors.Is(err, core.ErrToolCredentialsUnsupported) {
		t.Fatalf("unknown route: %v", err)
	}
	if _, err := c.ToolCredentials(ctx, "c1", ""); err == nil {
		t.Fatal("no tool accepted")
	}
	if v3Carries(http.MethodPost, "/commands/c1/"+protov2.ToolCredentialsAction) {
		t.Fatal("v3 carries tool credentials")
	}
}
