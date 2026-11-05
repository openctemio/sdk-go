package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// A proxy pool's report goes for the command under the lease the sensor
// holds, its epoch inside the body, on v2 HTTPS.
func TestEgressReport(t *testing.T) {
	var reportBody []byte
	var reportEpoch string
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
		case protov2.PathPrefix + "/commands/c1/" + protov2.EgressReportAction:
			reportBody, _ = io.ReadAll(r.Body)
			reportEpoch = r.Header.Get(protov2.HeaderLeaseEpoch)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	ctx := context.Background()
	if err := c.StartCommand(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	eps := make([]upstream.EndpointReport, 70)
	for i := range eps {
		eps[i] = upstream.EndpointReport{EndpointID: "e", OK: 1, LastError: strings.Repeat("x", 300)}
	}
	if err := c.EgressReport(ctx, "c1", upstream.Report{PoolID: "pool-1", Endpoints: eps}); err != nil {
		t.Fatal(err)
	}
	var got protov2.EgressReport
	if err := json.Unmarshal(reportBody, &got); err != nil || reportEpoch != "4" {
		t.Fatalf("report %s %v epoch %q", reportBody, err, reportEpoch)
	}
	if got.LeaseEpoch != 4 {
		t.Fatalf("report lease epoch %d, want 4 in the body", got.LeaseEpoch)
	}
	if got.PoolID != "pool-1" || len(got.Endpoints) != protov2.MaxEgressReportEndpoints || len(got.Endpoints[0].LastError) != protov2.MaxEgressLastError {
		t.Fatalf("report bounds: %d endpoints, last_error %d", len(got.Endpoints), len(got.Endpoints[0].LastError))
	}
	if err := c.EgressReport(ctx, "", upstream.Report{PoolID: "pool-1"}); err == nil {
		t.Fatal("no command id accepted")
	}
}

// Protocol v3 carries neither the secrets fetch nor the egress report: they
// stay on v2 HTTPS.
func TestV3DoesNotCarryEgress(t *testing.T) {
	for _, a := range []string{protov2.SecretsAction, protov2.EgressReportAction} {
		if v3Carries(http.MethodPost, "/commands/c1/"+a) {
			t.Fatalf("v3 carries %s", a)
		}
	}
}
