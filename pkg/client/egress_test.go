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

// A proxy pool's credentials and its report go for the command under the
// lease the sensor holds, on v2 HTTPS.
func TestEgressCredentialsAndReport(t *testing.T) {
	var credBody, reportBody []byte
	var credEpoch, reportEpoch string
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
		case protov2.PathPrefix + "/commands/c1/" + protov2.EgressCredentialsAction:
			credBody, _ = io.ReadAll(r.Body)
			credEpoch = r.Header.Get(protov2.HeaderLeaseEpoch)
			_, _ = w.Write([]byte(`{"credentials":[{"endpoint_id":"e1","username":"u","password":"p"}]}`))
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
	creds, err := c.EgressCredentials(ctx, "c1", "pool-1")
	if err != nil || len(creds) != 1 || creds[0] != (upstream.Credential{EndpointID: "e1", Username: "u", Password: "p"}) {
		t.Fatalf("credentials %+v %v", creds, err)
	}
	if string(credBody) != `{"pool_id":"pool-1"}` || credEpoch != "4" {
		t.Fatalf("credentials request %s epoch %q", credBody, credEpoch)
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
	if got.PoolID != "pool-1" || len(got.Endpoints) != protov2.MaxEgressReportEndpoints || len(got.Endpoints[0].LastError) != protov2.MaxEgressLastError {
		t.Fatalf("report bounds: %d endpoints, last_error %d", len(got.Endpoints), len(got.Endpoints[0].LastError))
	}
	if _, err := c.EgressCredentials(ctx, "", "pool-1"); err == nil {
		t.Fatal("no command id accepted")
	}
	if _, err := c.EgressCredentials(ctx, "c2", "pool-1"); err == nil {
		t.Fatal("a 404 was not an error")
	}
}

// Protocol v3 carries neither: they stay on v2 HTTPS.
func TestV3DoesNotCarryEgress(t *testing.T) {
	for _, a := range []string{protov2.EgressCredentialsAction, protov2.EgressReportAction} {
		if v3Carries(http.MethodPost, "/commands/c1/"+a) {
			t.Fatalf("v3 carries %s", a)
		}
	}
}
