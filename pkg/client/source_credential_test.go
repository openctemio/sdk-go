package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// The credential of a code-scan source is asked for the command under the
// lease the sensor holds, on v2 HTTPS.
func TestSourceCredential(t *testing.T) {
	var gotPath, gotEpoch, gotMethod string
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
			_, _ = w.Write([]byte(`{"id":"c1","status":"running","lease_epoch":3}`))
		case protov2.PathPrefix + "/commands/c1/" + protov2.SourceCredentialAction:
			gotPath, gotMethod, gotEpoch = r.URL.Path, r.Method, r.Header.Get(protov2.HeaderLeaseEpoch)
			_, _ = w.Write([]byte(`{"username":"x-access-token","password":"ghs_tok"}`))
		case protov2.PathPrefix + "/commands/c2/" + protov2.SourceCredentialAction:
			_, _ = w.Write([]byte(`{}`))
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
	cred, err := c.SourceCredential(ctx, "c1")
	if err != nil || cred.Username != "x-access-token" || cred.Password != "ghs_tok" {
		t.Fatalf("credential: %+v %v", cred, err)
	}
	if gotMethod != http.MethodPost || gotEpoch != "3" || gotPath == "" {
		t.Fatalf("request: %s %s epoch %q", gotMethod, gotPath, gotEpoch)
	}
	if _, err := c.SourceCredential(ctx, "c2"); err == nil {
		t.Fatal("an answer without a credential was accepted")
	}
	if _, err := c.SourceCredential(ctx, ""); err == nil {
		t.Fatal("no command id accepted")
	}
}

// Protocol v3 does not carry the source credential: it stays on v2 HTTPS.
func TestV3DoesNotCarrySourceCredential(t *testing.T) {
	if v3Carries(http.MethodPost, "/commands/c1/"+protov2.SourceCredentialAction) {
		t.Fatal("v3 carries the source credential")
	}
	if !v3Carries(http.MethodPost, "/commands/c1/complete") {
		t.Fatal("v3 no longer carries command transitions")
	}
}
