package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// refusalServer is a v2 platform whose hello lists features; it records the
// body of every POST .../fail.
func refusalServer(t *testing.T, features []string) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: features,
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
			return
		}
		if r.URL.Path == protov2.CommandActionPath("c1", protov2.FailAction) {
			raw, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			mu.Lock()
			bodies = append(bodies, m)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"id":"c1","status":"failed"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), bodies...)
	}
}

// A refused command's result carries the structured refusal to a platform
// that lists "refusal", and only the text to one that does not (an older
// platform could reject an unknown field). The text is the same either way.
func TestFail_StructuredRefusalOnlyWhenOffered(t *testing.T) {
	refused := &core.CommandResult{
		Status: "failed", Error: "refused by local policy: tools.allow: nuclei is not in tools.allow",
		Refusal: core.RefusalOf(&core.LocalPolicyError{Rule: "tools.allow", Detail: "nuclei is not in tools.allow"}),
	}
	for _, tc := range []struct {
		name     string
		features []string
		want     bool
	}{
		{"offered", []string{protov2.FeatureCommands, protov2.FeatureRefusal}, true},
		{"not offered", []string{protov2.FeatureCommands}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, bodies := refusalServer(t, tc.features)
			c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
			if err := c.ReportCommandResult(context.Background(), "c1", refused); err != nil {
				t.Fatal(err)
			}
			got := bodies()
			if len(got) != 1 {
				t.Fatalf("%d fail calls", len(got))
			}
			if got[0]["error_message"] != refused.Error {
				t.Errorf("error_message = %v", got[0]["error_message"])
			}
			ref, has := got[0]["refusal"].(map[string]any)
			if has != tc.want {
				t.Fatalf("refusal sent = %v, want %v (body %v)", has, tc.want, got[0])
			}
			if has && (ref["layer"] != "local" || ref["rule"] != "tools.allow" || ref["detail"] != "nuclei is not in tools.allow") {
				t.Errorf("refusal = %v", ref)
			}
		})
	}

	// A failure that is not a refusal sends none.
	srv, bodies := refusalServer(t, []string{protov2.FeatureCommands, protov2.FeatureRefusal})
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	if err := c.ReportCommandResult(context.Background(), "c1", &core.CommandResult{Status: "failed", Error: "nuclei exited 2"}); err != nil {
		t.Fatal(err)
	}
	if _, has := bodies()[0]["refusal"]; has {
		t.Error("a tool failure was reported as a refusal")
	}
}
