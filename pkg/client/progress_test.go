package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// The heartbeat carries per-command progress only to a platform that lists
// the command_progress feature; an older platform is never sent it.
func TestHeartbeatProgressOnlyToAPlatformThatReadsIt(t *testing.T) {
	send := func(features []string) map[string]any {
		t.Helper()
		var mu sync.Mutex
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", protov2.MediaTypeJSON)
			w.Header().Set(protov2.HeaderProtocol, "2")
			switch r.URL.Path {
			case protov2.PathPrefix + protov2.HelloPath:
				_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: features,
					MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
			case protov2.PathPrefix + protov2.HeartbeatPath:
				mu.Lock()
				_ = json.NewDecoder(r.Body).Decode(&got)
				mu.Unlock()
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
		err := c.SendHeartbeat(context.Background(), &core.SensorStatus{
			Name: "s1", Status: core.SensorStateRunning,
			RunningCommands: []string{"c1"},
			Progress:        map[string]core.CommandProgress{"c1": {Done: 3, Total: 72}},
		})
		if err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		return got
	}

	got := send([]string{protov2.FeatureHeartbeat, protov2.FeatureCommandProgress})
	p, ok := got["progress"].(map[string]any)
	if !ok {
		t.Fatalf("progress not sent: %v", got)
	}
	if c1, _ := p["c1"].(map[string]any); c1["done"] != float64(3) || c1["total"] != float64(72) {
		t.Fatalf("progress = %v", p)
	}
	if got := send([]string{protov2.FeatureHeartbeat}); got["progress"] != nil {
		t.Fatalf("progress sent to a platform without the feature: %v", got["progress"])
	}
}
