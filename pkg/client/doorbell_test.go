package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

func TestClient_SendHeartbeatWithHints(t *testing.T) {
	var gotFeatures []string
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != legacyv1.PathHeartbeat {
			t.Errorf("path %s", r.URL.Path)
		}
		gotFeatures = append(gotFeatures, r.Header.Get(legacyv1.HeaderSensorFeatures))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "k", SensorID: "s"})
	status := &core.SensorStatus{Name: "n", Status: core.SensorStateRunning}

	body = `{"agent_id":"s","status":"ok","pending_jobs":2,"next_heartbeat_seconds":5,"actions":["rotate_key"],"config_version":"0123456789abcdef"}`
	h, err := c.SendHeartbeatWithHints(context.Background(), status)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Present || h.PendingJobs != 2 || h.NextHeartbeat != 5*time.Second ||
		len(h.Actions) != 1 || h.Actions[0] != core.HeartbeatActionRotateKey || h.ConfigVersion != "0123456789abcdef" {
		t.Fatalf("hints %+v", *h)
	}

	// A server without the doorbell: no hints.
	body = `{"agent_id":"s","status":"ok","tenant_id":"t"}`
	h, err = c.SendHeartbeatWithHints(context.Background(), status)
	if err != nil || h.Present {
		t.Fatalf("v1 server: hints %+v err %v", h, err)
	}

	// The plain heartbeat does not announce the doorbell.
	if err := c.SendHeartbeat(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	want := []string{legacyv1.FeatureDoorbell, legacyv1.FeatureDoorbell, ""}
	for i := range want {
		if gotFeatures[i] != want[i] {
			t.Errorf("request %d: %s=%q, want %q", i, legacyv1.HeaderSensorFeatures, gotFeatures[i], want[i])
		}
	}
}

func TestClient_SendHeartbeatWithHints_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	if _, err := c.SendHeartbeatWithHints(context.Background(), &core.SensorStatus{}); !IsAuthenticationError(err) {
		t.Fatalf("want 401 error, got %v", err)
	}
}
