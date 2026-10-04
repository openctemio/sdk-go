package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

func TestClient_SendHeartbeatWithHints(t *testing.T) {
	var gotFeatures []string
	var body string
	srv := httptest.NewServer(v1Only(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != legacyv1.PathHeartbeat {
			t.Errorf("path %s", r.URL.Path)
		}
		gotFeatures = append(gotFeatures, strings.Join(r.Header.Values(legacyv1.HeaderSensorFeatures), ","))
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

	// The plain heartbeat does not announce the doorbell. Every heartbeat
	// in auto mode asks whether the platform offers v2 results.
	if err := c.SendHeartbeat(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	want := []string{"doorbell,results-v2", "doorbell,results-v2", "results-v2"}
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

// A sensor without the doorbell still reads cancel_command_ids, and its
// heartbeat does not announce the doorbell.
func TestClient_SendHeartbeatForCancels(t *testing.T) {
	var gotFeatures []string
	srv := httptest.NewServer(v1Only(func(w http.ResponseWriter, r *http.Request) {
		gotFeatures = append(gotFeatures, strings.Join(r.Header.Values(legacyv1.HeaderSensorFeatures), ","))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_id":"s","status":"ok","actions":["cancel"],"cancel_command_ids":["c1","c2"]}`))
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "k", SensorID: "s"})
	ids, err := c.SendHeartbeatForCancels(context.Background(), &core.SensorStatus{Name: "n", Status: core.SensorStateRunning})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "c1,c2" {
		t.Fatalf("cancel ids %v", ids)
	}
	if len(gotFeatures) != 1 || strings.Contains(gotFeatures[0], legacyv1.FeatureDoorbell) {
		t.Fatalf("features %q: the plain heartbeat must not announce the doorbell", gotFeatures)
	}
}
