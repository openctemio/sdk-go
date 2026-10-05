package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func TestClient_SendHeartbeatWithHints(t *testing.T) {
	var body string
	srv := v2Platform(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protov2.PathPrefix+protov2.HeartbeatPath {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	c := New(&Config{BaseURL: srv.URL, APIKey: "k", SensorID: "s"})
	status := &core.SensorStatus{Name: "n", Status: core.SensorStateRunning}

	body = `{"sensor_id":"s","status":"ok","pending_jobs":2,"next_heartbeat_seconds":5,"actions":["rotate_key"],"config_version":"0123456789abcdef"}`
	h, err := c.SendHeartbeatWithHints(context.Background(), status)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Present || h.PendingJobs != 2 || h.NextHeartbeat != 5*time.Second ||
		len(h.Actions) != 1 || h.Actions[0] != core.HeartbeatActionRotateKey || h.ConfigVersion != "0123456789abcdef" {
		t.Fatalf("hints %+v", *h)
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

// SendHeartbeatForCancels reads cancel_command_ids.
func TestClient_SendHeartbeatForCancels(t *testing.T) {
	srv := v2Platform(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sensor_id":"s","status":"ok","actions":["cancel"],"cancel_command_ids":["c1","c2"]}`))
	})
	c := New(&Config{BaseURL: srv.URL, APIKey: "k", SensorID: "s"})
	ids, err := c.SendHeartbeatForCancels(context.Background(), &core.SensorStatus{Name: "n", Status: core.SensorStateRunning})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "c1,c2" {
		t.Fatalf("cancel ids %v", ids)
	}
}
