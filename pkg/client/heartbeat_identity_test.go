package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// The heartbeat must carry the sensor's version and hostname; they were
// declared on HeartbeatRequest but never set, so every sensor showed
// "No host info" on the platform.
func TestHeartbeatSendsVersionAndHostname(t *testing.T) {
	var got HeartbeatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := New(&Config{BaseURL: srv.URL, APIKey: "k", Timeout: 5e9, MaxRetries: 1})
	c.httpClient = srv.Client()
	err := c.SendHeartbeat(context.Background(), &core.SensorStatus{
		Name: "s1", Status: core.SensorStateRunning, Version: "0.4.2", Hostname: "scanner-01",
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if got.Version != "0.4.2" || got.Hostname != "scanner-01" {
		t.Fatalf("heartbeat version/hostname = %q/%q, want 0.4.2/scanner-01", got.Version, got.Hostname)
	}
}

func TestBaseSensorStatusCarriesVersionAndHostname(t *testing.T) {
	s := core.NewBaseSensor(&core.BaseSensorConfig{Name: "s1", Version: "0.4.2"}, nil)
	st := s.Status()
	if st.Version != "0.4.2" || st.Hostname == "" {
		t.Fatalf("status version/hostname = %q/%q", st.Version, st.Hostname)
	}
}
