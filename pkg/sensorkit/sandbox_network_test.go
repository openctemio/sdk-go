package sensorkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// SENSOR_SANDBOX_NETWORK=required on a host that cannot confine a tool's
// network (here: the tool sandbox is off) is refused before the sensor
// pairs: the platform never sees a pairing request from a sensor that would
// then refuse to start.
func TestNewChecksRequiredSandboxNetworkBeforePairing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	clearEnv(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvSandboxNetwork, "required")
	_, err := New(Options{Name: "net-required", Version: "1.0.0", APIURL: srv.URL, Sandbox: "off",
		StateDir: t.TempDir(), Outbox: OutboxSettings{Dir: t.TempDir()}})
	if err == nil || !strings.Contains(err.Error(), EnvSandboxNetwork+"=required") {
		t.Fatalf("want the %s=required refusal, got %v", EnvSandboxNetwork, err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the platform got %d requests before the refusal: pairing must not start", n)
	}
}

func TestValidateSandboxNetwork(t *testing.T) {
	clearEnv(t)
	for _, tc := range []struct {
		net, sandbox string
		wantErr      bool
	}{
		{"", "off", false},
		{"auto", "off", false},
		{"off", "off", false},
		{"required", "off", true},
		{"bogus", "off", true},
	} {
		t.Setenv(EnvSandboxNetwork, tc.net)
		if err := ValidateSandboxNetwork(tc.sandbox); (err != nil) != tc.wantErr {
			t.Fatalf("%s=%q sandbox=%s: err %v, want error %v", EnvSandboxNetwork, tc.net, tc.sandbox, err, tc.wantErr)
		}
	}
}
