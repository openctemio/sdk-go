package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

func TestClientSendsUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	sdk := "openctem-sdk-go/" + useragent.SDKVersion()
	status := &core.SensorStatus{Name: "s", Status: core.SensorStateRunning}

	tests := []struct {
		name string
		cli  *Client
		want string
	}{
		{"default", New(&Config{BaseURL: srv.URL, APIKey: "k"}), sdk},
		{"Config.UserAgent", New(&Config{BaseURL: srv.URL, APIKey: "k", UserAgent: "openctemio-sensor/0.3.1"}), "openctemio-sensor/0.3.1 " + sdk},
		{"WithUserAgent", NewWithOptions(WithBaseURL(srv.URL), WithAPIKey("k"), WithUserAgent("ci-runner/2\r\nX: y")), "ci-runner/2 X y " + sdk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cli.SendHeartbeat(context.Background(), status); err != nil {
				t.Fatalf("SendHeartbeat: %v", err)
			}
			if got != tt.want {
				t.Errorf("User-Agent = %q, want %q", got, tt.want)
			}
		})
	}
}
