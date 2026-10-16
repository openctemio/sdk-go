package sensorstate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/sdk-go/pkg/useragent"
)

// The renew request sends the SDK's User-Agent, with the product the
// embedding binary set.
func TestRenewClientSendsUserAgent(t *testing.T) {
	useragent.SetProduct("openctemio-sensor", "0.3.1")
	t.Cleanup(func() { useragent.SetProduct("", "") })

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"api_key":"rda_new","api_prefix":"rda_new"}`))
	}))
	defer srv.Close()

	pc := NewRenewClient(srv.URL, "rda_old")
	if _, err := pc.RenewKey(context.Background()); err != nil {
		t.Fatalf("RenewKey: %v", err)
	}
	want := "openctemio-sensor/0.3.1 openctem-sdk-go/" + useragent.SDKVersion()
	if got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}
