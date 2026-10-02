package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/sdk-go/pkg/useragent"
)

// Platform requests used to carry Go's default User-Agent; they now send the
// SDK's, with the product the embedding binary set.
func TestPlatformClientSendsUserAgent(t *testing.T) {
	useragent.SetProduct("openctemio-sensor", "0.3.1")
	t.Cleanup(func() { useragent.SetProduct("", "") })

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"api_key":"rda_new","api_prefix":"rda_new"}`))
	}))
	defer srv.Close()

	pc := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "rda_old", SensorID: "s1"})
	if _, err := pc.RenewKey(context.Background()); err != nil {
		t.Fatalf("RenewKey: %v", err)
	}
	want := "openctemio-sensor/0.3.1 openctem-sdk-go/" + useragent.SDKVersion()
	if got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}
