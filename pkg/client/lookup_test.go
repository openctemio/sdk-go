package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/lookupjob"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func TestLookupRoundTrip(t *testing.T) {
	var done lookupjob.Result
	var donePath string
	empty := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == protov2.PathPrefix+lookupjob.NextPath:
			if empty {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_, _ = w.Write([]byte(`{"id":"j-1","payload":{"scanner":"ctlog"},"signed_job":{"x":1}}`))
		case r.Method == http.MethodPost:
			donePath = r.URL.EscapedPath()
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &done)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "test-key", MaxRetries: 0})
	j, wait, err := c.NextLookup(context.Background())
	if err != nil || j != nil || wait != 7*time.Second {
		t.Fatalf("204: %v %v %v", j, wait, err)
	}
	empty = false
	j, _, err = c.NextLookup(context.Background())
	if err != nil || j == nil || j.ID != "j-1" || string(j.Payload) != `{"scanner":"ctlog"}` {
		t.Fatalf("job: %+v %v", j, err)
	}
	if err := c.LookupDone(context.Background(), "j/1", lookupjob.Result{Output: json.RawMessage(`{"records":[]}`)}); err != nil {
		t.Fatal(err)
	}
	if donePath != protov2.PathPrefix+lookupjob.JobPath+"j%2F1/done" {
		t.Fatalf("done path %q: the job id is one escaped segment", donePath)
	}
	if string(done.Output) != `{"records":[]}` {
		t.Fatalf("done body %+v", done)
	}
}
