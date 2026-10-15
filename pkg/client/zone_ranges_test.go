package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// A shared job's zone ranges reach the command, from the claim-N poll and
// from the claim answer.
func TestZoneRangesReachTheCommand(t *testing.T) {
	const id = "44444444-4444-4444-8444-444444444444"
	cmd := `{"id":"` + id + `","type":"scan","status":"acknowledged","lease_epoch":1,"payload":{},"zone_ranges":["10.20.0.0/16"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		switch {
		case r.URL.Path == protov2.PathPrefix+protov2.HelloPath:
			_, _ = w.Write([]byte(`{"protocol":2,"features":["commands","capacity"],"media_types":["` + protov2.MediaTypeCTIS + `"]}`))
		case strings.HasSuffix(r.URL.Path, "/claim"):
			_, _ = w.Write([]byte(cmd))
		default:
			_, _ = w.Write([]byte(`{"commands":[` + cmd + `]}`))
		}
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	resp, err := c.GetCommandsLimit(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Commands[0].ZoneRanges; !slices.Equal(got, []string{"10.20.0.0/16"}) {
		t.Fatalf("poll: zone %v", got)
	}
	claimed, err := c.ClaimCommand(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(claimed.ZoneRanges, []string{"10.20.0.0/16"}) {
		t.Fatalf("claim: zone %v", claimed.ZoneRanges)
	}
}
