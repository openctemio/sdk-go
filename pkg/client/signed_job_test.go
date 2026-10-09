package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// The job signature binds the payload's bytes as the response carried
// them: the client must hand the poller exactly those bytes, and the signed
// job, from the claim-N poll and from the claim answer.
func TestSignedJobAndRawPayloadReachTheCommand(t *testing.T) {
	const id = "33333333-3333-4333-8333-333333333333"
	const env = `{"payloadType":"application/vnd.openctem.job.v1+json","payload":"e30=","signatures":[]}`
	payloads := []string{`{"targets":["b", "a"],"scanner":"nuclei"}`, `null`}
	for _, payload := range payloads {
		cmd := `{"id":"` + id + `","type":"scan","status":"acknowledged","lease_epoch":3,"payload":` + payload + `,"signed_job":` + env + `}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", protov2.MediaTypeJSON)
			w.Header().Set(protov2.HeaderProtocol, "2")
			switch {
			case r.URL.Path == protov2.PathPrefix+protov2.HelloPath:
				_, _ = w.Write([]byte(`{"protocol":2,"features":["commands","capacity","signed_jobs"],"media_types":["` + protov2.MediaTypeCTIS + `"]}`))
			case strings.HasSuffix(r.URL.Path, "/claim"):
				_, _ = w.Write([]byte(cmd))
			default:
				_, _ = w.Write([]byte(`{"commands":[` + cmd + `]}`))
			}
		}))
		c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
		resp, err := c.GetCommandsLimit(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		got := resp.Commands[0]
		if string(got.Payload) != payload || string(got.SignedJob) != env || got.LeaseEpoch != 3 {
			t.Fatalf("poll: payload %q signed_job %q epoch %d", got.Payload, got.SignedJob, got.LeaseEpoch)
		}
		claimed, err := c.ClaimCommand(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if string(claimed.Payload) != payload || string(claimed.SignedJob) != env || claimed.LeaseEpoch != 3 {
			t.Fatalf("claim: payload %q signed_job %q epoch %d", claimed.Payload, claimed.SignedJob, claimed.LeaseEpoch)
		}
		if jobsig.PayloadDigest(claimed.Payload) != jobsig.PayloadDigest([]byte(payload)) {
			t.Fatal("digest of the received payload differs")
		}
		h, err := c.Hello(context.Background())
		if err != nil || !h.Supports(protov2.FeatureSignedJobs) {
			t.Fatalf("hello: %v %+v", err, h)
		}
		srv.Close()
	}
}
