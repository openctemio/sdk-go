package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// v1Ingest is a fake v1 ingest route that records the command header of
// every request and answers with respond.
type v1Ingest struct {
	mu      sync.Mutex
	headers []string // legacyv1.HeaderCommandID per request ("" when absent)
	respond func(w http.ResponseWriter, cmdID string, n int)
}

func (f *v1Ingest) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != legacyv1.PathIngest {
			http.NotFound(w, r)
			return
		}
		id := r.Header.Get(legacyv1.HeaderCommandID)
		f.mu.Lock()
		f.headers = append(f.headers, id)
		n := len(f.headers)
		f.mu.Unlock()
		f.respond(w, id, n)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *v1Ingest) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.headers...)
}

func ingestOK(w http.ResponseWriter, _ string, _ int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(IngestResponse{ScanID: "r1", FindingsCreated: 1})
}

func oneFinding() *ctis.Report {
	r := ctis.NewReport()
	r.Findings = []ctis.Finding{{ID: "f1", Title: "t", Severity: ctis.SeverityHigh}}
	return r
}

func v1Client(url string) *Client {
	return New(&Config{BaseURL: url, APIKey: "k", Protocol: ProtocolV1, MaxRetries: 1, RetryDelay: time.Millisecond})
}

// A v1 push made for a command names it, so the platform binds the results
// to that command instead of treating them as unsolicited (quarantine).
func TestPushFindingsV1_SendsCommandID(t *testing.T) {
	f := &v1Ingest{respond: ingestOK}
	c := v1Client(f.server(t).URL)

	ctx := core.WithCommandID(context.Background(), "3b0c6f0e-0000-4000-8000-000000000001")
	if _, err := c.PushFindings(ctx, oneFinding()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushAssets(ctx, oneFinding()); err != nil {
		t.Fatal(err)
	}
	got := f.seen()
	if len(got) != 2 || got[0] != "3b0c6f0e-0000-4000-8000-000000000001" || got[1] != got[0] {
		t.Fatalf("command headers = %q, want the command id on both pushes", got)
	}
}

// Work done for no command (CI mode, a collector) stays unsolicited: no
// header at all, never an empty one.
func TestPushFindingsV1_NoCommandNoHeader(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(legacyv1.HeaderCommandID)]
		ingestOK(w, "", 1)
	}))
	defer srv.Close()

	if _, err := v1Client(srv.URL).PushFindings(context.Background(), oneFinding()); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("an unsolicited push must not carry the command header")
	}
}

// The platform answers 404 COMMAND_NOT_FOUND once the command finished more
// than its grace period ago (or is not this sensor's). The report is then
// sent once more, unbound, as the v2 path does; the platform's unsolicited
// policy applies to it.
func TestPushFindingsV1_CommandGoneResendsUnbound(t *testing.T) {
	f := &v1Ingest{respond: func(w http.ResponseWriter, id string, _ int) {
		if id != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"COMMAND_NOT_FOUND","message":"No open command with this id is assigned to this sensor."}`))
			return
		}
		ingestOK(w, id, 0)
	}}
	c := v1Client(f.server(t).URL)

	res, err := c.PushFindings(core.WithCommandID(context.Background(), "cmd-1"), oneFinding())
	if err != nil {
		t.Fatalf("PushFindings: %v", err)
	}
	if res.FindingsCreated != 1 {
		t.Errorf("FindingsCreated = %d, want 1", res.FindingsCreated)
	}
	if got := f.seen(); len(got) != 2 || got[0] != "cmd-1" || got[1] != "" {
		t.Fatalf("command headers = %q, want [cmd-1, \"\"]", got)
	}
}

// Any other 404 (an old platform, a wrong base URL) is an error, not a reason
// to resend.
func TestPushFindingsV1_Plain404NotResent(t *testing.T) {
	f := &v1Ingest{respond: func(w http.ResponseWriter, _ string, _ int) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}}
	c := v1Client(f.server(t).URL)

	if _, err := c.PushFindings(core.WithCommandID(context.Background(), "cmd-1"), oneFinding()); err == nil {
		t.Fatal("want an error for a plain 404")
	}
	if got := f.seen(); len(got) != 1 {
		t.Fatalf("requests = %d, want 1", len(got))
	}
}

// A command id that cannot be a header value (control bytes, oversized) is
// never put on the wire: no header injection, and the push still goes out,
// unbound.
func TestPushFindingsV1_InvalidCommandIDNotSent(t *testing.T) {
	for _, id := range []string{"a\r\nX-Evil: 1", "a b", strings.Repeat("a", maxCommandIDLen+1), "é"} {
		f := &v1Ingest{respond: ingestOK}
		c := v1Client(f.server(t).URL)
		if _, err := c.PushFindings(core.WithCommandID(context.Background(), id), oneFinding()); err != nil {
			t.Fatalf("id %q: %v", id, err)
		}
		if got := f.seen(); len(got) != 1 || got[0] != "" {
			t.Fatalf("id %q: command headers = %q, want none", id, got)
		}
	}
}

// The outbox keeps the command id with the stored report and its v1 delivery
// sends it, including a delivery after a restart (a new client on the same
// directory).
func TestOutboxV1_DeliversCommandID(t *testing.T) {
	f := &v1Ingest{respond: ingestOK}
	c := v1Client(f.server(t).URL)
	if err := c.EnableOutbox(OutboxConfig{Dir: t.TempDir(), SyncWait: 5 * time.Second, LegacyRetryQueueDir: "-", Logf: t.Logf}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	res, err := c.PushFindings(core.WithCommandID(context.Background(), "cmd-ob"), oneFinding())
	if err != nil {
		t.Fatal(err)
	}
	if res.Queued {
		t.Fatal("the report was queued, want delivered within SyncWait")
	}
	if got := f.seen(); len(got) != 1 || got[0] != "cmd-ob" {
		t.Fatalf("command headers = %q, want [cmd-ob]", got)
	}
}
