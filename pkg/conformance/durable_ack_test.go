package conformance

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// Durable acknowledgement (research/467 D0): a 202 is the platform taking a
// report, not processing it. The outbox keeps the report until the status
// resource is final.

func asyncOutbox(t *testing.T, c *client.Client, dir string) {
	t.Helper()
	if err := c.EnableOutbox(client.OutboxConfig{
		Dir: dir, SyncWait: 2 * time.Second, LegacyRetryQueueDir: "-", ReportStatusPoll: 20 * time.Millisecond,
		Logf: func(format string, args ...any) { t.Logf("[outbox] "+format, args...) },
	}); err != nil {
		t.Fatal(err)
	}
}

func onlyReportID(t *testing.T, f *FakePlatform) string {
	t.Helper()
	reps := f.Reports()
	if len(reps) != 1 {
		t.Fatalf("platform holds %d reports, want 1", len(reps))
	}
	for id := range reps {
		return id
	}
	return ""
}

func pending(c *client.Client) int {
	st, _ := c.OutboxStats()
	return st.PendingCount
}

// Accepted then completed: kept while queued, deleted once completed.
func TestDurableAck_KeptUntilCompleted(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.AsyncIngest = true
	c := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c, t.TempDir())
	res, err := c.PushFindings(context.Background(), report("semgrep", 1, 13))
	if err != nil || !res.Success {
		t.Fatalf("%+v %v", res, err)
	}
	id := onlyReportID(t, f)
	time.Sleep(150 * time.Millisecond) // several status reads while queued
	if pending(c) != 1 {
		t.Fatal("the report left the outbox on the 202, before the platform processed it")
	}
	reads := 0
	for _, r := range f.RequestsTo(http.MethodGet, "") {
		if strings.Contains(r.Path, id) {
			reads++
		}
	}
	if reads == 0 {
		t.Fatal("the status of the accepted report was never read")
	}
	f.SetReportState(id, protov2.StateCompleted)
	waitUntil(t, 5*time.Second, func() bool { return pending(c) == 0 })
}

// Failed: the same report id is sent again with the same bytes (an
// identical replay the platform re-queues), then completed.
func TestDurableAck_FailedIsReSentIdentically(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.AsyncIngest = true
	c := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c, t.TempDir())
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 3)); err != nil {
		t.Fatal(err)
	}
	id := onlyReportID(t, f)
	f.SetReportState(id, protov2.StateFailed)
	waitUntil(t, 5*time.Second, func() bool { return f.ReportReplays(id) >= 1 })
	if pending(c) != 1 {
		t.Fatal("the re-sent report left the outbox")
	}
	if got := onlyReportID(t, f); got != id {
		t.Fatalf("re-sent under %s, want the same id %s", got, id)
	}
	for _, r := range f.RequestsTo(http.MethodPut, protov2.PathPrefix) {
		if r.Status == http.StatusConflict {
			t.Fatal("the re-send was not byte-identical (409 conflict)")
		}
	}
	f.SetReportState(id, protov2.StateCompleted)
	waitUntil(t, 5*time.Second, func() bool { return pending(c) == 0 })
}

// Failed every time: capped, then kept as a dead letter (never deleted).
func TestDurableAck_FailedPastTheCapIsKept(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.AsyncIngest = true
	c := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c, t.TempDir())
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 3)); err != nil {
		t.Fatal(err)
	}
	id := onlyReportID(t, f)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				f.SetReportState(id, protov2.StateFailed)
			}
		}
	}()
	waitUntil(t, 20*time.Second, func() bool { st, _ := c.OutboxStats(); return st.DeadLetterCount == 1 })
	if n := f.ReportReplays(id); n != 5 {
		t.Fatalf("re-sent %d times, want 5", n)
	}
	if pending(c) != 0 {
		t.Fatal("still pending after the cap")
	}
}

// Expired: kept as a dead letter, never silently deleted.
func TestDurableAck_ExpiredIsKept(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.AsyncIngest = true
	c := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c, t.TempDir())
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 3)); err != nil {
		t.Fatal(err)
	}
	f.SetReportState(onlyReportID(t, f), protov2.StateExpired)
	waitUntil(t, 5*time.Second, func() bool { st, _ := c.OutboxStats(); return st.DeadLetterCount == 1 })
}

// The platform lost a report it accepted: sent again under the same id.
func TestDurableAck_LostReportIsReSent(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.AsyncIngest = true
	c := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c, t.TempDir())
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 3)); err != nil {
		t.Fatal(err)
	}
	id := onlyReportID(t, f)
	f.ForgetReport(id)
	waitUntil(t, 5*time.Second, func() bool { return len(f.Reports()) == 1 })
	if got := onlyReportID(t, f); got != id {
		t.Fatalf("re-sent under %s, want %s", got, id)
	}
	f.SetReportState(id, protov2.StateCompleted)
	waitUntil(t, 5*time.Second, func() bool { return pending(c) == 0 })
}

// A restart between the 202 and the final status keeps the report and
// resumes reading its status (it is not sent again).
func TestDurableAck_RestartKeepsAcceptedReport(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.AsyncIngest = true
	dir := t.TempDir()
	c := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c, dir)
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 3)); err != nil {
		t.Fatal(err)
	}
	id := onlyReportID(t, f)
	_ = c.Close()
	puts := len(f.RequestsTo(http.MethodPut, protov2.PathPrefix))

	c2 := newClient(t, f, client.ProtocolV2)
	asyncOutbox(t, c2, dir)
	if pending(c2) != 1 {
		t.Fatal("the accepted report did not survive the restart")
	}
	f.SetReportState(id, protov2.StateCompleted)
	waitUntil(t, 5*time.Second, func() bool { return pending(c2) == 0 })
	if got := len(f.RequestsTo(http.MethodPut, protov2.PathPrefix)); got != puts {
		t.Fatalf("PUTs %d -> %d: an accepted report was sent again after the restart", puts, got)
	}
}
