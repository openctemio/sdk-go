package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

const ledgerTenant = "aaaaaaaa-0000-4000-8000-0000000000aa"

func ledgerClient(t *testing.T) (*Client, *core.JobLedger) {
	t.Helper()
	// Nothing listens there: items stay in the outbox, where the test reads them.
	c := New(&Config{BaseURL: "http://127.0.0.1:1", APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	if err := c.EnableOutbox(OutboxConfig{Dir: t.TempDir(), SyncWait: -1, LegacyRetryQueueDir: "-"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	l := core.NewJobLedger()
	c.SetJobLedger(l)
	return c, l
}

// SECURITY: a shared sensor's client stores nothing for a job it does not
// hold, and tags everything of a held job with the job's organization.
func TestJobLedgerGatesAndTagsResults(t *testing.T) {
	c, l := ledgerClient(t)
	ctx := context.Background()
	report := ctis.NewReport()

	if _, err := c.PushFindings(ctx, report); !errors.Is(err, core.ErrJobNotHeld) {
		t.Fatalf("unsolicited push: %v", err)
	}
	if _, err := c.PushFindings(core.WithCommandID(ctx, "c-other"), report); !errors.Is(err, core.ErrJobNotHeld) {
		t.Fatalf("report for a job not held: %v", err)
	}
	if err := c.ReportCommandResult(ctx, "c-other", &core.CommandResult{Status: "completed"}); !errors.Is(err, core.ErrJobNotHeld) {
		t.Fatalf("result for a job not held: %v", err)
	}
	if err := c.QueueCommandLogs(ctx, "c-other", protov2.CommandLogsRequest{Lines: []protov2.CommandLogLine{{Msg: "x"}}}); !errors.Is(err, core.ErrJobNotHeld) {
		t.Fatalf("logs for a job not held: %v", err)
	}
	if n := len(c.Outbox().Pending()); n != 0 {
		t.Fatalf("%d items stored for jobs not held", n)
	}

	l.Hold("c1", ledgerTenant)
	if _, err := c.PushFindings(core.WithCommandID(ctx, "c1"), report); err != nil {
		t.Fatalf("report of a held job: %v", err)
	}
	if err := c.ReportCommandResult(ctx, "c1", &core.CommandResult{Status: "completed"}); err != nil {
		t.Fatalf("result of a held job: %v", err)
	}
	pending := c.Outbox().Pending()
	if len(pending) != 2 {
		t.Fatalf("pending %+v", pending)
	}
	for _, m := range pending {
		if m.CommandID != "c1" || m.TenantID != ledgerTenant {
			t.Fatalf("item %+v not tagged with the job and its organization", m)
		}
	}
}
