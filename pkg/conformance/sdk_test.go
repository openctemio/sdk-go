package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/outbox"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func TestMain(m *testing.M) {
	// The fake listens on 127.0.0.1; the SDK refuses loopback by default.
	httpsec.AllowLoopback = true
	os.Exit(m.Run())
}

func newClient(t *testing.T, f *FakePlatform, protocol string) *client.Client {
	t.Helper()
	c := client.New(&client.Config{
		BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 3, RetryDelay: 5 * time.Millisecond,
		Protocol: protocol, EnableCompression: true,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func report(tool string, assets, findingsPerAsset int) *ctis.Report {
	r := &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{Timestamp: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), SourceType: "scanner"},
		Tool:     &ctis.Tool{Name: tool, Version: "1.0"},
	}
	for a := range assets {
		r.Assets = append(r.Assets, ctis.Asset{ID: fmt.Sprintf("a%d", a), Type: ctis.AssetTypeRepository, Value: fmt.Sprintf("github.com/org/repo%d", a)})
		for i := range findingsPerAsset {
			r.Findings = append(r.Findings, ctis.Finding{
				ID: fmt.Sprintf("f%d-%d", a, i), Type: ctis.FindingTypeVulnerability, Title: "finding",
				Severity: ctis.SeverityMedium, AssetRef: fmt.Sprintf("a%d", a), Fingerprint: fmt.Sprintf("fp-%d-%d", a, i),
				RuleID: strings.Repeat("r", 40),
			})
		}
	}
	return r
}

// --- wire: headers, digest, encoding -------------------------------------

func TestV2_HeadersDigestAndEncoding(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	res, err := c.PushFindings(context.Background(), report("semgrep", 2, 30))
	if err != nil {
		t.Fatal(err)
	}
	if res.ReportID == "" {
		t.Fatal("no report id on a v2 push")
	}
	puts := f.RequestsTo(http.MethodPut, protov2.PathPrefix+"/results/")
	if len(puts) != 1 {
		t.Fatalf("PUTs = %d", len(puts))
	}
	p := puts[0]
	if got := p.Header.Get("Content-Type"); got != protov2.MediaTypeCTIS {
		t.Errorf("Content-Type = %q", got)
	}
	if got := p.Header.Get("Content-Digest"); got != protov2.ContentDigest(p.Body) {
		t.Errorf("Content-Digest %q does not cover the bytes as sent", got)
	}
	if got := p.Header.Get("Content-Encoding"); got != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd for a %d-byte body", got, len(p.Body))
	}
	if !strings.HasPrefix(p.Header.Get("User-Agent"), "") || !strings.Contains(p.Header.Get("User-Agent"), "openctem-sdk-go/") {
		t.Errorf("User-Agent = %q", p.Header.Get("User-Agent"))
	}
	if p.Status != http.StatusAccepted {
		t.Errorf("status %d", p.Status)
	}
	rep := f.Reports()[res.ReportID]
	if rep == nil || !rep.Committed || rep.Status.Accepted.Findings != 60 {
		t.Fatalf("stored = %+v", rep)
	}
	// metadata.id carries the report id.
	if got := rep.Segments[0].report.Metadata.ID; got != res.ReportID {
		t.Errorf("metadata.id = %q, want the report id", got)
	}
}

func TestV2_ReportWithoutToolIsRefusedClientSide(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	r := report("x", 1, 1)
	r.Tool = nil
	if _, err := c.PushResultsV2(context.Background(), r, nil); !errors.Is(err, client.ErrV2NoTool) {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.RequestsTo(http.MethodPut, protov2.PathPrefix)); n != 0 {
		t.Fatalf("%d PUTs for a report v2 cannot accept", n)
	}
}

// --- idempotency -----------------------------------------------------------

func TestV2_ReplayIsANoOpAndReusesReportID(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	r := report("semgrep", 1, 5)
	st1, err := c.PushResultsV2(context.Background(), r, &client.V2PushOptions{ReportID: "01928a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b"})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := c.PushResultsV2(context.Background(), r, &client.V2PushOptions{ReportID: st1.ReportID})
	if err != nil {
		t.Fatal(err)
	}
	puts := f.RequestsTo(http.MethodPut, protov2.PathPrefix)
	if len(puts) != 2 || puts[0].Status != 202 || puts[1].Status != 200 {
		t.Fatalf("statuses = %v", statuses(puts))
	}
	if puts[0].Header.Get("Content-Digest") != puts[1].Header.Get("Content-Digest") {
		t.Fatal("a replay of the same report sent different bytes")
	}
	if st2.ReportID != st1.ReportID || f.AcceptedFindings() != 5 {
		t.Fatalf("replay duplicated: %d findings", f.AcceptedFindings())
	}
}

func statuses(rs []Request) []int {
	out := make([]int, len(rs))
	for i, r := range rs {
		out[i] = r.Status
	}
	return out
}

// --- §3.8 retry table --------------------------------------------------------

func TestV2_RetriesOnlyWhatTheRFCSays(t *testing.T) {
	cases := []struct {
		status  int
		problem protov2.ProblemType
		retry   bool
	}{
		{400, protov2.ProblemDigestMismatch, false},
		{401, protov2.ProblemUnauthenticated, false},
		{404, protov2.ProblemReportNotFound, false},
		{409, protov2.ProblemReportCommitted, false},
		{415, protov2.ProblemUnsupportedMediaType, false},
		{422, protov2.ProblemSchemaInvalid, false},
		{429, protov2.ProblemRateLimited, true},
		{500, protov2.ProblemInternal, true},
		{502, "", true},
		{503, protov2.ProblemUnavailable, true},
		{504, "", true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d", tc.status), func(t *testing.T) {
			f := NewFakePlatform(true)
			defer f.Close()
			var hits atomic.Int32
			f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
				if r.Method == http.MethodPut && hits.Add(1) == 1 {
					return &FaultAnswer{Status: tc.status, Problem: tc.problem, RetryAfter: "0"}
				}
				return nil
			})
			c := newClient(t, f, client.ProtocolV2)
			_, err := c.PushFindings(context.Background(), report("semgrep", 1, 1))
			puts := f.RequestsTo(http.MethodPut, protov2.PathPrefix)
			if tc.retry {
				if err != nil || len(puts) != 2 {
					t.Fatalf("retryable %d: err=%v puts=%d", tc.status, err, len(puts))
				}
				if puts[0].Path != puts[1].Path {
					t.Fatalf("retry used another report id: %s then %s", puts[0].Path, puts[1].Path)
				}
				return
			}
			if err == nil || len(puts) != 1 {
				t.Fatalf("non-retryable %d: err=%v puts=%d", tc.status, err, len(puts))
			}
		})
	}
}

func TestV2_SplitsOn413(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		// Anything carrying more than 10 findings is "too large".
		if r.Method == http.MethodPut {
			raw, _ := decodeBody(r.Header.Get("Content-Encoding"), mustRead(r))
			var rep ctis.Report
			_ = json.Unmarshal(raw, &rep)
			if len(rep.Findings) > 10 {
				return &FaultAnswer{Status: 413, Problem: protov2.ProblemReportTooLarge}
			}
		}
		return nil
	})
	c := newClient(t, f, client.ProtocolV2)
	st, err := c.PushResultsV2(context.Background(), report("semgrep", 4, 10), nil)
	if err != nil {
		t.Fatal(err)
	}
	rep := f.Reports()[st.ReportID]
	if rep == nil || !rep.Committed || len(rep.Segments) < 4 || rep.Status.Accepted.Findings != 40 {
		t.Fatalf("after 413: %+v", rep)
	}
	if f.AcceptedFindings() != 40 {
		t.Fatalf("accepted %d findings, want 40", f.AcceptedFindings())
	}
}

func mustRead(r *http.Request) []byte {
	b := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(b)
	return b
}

func TestV2_SegmentsAndCommit(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	st, err := c.PushResultsV2(context.Background(), report("semgrep", 3, 7), &client.V2PushOptions{MaxFindingsPerSegment: 5})
	if err != nil {
		t.Fatal(err)
	}
	rep := f.Reports()[st.ReportID]
	if rep == nil || len(rep.Segments) < 5 || !rep.Committed {
		t.Fatalf("segments: %+v", rep)
	}
	if rep.Status.Rejected.Findings != 0 || rep.Status.Accepted.Findings != 21 {
		t.Fatalf("a finding lost its asset in a segment: %+v", rep.Status)
	}
	commits := f.RequestsTo(http.MethodPost, protov2.PathPrefix)
	if len(commits) != 1 || !strings.HasSuffix(commits[0].Path, "/commit") {
		t.Fatalf("commits: %+v", commits)
	}
}

func TestV2_ResumesAfterALostSegmentResponse(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	var n atomic.Int32
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/segments/1") && n.Add(1) == 1 {
			return &FaultAnswer{Drop: true, Process: true} // processed, answer lost
		}
		return nil
	})
	c := newClient(t, f, client.ProtocolV2)
	var prog client.V2Progress
	opts := &client.V2PushOptions{MaxFindingsPerSegment: 2, OnProgress: func(p client.V2Progress) error { prog = p; return nil }}
	_, err := c.PushResultsV2(context.Background(), report("semgrep", 1, 6), opts)
	if err == nil {
		t.Fatal("expected the lost response to surface")
	}
	opts.Progress = &prog
	st, err := c.PushResultsV2(context.Background(), report("semgrep", 1, 6), opts)
	if err != nil {
		t.Fatal(err)
	}
	segPuts := f.RequestsTo(http.MethodPut, protov2.PathPrefix)
	// seg0 once (acknowledged, not resent), seg1 twice (lost answer, replay 200), seg2 once.
	if len(segPuts) != 4 {
		t.Fatalf("segment PUTs = %d (%v)", len(segPuts), statuses(segPuts))
	}
	if f.AcceptedFindings() != 6 || st.State != protov2.StateCompleted {
		t.Fatalf("accepted %d, state %s", f.AcceptedFindings(), st.State)
	}
}

func TestV2_PartiallyAcceptedReportIsNotResent(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	r := report("semgrep", 2, 2)
	r.Findings = append(r.Findings, ctis.Finding{ID: "orphan", Title: "no asset", Severity: ctis.SeverityLow, Type: ctis.FindingTypeVulnerability})
	res, err := c.PushFindings(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	rep := f.Reports()[res.ReportID]
	if rep.Status.Rejected.Findings != 1 || rep.Status.Accepted.Findings != 4 {
		t.Fatalf("status = %+v", rep.Status)
	}
	if n := len(f.RequestsTo(http.MethodPut, protov2.PathPrefix)); n != 1 {
		t.Fatalf("partially accepted report sent %d times", n)
	}
}

// --- protocol selection ----------------------------------------------------

func TestAuto_FallsBackToV1OnAnOldPlatform(t *testing.T) {
	f := NewFakePlatform(false)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	if err := c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "s", Status: core.SensorStateRunning}); err != nil {
		t.Fatal(err)
	}
	res, err := c.PushFindings(context.Background(), report("semgrep", 1, 3))
	if err != nil || res.FindingsCreated != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(f.V1Reports()) != 1 || len(f.Reports()) != 0 {
		t.Fatal("not delivered over v1")
	}
	if p, _ := c.ResultsProtocol(context.Background()); p != client.ProtocolV1 {
		t.Fatalf("protocol = %s", p)
	}
}

func TestAuto_UsesV2WhenAdvertised(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	if err := c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "s", Status: core.SensorStateRunning}); err != nil {
		t.Fatal(err)
	}
	hb := f.RequestsTo(http.MethodPost, "/api/v1/agent/heartbeat")
	if !protov2HasFeature(hb[0].Header.Values("X-OpenCTEM-Sensor-Features"), protov2.FeatureResultsV2) {
		t.Fatal("heartbeat did not ask about v2")
	}
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if len(f.Reports()) != 1 || len(f.V1Reports()) != 0 {
		t.Fatal("not delivered over v2")
	}
}

func TestV1Mode_NeverTouchesV2(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV1)
	_ = c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "s"})
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if n := len(f.RequestsTo("", protov2.PathPrefix)); n != 0 {
		t.Fatalf("%d v2 requests in v1 mode", n)
	}
	if v := f.RequestsTo("", "/api/v1/agent/heartbeat")[0].Header.Values("X-OpenCTEM-Sensor-Features"); len(v) != 0 {
		t.Fatalf("v1 mode announced features %v", v)
	}
}

func TestV2Forced_FailsAgainstAnOldPlatform(t *testing.T) {
	f := NewFakePlatform(false)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 1)); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("err = %v", err)
	}
}

// --- outbox ---------------------------------------------------------------

func enableOutbox(t *testing.T, c *client.Client, dir string) {
	t.Helper()
	if err := c.EnableOutbox(client.OutboxConfig{
		Dir: dir, SyncWait: 2 * time.Second, LegacyRetryQueueDir: "-",
		Logf: func(format string, args ...any) { t.Logf("[outbox] "+format, args...) },
	}); err != nil {
		t.Fatal(err)
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOutbox_PlatformDownQueuesThenDrainsInOrderOnHeartbeat(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	var down atomic.Bool
	down.Store(true)
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if down.Load() {
			return &FaultAnswer{Drop: true}
		}
		return nil
	})
	c := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c, t.TempDir())
	var ids []string
	for i := range 3 {
		res, err := c.PushFindings(context.Background(), report("semgrep", 1, i+1))
		if err != nil || !res.Queued {
			t.Fatalf("push %d: res=%+v err=%v", i, res, err)
		}
		ids = append(ids, res.ReportID)
	}
	if st, _ := c.OutboxStats(); st.PendingCount != 3 {
		t.Fatalf("pending = %d", st.PendingCount)
	}
	down.Store(false)
	if err := c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "s"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { st, _ := c.OutboxStats(); return st.PendingCount == 0 })
	var order []string
	for _, p := range f.RequestsTo(http.MethodPut, protov2.PathPrefix) {
		if p.Status == http.StatusAccepted {
			order = append(order, p.Path[strings.LastIndex(p.Path, "/")+1:])
		}
	}
	if strings.Join(order, ",") != strings.Join(ids, ",") {
		t.Fatalf("drain order %v, want %v", order, ids)
	}
	if f.AcceptedFindings() != 6 {
		t.Fatalf("accepted %d findings", f.AcceptedFindings())
	}
	if len(f.HeartbeatOutbox()) == 0 {
		t.Fatal("heartbeat carried no outbox state")
	}
}

func TestOutbox_RestartReplaysWithoutDuplicates(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	// The first PUT is processed but its answer is lost; then the process
	// "dies" before it learns the outcome.
	var n atomic.Int32
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.Method == http.MethodPut && n.Add(1) == 1 {
			return &FaultAnswer{Drop: true, Process: true}
		}
		return nil
	})
	dir := t.TempDir()
	c := newClient(t, f, client.ProtocolV2)
	if err := c.EnableOutbox(client.OutboxConfig{Dir: dir, SyncWait: -1, LegacyRetryQueueDir: "-"}); err != nil {
		t.Fatal(err)
	}
	res, err := c.PushFindings(context.Background(), report("semgrep", 1, 4))
	if err != nil || !res.Queued {
		t.Fatalf("%+v %v", res, err)
	}
	waitUntil(t, 5*time.Second, func() bool { return n.Load() >= 1 })
	_ = c.Close() // the "crash": the item is still on disk

	c2 := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c2, dir)
	if err := c2.FlushOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { st, _ := c2.OutboxStats(); return st.PendingCount == 0 })
	puts := f.RequestsTo(http.MethodPut, protov2.PathPrefix)
	if len(puts) < 2 || puts[len(puts)-1].Status != http.StatusOK {
		t.Fatalf("replay statuses = %v, want the last one 200 (server-side no-op)", statuses(puts))
	}
	if len(f.Reports()) != 1 || f.AcceptedFindings() != 4 {
		t.Fatalf("reports=%d findings=%d", len(f.Reports()), f.AcceptedFindings())
	}
}

func TestOutbox_PoisonGoesToDeadLetterWhileOthersFlow(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.Tools = []string{"semgrep"} // anything else is 422 tool-not-permitted
	c := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c, t.TempDir())
	_, err := c.PushFindings(context.Background(), report("undeclared-tool", 1, 1))
	var refused *client.RefusedError
	if !errors.As(err, &refused) || refused.DeadLetter.Status != 422 {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 2)); err != nil {
		t.Fatal(err)
	}
	st, _ := c.OutboxStats()
	if st.DeadLetterCount != 1 || st.PendingCount != 0 || f.AcceptedFindings() != 2 {
		t.Fatalf("stats=%+v accepted=%d", st, f.AcceptedFindings())
	}
}

func TestOutbox_401PausesThenResumesAfterKeyRotation(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c, t.TempDir())
	_, _ = c.ResultsProtocol(context.Background()) // decide v2 while the key works
	f.SetAPIKey("rda_rotated")                     // the platform rotated the key
	res, err := c.PushFindings(context.Background(), report("semgrep", 1, 2))
	if err != nil || !res.Queued {
		t.Fatalf("%+v %v", res, err)
	}
	waitUntil(t, 5*time.Second, func() bool { st, _ := c.OutboxStats(); return st.AuthPaused })
	before := len(f.Requests())
	time.Sleep(200 * time.Millisecond)
	if len(f.Requests()) != before {
		t.Fatal("kept sending while the key is rejected")
	}
	c.SetAPIKey("rda_rotated")
	waitUntil(t, 5*time.Second, func() bool { st, _ := c.OutboxStats(); return st.PendingCount == 0 })
	if f.AcceptedFindings() != 2 {
		t.Fatalf("accepted %d", f.AcceptedFindings())
	}
	if st, _ := c.OutboxStats(); st.DeadLetterCount != 0 {
		t.Fatal("a 401 was dead-lettered")
	}
}

func TestOutbox_CommandCompletesOnlyAfterItsResults(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.OpenCommand("0192a3b4-0000-7000-8000-000000000001")
	var hold atomic.Bool
	hold.Store(true)
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if hold.Load() && r.Method == http.MethodPut {
			return &FaultAnswer{Status: 503, Problem: protov2.ProblemUnavailable, RetryAfter: "0"}
		}
		return nil
	})
	c := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c, t.TempDir())
	cmd := "0192a3b4-0000-7000-8000-000000000001"
	ctx := core.WithCommandID(context.Background(), cmd)
	res, err := c.PushFindings(ctx, report("semgrep", 1, 1))
	if err != nil || !res.Queued {
		t.Fatalf("%+v %v", res, err)
	}
	if err := c.ReportCommandResult(ctx, cmd, &core.CommandResult{Status: "completed", FindingsCount: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if state, _ := f.CommandState(cmd); state != "running" {
		t.Fatalf("command %s before its results were accepted", state)
	}
	hold.Store(false)
	c.Outbox().Wake()
	waitUntil(t, 5*time.Second, func() bool { s, _ := f.CommandState(cmd); return s == "completed" })
	for _, p := range f.RequestsTo(http.MethodPut, protov2.PathPrefix) {
		if !strings.Contains(p.Path, "/commands/"+cmd+"/") {
			t.Fatalf("result not bound to its command: %s", p.Path)
		}
	}
}

func TestOutbox_RefusedResultsFailTheCommand(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	f.Tools = []string{"semgrep"}
	cmd := "0192a3b4-0000-7000-8000-000000000002"
	f.OpenCommand(cmd)
	c := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c, t.TempDir())
	ctx := core.WithCommandID(context.Background(), cmd)
	if _, err := c.PushFindings(ctx, report("not-declared", 1, 1)); err == nil {
		t.Fatal("expected a refusal")
	}
	// The executor would still report "completed" if it ignored the error.
	if err := c.ReportCommandResult(ctx, cmd, &core.CommandResult{Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, func() bool { s, _ := f.CommandState(cmd); return s != "running" })
	state, msg := f.CommandState(cmd)
	if state != "failed" || !strings.Contains(msg, "refused") {
		t.Fatalf("command %s (%q)", state, msg)
	}
}

func TestOutbox_GoneCommandSendsResultsUnsolicited(t *testing.T) {
	f := NewFakePlatform(true)
	defer f.Close()
	c := newClient(t, f, client.ProtocolV2)
	enableOutbox(t, c, t.TempDir())
	// The command expired while the sensor was offline: never opened here.
	ctx := core.WithCommandID(context.Background(), "0192a3b4-0000-7000-8000-000000000003")
	if _, err := c.PushFindings(ctx, report("semgrep", 1, 2)); err != nil {
		t.Fatal(err)
	}
	if f.AcceptedFindings() != 2 {
		t.Fatalf("results of a gone command lost: %d", f.AcceptedFindings())
	}
}

func TestOutbox_V1PlatformGetsTheQueueOverV1(t *testing.T) {
	f := NewFakePlatform(false)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	enableOutbox(t, c, t.TempDir())
	if _, err := c.PushFindings(context.Background(), report("semgrep", 1, 3)); err != nil {
		t.Fatal(err)
	}
	if len(f.V1Reports()) != 1 {
		t.Fatal("not delivered over v1")
	}
}

var _ = outbox.KindReport
