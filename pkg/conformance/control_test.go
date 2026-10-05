package conformance

// api RFC-029: the SDK speaks protocol v2 for the whole sensor surface, never
// sends X-Agent-ID, and never falls back to the retired protocol v1: a
// platform that does not serve a v2 route answers client.ErrV2Unsupported.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/platform"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func newControlFake(t *testing.T) *FakePlatform {
	t.Helper()
	f := NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	return f
}

func status() *core.SensorStatus {
	return &core.SensorStatus{Name: "conformance", Status: core.SensorStateRunning, Version: "0.5.0", Hostname: "h"}
}

// Every call of a sensor's life on a full v2 platform: only /api/v2/sensor,
// and no X-Agent-ID anywhere even with a sensor id configured.
func TestControl_EverythingOnV2WithoutAgentHeader(t *testing.T) {
	f := newControlFake(t)
	f.QueueCommand("0192a3b4-0000-7000-8000-000000000001")
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, SensorID: "sensor-1", MaxRetries: 2})
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	hints, err := c.SendHeartbeatWithHints(ctx, status())
	if err != nil || !hints.Present || hints.PendingJobs != 1 || hints.NextHeartbeat == 0 {
		t.Fatalf("heartbeat: %+v %v", hints, err)
	}
	resp, err := c.GetCommands(ctx)
	if err != nil || len(resp.Commands) != 1 {
		t.Fatalf("poll: %+v %v", resp, err)
	}
	id := resp.Commands[0].ID
	if err := c.AcknowledgeCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.StartCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportCommandResult(ctx, id, &core.CommandResult{Status: "completed", FindingsCount: 2}); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.CommandState(id); st != "completed" {
		t.Fatalf("command state %q", st)
	}
	rules, err := c.GetSuppressions(ctx)
	if err != nil || len(rules) != 1 {
		t.Fatalf("suppressions %v %v", rules, err)
	}
	if res, err := c.CheckFingerprints(ctx, []string{"a", "b"}); err != nil || len(res.Missing) != 2 {
		t.Fatalf("check %+v %v", res, err)
	}
	if nw, err := c.BaselineDiff(ctx, "github.com/o/r", "main", []string{"a"}); err != nil || len(nw) != 1 {
		t.Fatalf("baseline %v %v", nw, err)
	}
	if _, err := c.PushFindings(ctx, report("semgrep", 1, 2)); err != nil {
		t.Fatal(err)
	}
	pc := platform.NewPlatformClient(&platform.ClientConfig{BaseURL: f.URL(), APIKey: f.APIKey, SensorID: "sensor-1"})
	if k, err := pc.RenewKey(ctx); err != nil || !strings.HasPrefix(k.APIKey, "rda_rotated_") {
		t.Fatalf("renew %+v %v", k, err)
	}

	for _, r := range f.Requests() {
		if !strings.HasPrefix(r.Path, protov2.PathPrefix+"/") {
			t.Errorf("%s %s: not a protocol v2 path", r.Method, r.Path)
		}
		if r.Header.Get("X-Agent-ID") != "" {
			t.Errorf("%s %s carries X-Agent-ID", r.Method, r.Path)
		}
		if r.Header.Get(protov2.HeaderSensorFeatures) != "" {
			t.Errorf("%s %s carries %s", r.Method, r.Path, protov2.HeaderSensorFeatures)
		}
	}
	if got := c.ProtocolFeatures(); len(got) != 6 {
		t.Errorf("negotiated features %v", got)
	}
	if n := len(f.RequestsTo(http.MethodGet, protov2.PathPrefix+protov2.HelloPath)); n != 1 {
		t.Errorf("hello asked %d times, want once (cached)", n)
	}
}

// A platform that serves only v2 results (api v0.8): the control plane is
// ErrV2Unsupported; nothing goes to the retired protocol v1.
func TestControl_ResultsOnlyPlatformIsUnsupported(t *testing.T) {
	f := NewFakePlatform(true)
	f.SetControl(false)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	if err := c.SendHeartbeat(ctx, status()); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("heartbeat: %v, want ErrV2Unsupported", err)
	}
	if _, err := c.PushFindings(ctx, report("semgrep", 1, 1)); err != nil {
		t.Fatal(err)
	}
	assertNoV1(t, f)
}

// A platform without protocol v2: every call is ErrV2Unsupported, and no
// request goes to /api/v1/agent.
func TestControl_OldPlatformIsUnsupported(t *testing.T) {
	f := NewFakePlatform(false)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	if err := c.SendHeartbeat(ctx, status()); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, err := c.GetSuppressions(ctx); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("suppressions: %v", err)
	}
	if _, err := c.PushFindings(ctx, report("semgrep", 1, 1)); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("push: %v", err)
	}
	if err := c.AcknowledgeCommand(ctx, "cmd-1"); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("claim: %v", err)
	}
	assertNoV1(t, f)
}

// assertNoV1 fails when any request went to the retired protocol v1.
func assertNoV1(t *testing.T, f *FakePlatform) {
	t.Helper()
	for _, r := range f.Requests() {
		if strings.HasPrefix(r.Path, "/api/v1/agent") {
			t.Errorf("request %s %s to the retired protocol v1", r.Method, r.Path)
		}
	}
}

// A completion whose answer was lost is retried and is a replay (200), not
// an error: transitions are idempotent.
func TestControl_LostCompletionIsReplayed(t *testing.T) {
	f := newControlFake(t)
	id := "0192a3b4-0000-7000-8000-000000000002"
	f.QueueCommand(id)
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	if err := c.AcknowledgeCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.StartCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
	dropped := false
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if strings.HasSuffix(r.URL.Path, "/complete") && !dropped {
			dropped = true
			return &FaultAnswer{Drop: true, Process: true}
		}
		return nil
	})
	if err := c.CompleteCommand(ctx, id, json.RawMessage(`{"findings":3}`)); err != nil {
		t.Fatalf("complete after a lost answer: %v", err)
	}
	completes := f.RequestsTo(http.MethodPost, protov2.CommandActionPath(id, protov2.CompleteAction))
	if len(completes) != 2 || completes[1].Status != http.StatusOK {
		t.Fatalf("complete attempts %v", statuses(completes))
	}
	if string(f.CommandResult(id)) != `{"findings":3}` {
		t.Fatalf("result %s", f.CommandResult(id))
	}
	// A completion with another result is a conflict, not a replay.
	err := c.CompleteCommand(ctx, id, json.RawMessage(`{"findings":4}`))
	var ve *client.V2Error
	if !errors.As(err, &ve) || ve.ProblemName() != protov2.ProblemTransitionConflict || !client.IsClientError(err) {
		t.Fatalf("conflicting completion: %v", err)
	}
}

func TestControl_GoneCommand(t *testing.T) {
	f := newControlFake(t)
	id := "0192a3b4-0000-7000-8000-000000000003"
	f.QueueCommand(id)
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	if err := c.AcknowledgeCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
	err := c.CompleteCommand(ctx, id, nil) // not started
	var ve *client.V2Error
	if !client.IsCommandGone(err) || !errors.As(err, &ve) || ve.Problem.State != "acknowledged" {
		t.Fatalf("out-of-order completion: %v", err)
	}
	if err := c.AcknowledgeCommand(ctx, "unknown"); !client.IsCommandGone(err) || !client.IsNotFoundError(err) {
		t.Fatalf("unknown command: %v", err)
	}
}

// v2 tells a disabled sensor to pause with a 200: the doorbell-aware call
// returns the pause action; the plain heartbeat (connection test) reports a
// refused key.
func TestControl_PausedSensor(t *testing.T) {
	f := newControlFake(t)
	f.SetPaused(true)
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	h, err := c.SendHeartbeatWithHints(ctx, status())
	if err != nil || len(h.Actions) != 1 || h.Actions[0] != core.HeartbeatActionPause {
		t.Fatalf("hints %+v %v", h, err)
	}
	if err := c.TestConnection(ctx); !client.IsAuthenticationError(err) || core.AuthFailureStatus(err) != http.StatusUnauthorized {
		t.Fatalf("connection test of a disabled sensor: %v", err)
	}
}

func TestControl_SuppressionsRevalidate(t *testing.T) {
	f := newControlFake(t)
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	for range 2 {
		rules, err := c.GetSuppressions(ctx)
		if err != nil || len(rules) != 1 || rules[0].RuleID != "r1" {
			t.Fatalf("rules %v %v", rules, err)
		}
	}
	gets := f.RequestsTo(http.MethodGet, protov2.PathPrefix+protov2.SuppressionsPath)
	if len(gets) != 2 || gets[0].Header.Get("If-None-Match") != "" ||
		gets[1].Header.Get("If-None-Match") != fakeSuppressionsETag || gets[1].Status != http.StatusNotModified {
		t.Fatalf("revalidation %v", statuses(gets))
	}
}

func TestControl_FingerprintsAreSplitAtTheLimit(t *testing.T) {
	f := newControlFake(t)
	f.Limits.MaxFingerprintsPerRequest = 3
	c := newClient(t, f, client.ProtocolAuto)
	fps := []string{"1", "2", "3", "4", "5", "6", "7"}
	res, err := c.CheckFingerprints(context.Background(), fps)
	if err != nil || len(res.Missing) != 7 {
		t.Fatalf("check %+v %v", res, err)
	}
	if n := len(f.RequestsTo(http.MethodPost, protov2.PathPrefix+protov2.FingerprintsCheckPath)); n != 3 {
		t.Fatalf("%d requests, want 3", n)
	}
}

// A platform that listed a feature but lost the route (404 without a problem)
// answers ErrV2Unsupported and is asked hello again; no fall-back to v1.
func TestControl_RouteMissingIsUnsupported(t *testing.T) {
	f := newControlFake(t)
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.URL.Path == protov2.PathPrefix+protov2.HeartbeatPath {
			return &FaultAnswer{Status: http.StatusNotFound}
		}
		return nil
	})
	c := newClient(t, f, client.ProtocolAuto)
	if err := c.SendHeartbeat(context.Background(), status()); !errors.Is(err, client.ErrV2Unsupported) {
		t.Fatalf("heartbeat: %v", err)
	}
	assertNoV1(t, f)
}

func paths(rs []Request) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}
