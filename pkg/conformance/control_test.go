package conformance

// api RFC-029: the SDK uses protocol v2 for every feature the platform lists
// on hello, never sends X-Agent-ID on v2, and falls back to v1 per feature
// against a platform that does not list it (api v0.8: results only; before
// that: nothing on v2).

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
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
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
		if r.Header.Get(legacyv1.HeaderSensorID) != "" {
			t.Errorf("%s %s carries %s", r.Method, r.Path, legacyv1.HeaderSensorID)
		}
		if r.Header.Get(legacyv1.HeaderSensorFeatures) != "" {
			t.Errorf("%s %s carries %s", r.Method, r.Path, legacyv1.HeaderSensorFeatures)
		}
	}
	if got := c.ProtocolFeatures(); len(got) != 6 {
		t.Errorf("negotiated features %v", got)
	}
	if n := len(f.RequestsTo(http.MethodGet, protov2.PathPrefix+protov2.HelloPath)); n != 1 {
		t.Errorf("hello asked %d times, want once (cached)", n)
	}
}

// An api v0.8 platform lists only results on v2: results go v2, the rest v1.
func TestControl_MixedPlatformUsesV1ForUnlistedFeatures(t *testing.T) {
	f := NewFakePlatform(true) // Control off
	defer f.Close()
	f.OpenCommand("cmd-1")
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	if err := c.SendHeartbeat(ctx, status()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PushFindings(ctx, report("semgrep", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportCommandResult(ctx, "cmd-1", &core.CommandResult{Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	if len(f.RequestsTo(http.MethodPost, legacyv1.PathHeartbeat)) != 1 ||
		len(f.RequestsTo(http.MethodPut, protov2.PathPrefix+protov2.ResultsPath)) != 1 ||
		len(f.RequestsTo(http.MethodPost, legacyv1.PathCommands+"/cmd-1/complete")) != 1 {
		t.Fatalf("requests %v", paths(f.Requests()))
	}
	if st, _ := f.CommandState("cmd-1"); st != "completed" {
		t.Fatalf("state %q", st)
	}
	// v2 mode requires v2 results only; the heartbeat keeps working on v1.
	c2 := newClient(t, f, client.ProtocolV2)
	if err := c2.SendHeartbeat(ctx, status()); err != nil {
		t.Fatalf("v2 mode against a results-only platform: %v", err)
	}
}

// A platform without v2: everything on v1 after one hello probe.
func TestControl_OldPlatformGetsV1(t *testing.T) {
	f := NewFakePlatform(false)
	defer f.Close()
	c := newClient(t, f, client.ProtocolAuto)
	ctx := context.Background()
	if err := c.SendHeartbeat(ctx, status()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSuppressions(ctx); err != nil && !client.IsNotFoundError(err) {
		t.Logf("suppressions on the fake v1: %v", err)
	}
	for _, r := range f.Requests() {
		if strings.HasPrefix(r.Path, protov2.PathPrefix) && r.Path != protov2.PathPrefix+protov2.HelloPath {
			t.Errorf("v2 request %s %s against a v1 platform", r.Method, r.Path)
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
// refused key, as v1's 401 did.
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
// gets the call on v1 and is asked hello again.
func TestControl_RouteMissingFallsBackToV1(t *testing.T) {
	f := newControlFake(t)
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.URL.Path == protov2.PathPrefix+protov2.HeartbeatPath {
			return &FaultAnswer{Status: http.StatusNotFound}
		}
		return nil
	})
	c := newClient(t, f, client.ProtocolAuto)
	if err := c.SendHeartbeat(context.Background(), status()); err != nil {
		t.Fatal(err)
	}
	if len(f.RequestsTo(http.MethodPost, legacyv1.PathHeartbeat)) != 1 {
		t.Fatalf("requests %v", paths(f.Requests()))
	}
}

func paths(rs []Request) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}
