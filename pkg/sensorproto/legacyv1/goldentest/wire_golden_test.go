// Package goldentest pins the sensor protocol v1 wire the SDK speaks.
//
// The recording in testdata/protocol_v1.golden.json was made from the SDK as
// it was before the agent → sensor rename (sdk-go be8a8b1, RFC-023 §9.5). Every
// request the SDK sends — method, path, query, headers and the exact body
// bytes — and the fields it reads back from v1 responses must stay identical:
// deployed API servers and sensors depend on them. Run with -update only when
// the protocol itself changes, which v1 never does (RFC-023 §9.2 C1).
package goldentest

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/platform"
)

var update = flag.Bool("update", false, "rewrite the golden file")

const goldenFile = "testdata/protocol_v1.golden.json"

// exchange is one recorded request.
type exchange struct {
	Call    string            `json:"call"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type golden struct {
	Requests []exchange `json:"requests"`
	// Decoded holds what the SDK read back from canned v1 responses,
	// re-encoded with the SDK's own types: it proves the response field
	// names (agent_id, ...) are still the ones the SDK decodes.
	Decoded map[string]json.RawMessage `json:"decoded"`
	// Values are wire values the SDK emits outside a request body builder.
	Values map[string]string `json:"values"`
}

// recorder is an httptest handler that records every request and answers
// with a canned v1 response for its route.
type recorder struct {
	mu   sync.Mutex
	call string
	got  []exchange
}

// ignoredHeaders are set by net/http itself and say nothing about the SDK.
var ignoredHeaders = map[string]bool{"Accept-Encoding": true}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	h := map[string]string{}
	for k, v := range req.Header {
		if !ignoredHeaders[k] {
			h[k] = strings.Join(v, ", ")
		}
	}
	r.mu.Lock()
	r.got = append(r.got, exchange{
		Call: r.call, Method: req.Method, Path: req.URL.Path, Query: req.URL.RawQuery,
		Headers: h, Body: string(body),
	})
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, cannedResponse(req.Method, req.URL.Path))
}

// cannedResponse returns the v1 response body an API server sends for path.
func cannedResponse(method, path string) string {
	switch {
	case path == "/api/v1/platform/register":
		return `{"agent_id":"11111111-1111-1111-1111-111111111111","api_key":"rda_secret","api_prefix":"rda_sec","message":"ok"}`
	case path == "/api/v1/agent/renew":
		return `{"api_key":"rda_new","api_prefix":"rda_new","expires_at":"2027-01-01T00:00:00Z"}`
	case path == "/api/v1/agent/commands" && method == http.MethodGet:
		return `[{"id":"c1","tenant_id":"t1","agent_id":"11111111-1111-1111-1111-111111111111","type":"scan","priority":"normal","payload":{"agent_preference":"tenant"},"status":"pending","created_at":"2026-10-01T00:00:00Z"}]`
	case path == "/api/v1/platform/lease" && method == http.MethodPut:
		return `{"success":true,"lease_duration_seconds":60}`
	case path == "/api/v1/platform/poll":
		return `{"jobs":[{"id":"j1","type":"scan","priority":1,"tenant_id":"t1","payload":{"agent_preference":"platform"}}],"queue_depth":0}`
	case path == "/api/v1/agent/ingest/check":
		return `{"existing":["fp1"],"missing":["fp2"]}`
	case path == "/api/v1/agent/ingest/baseline-diff":
		return `{"new_fingerprints":["fp2"],"pre_existing_fingerprints":["fp1"],"base_branch_scanned":true}`
	case path == "/api/v1/exposures/ingest":
		return `{"created":1,"updated":0,"failed":0}`
	case path == "/api/v1/threatintel/epss":
		return `{"scores":[]}`
	case path == "/api/v1/threatintel/kev":
		return `{"entries":[]}`
	case path == "/api/v1/agent/suppressions":
		return `{"rules":[],"count":0}`
	default:
		return `{}`
	}
}

func (r *recorder) start(call string) {
	r.mu.Lock()
	r.call = call
	r.mu.Unlock()
}

func TestMain(m *testing.M) {
	// The recorder listens on 127.0.0.1; the SDK refuses loopback by default.
	httpsec.AllowLoopback = true
	os.Exit(m.Run())
}

func TestProtocolV1Golden(t *testing.T) {
	t.Setenv("REGION", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("GOOGLE_CLOUD_REGION", "")
	t.Setenv("AZURE_REGION", "")

	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	ctx := context.Background()
	decoded := map[string]json.RawMessage{}
	keep := func(name string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		decoded[name] = b
	}
	must := func(call string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", call, err)
		}
	}

	const sensorID = "11111111-1111-1111-1111-111111111111"

	// ---- pkg/client (tenant sensors: /api/v1/agent/*) ----
	c := client.New(&client.Config{
		BaseURL: srv.URL, APIKey: "rda_test", SensorID: sensorID,
		MaxRetries: 1, EnableCompression: false,
	})

	rec.start("client.SendHeartbeat")
	must("SendHeartbeat", c.SendHeartbeat(ctx, &core.SensorStatus{
		Name: "s1", Status: core.SensorStateRunning, Scanners: []string{"nuclei"},
		Uptime: 10, TotalScans: 2, Message: "ok", Region: "r1",
	}))

	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID: "rep-1", Timestamp: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			SourceType: "scanner",
		},
		Tool:     &ctis.Tool{Name: "nuclei", Version: "3.0.0"},
		Findings: []ctis.Finding{{ID: "f1", Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityHigh, Fingerprint: "fp1"}},
		Assets:   []ctis.Asset{{ID: "a1", Type: ctis.AssetTypeDomain, Value: "example.com"}},
	}
	rec.start("client.PushFindings")
	res, err := c.PushFindings(ctx, report)
	must("PushFindings", err)
	keep("client.PushFindings", res)

	rec.start("client.PushAssets")
	_, err = c.PushAssets(ctx, report)
	must("PushAssets", err)

	rec.start("client.CheckFingerprints")
	fps, err := c.CheckFingerprints(ctx, []string{"fp1", "fp2"})
	must("CheckFingerprints", err)
	keep("client.CheckFingerprints", fps)

	rec.start("client.BaselineDiff")
	newFps, err := c.BaselineDiff(ctx, "org/repo", "main", []string{"fp1", "fp2"})
	must("BaselineDiff", err)
	keep("client.BaselineDiff", newFps)

	rec.start("client.PollCommands")
	cmds, err := c.PollCommands(ctx, 5)
	must("PollCommands", err)
	keep("client.PollCommands", cmds)

	rec.start("client.AcknowledgeCommand")
	must("AcknowledgeCommand", c.AcknowledgeCommand(ctx, "c1"))
	rec.start("client.StartCommand")
	must("StartCommand", c.StartCommand(ctx, "c1"))
	rec.start("client.CompleteCommand")
	must("CompleteCommand", c.CompleteCommand(ctx, "c1", json.RawMessage(`{"findings":1}`)))
	rec.start("client.FailCommand")
	must("FailCommand", c.FailCommand(ctx, "c1", "boom"))

	rec.start("client.PushExposures")
	_, err = c.PushExposures(ctx, []client.ExposureEvent{{Type: "port_open", AssetID: "a1", Port: 443}})
	must("PushExposures", err)

	rec.start("client.GetEPSSScores")
	_, err = c.GetEPSSScores(ctx, []string{"CVE-2024-0001"})
	must("GetEPSSScores", err)
	rec.start("client.GetKEVEntries")
	_, err = c.GetKEVEntries(ctx, []string{"CVE-2024-0001"})
	must("GetKEVEntries", err)
	rec.start("client.GetSuppressions")
	_, err = c.GetSuppressions(ctx)
	must("GetSuppressions", err)

	// ---- pkg/platform (platform sensors: /api/v1/platform/*, /api/v1/agent/renew) ----
	b := platform.NewBootstrapper(srv.URL, "bt_token", &platform.BootstrapConfig{RetryAttempts: 0})
	rec.start("platform.Register")
	reg, err := b.Register(ctx, &platform.RegistrationRequest{
		Name: "p1", Capabilities: []string{"dast"}, Tools: []string{"nuclei"},
		Region: "r1", Labels: map[string]string{"zone": "a"}, MaxConcurrentJobs: 3,
	})
	must("Register", err)
	keep("platform.Register", reg)

	pc := platform.NewPlatformClient(&platform.ClientConfig{
		BaseURL: srv.URL, APIKey: "rda_test", SensorID: sensorID, PollTimeout: time.Second,
	})
	rec.start("platform.RenewKey")
	rk, err := pc.RenewKey(ctx)
	must("RenewKey", err)
	keep("platform.RenewKey", rk)

	rec.start("platform.RenewLease")
	_, err = pc.RenewLease(ctx, &platform.LeaseRenewRequest{
		HolderIdentity: "h1", LeaseDurationSeconds: 60, CurrentJobs: 1, MaxJobs: 3,
	})
	must("RenewLease", err)
	rec.start("platform.ReleaseLease")
	must("ReleaseLease", pc.ReleaseLease(ctx))

	rec.start("platform.Poll")
	poll, err := pc.Poll(ctx, &platform.PollRequest{MaxJobs: 2, Capabilities: []string{"dast"}, TimeoutSeconds: 1})
	must("Poll", err)
	keep("platform.Poll", poll)

	rec.start("platform.AcknowledgeJob")
	must("AcknowledgeJob", pc.AcknowledgeJob(ctx, "j1"))
	rec.start("platform.ReportJobResult")
	must("ReportJobResult", pc.ReportJobResult(ctx, &platform.JobResult{
		JobID: "j1", Status: "completed", CompletedAt: time.Date(2026, 10, 1, 0, 0, 1, 0, time.UTC),
		DurationMs: 1000, FindingsCount: 1,
	}))
	rec.start("platform.ReportJobProgress")
	must("ReportJobProgress", pc.ReportJobProgress(ctx, "j1", 50, "half"))

	values := map[string]string{
		"ctis.DefaultReconConverterOptions.DiscoverySource": ctis.DefaultReconConverterOptions().DiscoverySource,
		"core.AgentStateRunning":                            string(core.SensorStateRunning),
		"core.AgentStateStopped":                            string(core.SensorStateStopped),
	}

	got := golden{Requests: rec.got, Decoded: decoded, Values: values}
	compare(t, got)
}

func compare(t *testing.T, got golden) {
	t.Helper()
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenFile), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenFile, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("read golden (run with -update to record): %v", err)
	}
	if !bytes.Equal(want, data) {
		var w golden
		_ = json.Unmarshal(want, &w)
		for i := range got.Requests {
			if i >= len(w.Requests) {
				t.Errorf("extra request %d: %+v", i, got.Requests[i])
				continue
			}
			g, e := got.Requests[i], w.Requests[i]
			gb, _ := json.Marshal(g)
			eb, _ := json.Marshal(e)
			if !bytes.Equal(gb, eb) {
				t.Errorf("request %d (%s) changed:\n got: %s\nwant: %s", i, e.Call, gb, eb)
			}
		}
		if len(w.Requests) > len(got.Requests) {
			t.Errorf("%d requests missing", len(w.Requests)-len(got.Requests))
		}
		t.Fatalf("protocol v1 wire differs from %s", goldenFile)
	}
}
