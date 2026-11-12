package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/outbox"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
)

const lateCmd = "11111111-1111-4111-8111-111111111111"

// latePlatform refuses every command-bound request as command-not-found
// (a stale lease epoch: the platform took the run back) and answers the
// unbound one with superseded (a platform that knows the late headers) or
// with a completed status (one that does not).
type latePlatform struct {
	superseded bool
	mu         sync.Mutex
	unbound    []http.Header
	bound      int
}

func (lp *latePlatform) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2,
			Features:   []string{protov2.FeatureResults, protov2.FeatureResultsLeaseEpoch},
			MediaTypes: []string{protov2.MediaTypeCTIS}})
		return
	}
	problem := func(status int, name protov2.ProblemType) {
		w.Header().Set("Content-Type", protov2.MediaTypeProblem)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(protov2.Problem{Type: protov2.ProblemTypeBase + string(name), Status: status})
	}
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if strings.Contains(r.URL.Path, "/commands/") {
		lp.bound++
		problem(http.StatusNotFound, protov2.ProblemCommandNotFound)
		return
	}
	lp.unbound = append(lp.unbound, r.Header.Clone())
	if lp.superseded && r.Header.Get(protov2.HeaderLateCommand) != "" {
		problem(http.StatusConflict, protov2.ProblemLeaseSuperseded)
		return
	}
	id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(protov2.Status{ReportID: id, State: protov2.StateCompleted})
}

func lateReport() *ctis.Report {
	r := ctis.NewReport()
	r.Tool = &ctis.Tool{Name: "nuclei"}
	return r
}

// A report the platform refused bound (stale epoch) is sent again without
// the command, but with its command and epoch as provenance: never as an
// anonymous unsolicited report the platform cannot tell from a collector's.
func TestPushResultsV2_LateReportCarriesItsCommandAndEpoch(t *testing.T) {
	lp := &latePlatform{}
	srv := httptest.NewServer(http.HandlerFunc(lp.handler))
	defer srv.Close()

	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	var saved V2Progress
	_, err := c.PushResultsV2(context.Background(), lateReport(), &V2PushOptions{
		CommandID: lateCmd, LeaseEpoch: 3,
		OnProgress: func(p V2Progress) error { saved = p; return nil }})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if lp.bound == 0 || len(lp.unbound) == 0 {
		t.Fatalf("bound=%d unbound=%d: expected a bound refusal and an unbound re-send", lp.bound, len(lp.unbound))
	}
	for i, h := range lp.unbound {
		if got := h.Get(protov2.HeaderLateCommand); got != lateCmd {
			t.Errorf("unbound request %d: %s = %q, want the command it was made for", i, protov2.HeaderLateCommand, got)
		}
		if got := h.Get(protov2.HeaderLateLeaseEpoch); got != "3" {
			t.Errorf("unbound request %d: %s = %q, want 3", i, protov2.HeaderLateLeaseEpoch, got)
		}
		if h.Get(protov2.HeaderLeaseEpoch) != "" {
			t.Errorf("unbound request %d states a lease epoch: it would read as a binding", i)
		}
	}
	// The provenance survives a restart: the outbox persists it.
	if !saved.Unbound || saved.LateCommand != lateCmd || saved.LateLeaseEpoch != 3 {
		t.Fatalf("persisted progress lost the provenance: %+v", saved)
	}
}

// A platform that knows the run was handed out again refuses the late
// report: final, not re-sent under another report id, and kept by the
// outbox as a permanent failure (not dropped silently).
func TestPushResultsV2_SupersededLateReportIsFinal(t *testing.T) {
	lp := &latePlatform{superseded: true}
	srv := httptest.NewServer(http.HandlerFunc(lp.handler))
	defer srv.Close()

	var logs []string
	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	_, err := c.PushResultsV2(context.Background(), lateReport(), &V2PushOptions{
		CommandID: lateCmd, LeaseEpoch: 3,
		Logf: func(f string, a ...any) { logs = append(logs, f) }})
	var ve *V2Error
	if !errors.As(err, &ve) || ve.ProblemName() != protov2.ProblemLeaseSuperseded {
		t.Fatalf("err = %v, want lease-superseded", err)
	}
	lp.mu.Lock()
	n := len(lp.unbound)
	lp.mu.Unlock()
	if n != 1 {
		t.Fatalf("the superseded report was sent %d times unbound, want once", n)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "superseded") {
		t.Fatalf("no log line says why the report was not delivered: %q", logs)
	}
	if !isPermanent(classify(err)) {
		t.Fatalf("classify(%v) is not permanent: the outbox would retry it", err)
	}
}

// A late report never rides the v3 binding, which has no field for its
// provenance: it goes over v2 HTTPS, whatever binding is selected.
func TestV3RoundTripper_LateReportStaysOnHTTPS(t *testing.T) {
	var viaHTTPS atomic.Int32
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		viaHTTPS.Add(1)
		return jsonResponse(http.StatusAccepted, []byte(`{}`)), nil
	})
	var state atomic.Pointer[v3State]
	state.Store(&v3State{svc: panicSensorService{}, binding: BindingGRPC})
	rt := &v3RoundTripper{next: next, state: &state, prefix: protov2.PathPrefix}

	req, _ := http.NewRequest(http.MethodPut, "https://platform.example.com"+protov2.ReportPath("", "22222222-2222-4222-8222-222222222222"), strings.NewReader("{}"))
	req.Header.Set(protov2.HeaderLateCommand, lateCmd)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if viaHTTPS.Load() != 1 {
		t.Fatal("the late report was not sent over v2 HTTPS")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// panicSensorService fails the test run if the v3 binding is used.
type panicSensorService struct {
	sensorv3connect.SensorServiceClient
}

func isPermanent(err error) bool {
	var p *outbox.PermanentError
	return errors.As(err, &p)
}

// A late report whose epoch the sensor never knew (0) names its command but
// states no epoch: "0" would read as a real epoch to the platform.
func TestPushResultsV2_LateReportWithoutEpochOmitsTheEpochHeader(t *testing.T) {
	if h := lateReportHeader(lateCmd, 0); h.Get(protov2.HeaderLateCommand) != lateCmd || len(h.Values(protov2.HeaderLateLeaseEpoch)) != 0 {
		t.Fatalf("lateReportHeader(cmd, 0) = %v, want the command and no epoch", h)
	}
	lp := &latePlatform{}
	srv := httptest.NewServer(http.HandlerFunc(lp.handler))
	defer srv.Close()

	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	if _, err := c.PushResultsV2(context.Background(), lateReport(), &V2PushOptions{CommandID: lateCmd}); err != nil {
		t.Fatalf("push: %v", err)
	}
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if len(lp.unbound) == 0 {
		t.Fatal("the report was never sent again unbound")
	}
	for i, h := range lp.unbound {
		if h.Get(protov2.HeaderLateCommand) != lateCmd {
			t.Errorf("unbound request %d lost its command", i)
		}
		if v := h.Values(protov2.HeaderLateLeaseEpoch); len(v) != 0 {
			t.Errorf("unbound request %d states lease epoch %q, want none", i, v)
		}
	}
}

// A lease-superseded answer to a request that carried no late provenance
// (the bound request itself) still names the command in the log line.
func TestPushResultsV2_SupersededLogNamesTheCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			w.Header().Set("Content-Type", protov2.MediaTypeJSON)
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2,
				Features:   []string{protov2.FeatureResults, protov2.FeatureResultsLeaseEpoch},
				MediaTypes: []string{protov2.MediaTypeCTIS}})
			return
		}
		w.Header().Set("Content-Type", protov2.MediaTypeProblem)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(protov2.Problem{Type: protov2.ProblemTypeBase + string(protov2.ProblemLeaseSuperseded), Status: http.StatusConflict})
	}))
	defer srv.Close()

	var logs []string
	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	_, err := c.PushResultsV2(context.Background(), lateReport(), &V2PushOptions{
		CommandID: lateCmd, LeaseEpoch: 3,
		Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }})
	var ve *V2Error
	if !errors.As(err, &ve) || ve.ProblemName() != protov2.ProblemLeaseSuperseded {
		t.Fatalf("err = %v, want lease-superseded", err)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "superseded") || !strings.Contains(joined, lateCmd) {
		t.Fatalf("the superseded log line does not name the command: %q", joined)
	}
}
