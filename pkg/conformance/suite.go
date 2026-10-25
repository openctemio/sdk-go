package conformance

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/outcome"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// SensorEndpoint is the platform RunSensorSuite points the sensor under test
// at: the fake's base URL and the sensor key it accepts.
type SensorEndpoint struct {
	URL    string
	APIKey string
}

// StartSensor starts the sensor under test against p (in process, or as a
// child process with SENSOR_API_URL / SENSOR_API_KEY set) and returns a function that
// stops it and waits until it has exited. The fake listens on 127.0.0.1: an
// SDK-based sensor needs httpsec.AllowLoopback (or
// OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK=1 for a child process) to reach it.
type StartSensor func(t *testing.T, p SensorEndpoint) (stop func())

// SuiteOptions configures RunSensorSuite.
type SuiteOptions struct {
	// ScanType and ScanPayload are a command the sensor can run to
	// completion against the fake ("" ScanType is "scan"). With no
	// ScanPayload the command checks are skipped.
	ScanType    string
	ScanPayload json.RawMessage
	// GuardScanner and GuardTarget are a network scanner the sensor runs
	// and a public target it completes a scan of; set, the TargetGuard
	// check runs ("" skips it).
	GuardScanner string
	GuardTarget  string
	// Timeout bounds every wait. Zero is 60s.
	Timeout time.Duration
}

// GuardRefusedTargets are targets every sensor's target guard refuses: cloud
// metadata (as host:port), carrier-grade NAT, and a name that never resolves
// (RFC 6761 .invalid).
var GuardRefusedTargets = []string{"169.254.169.254:80", "100.64.0.1", "unresolvable.invalid:443"}

// UnknownCommandType is the command type the suite dispatches to check that
// a sensor fails a command it does not know instead of hanging or crashing.
const UnknownCommandType = "x_conformance_unknown"

// RunSensorSuite checks a sensor against the platform contract every
// sensor must keep, whatever tools it runs, so a third-party sensor can
// prove it in its own tests:
//
//	func TestConformance(t *testing.T) {
//		httpsec.AllowLoopback = true // the fake listens on 127.0.0.1
//		conformance.RunSensorSuite(t, func(t *testing.T, p conformance.SensorEndpoint) func() {
//			kit, err := sensorkit.New(sensorkit.Options{Name: "my-sensor", Version: "1.0.0",
//				APIURL: p.URL, APIKey: p.APIKey, StateDir: t.TempDir(),
//				Outbox: sensorkit.OutboxSettings{Dir: t.TempDir()}})
//			if err != nil {
//				t.Fatal(err)
//			}
//			kit.AddScanner(myScanner)
//			ctx, cancel := context.WithCancel(context.Background())
//			done := make(chan error, 1)
//			go func() { done <- kit.Run(ctx) }()
//			return func() { cancel(); <-done }
//		}, conformance.SuiteOptions{ScanPayload: json.RawMessage(`{"scanner":"my-tool","target":"..."}`)})
//	}
//
// Each check runs against its own FakePlatform (protocol v2, control plane
// and manifest on):
//
//   - Heartbeat: the sensor heartbeats and names the SDK it is built on.
//   - Manifest: a sensor that announces a manifest digest registers the
//     manifest when the platform asks for it.
//   - UnknownCommand: a command of a type the sensor does not handle is
//     left pending for a sensor that does (or failed), never claimed and
//     abandoned, and the sensor keeps polling.
//   - ForwardCompatible: the same with every answer carrying a JSON member
//     no SDK knows (FutureMember), as a newer platform's would: the sensor
//     ignores it and keeps working (and runs its own command, with
//     ScanPayload).
//   - Command (with ScanPayload): the command completes, and every report
//     sent for it is committed before the command is completed.
//   - TargetGuard (with GuardScanner): a scan whose targets mix GuardTarget
//     with GuardRefusedTargets completes on GuardTarget; each refused target
//     is listed in the result with a reason and settled as skipped/refused,
//     never handed to the tool. A scan of refused targets only fails.
func RunSensorSuite(t *testing.T, start StartSensor, opts SuiteOptions) {
	t.Helper()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	newFake := func(t *testing.T) *FakePlatform {
		f := NewFakePlatform(true)
		f.SetControl(true)
		f.SetManifest(true)
		t.Cleanup(f.Close)
		return f
	}
	run := func(t *testing.T, f *FakePlatform) {
		stop := start(t, SensorEndpoint{URL: f.URL(), APIKey: f.APIKey})
		t.Cleanup(stop)
	}

	t.Run("Heartbeat", func(t *testing.T) {
		f := newFake(t)
		run(t, f)
		suiteWait(t, timeout, "a heartbeat", func() bool { return len(f.Heartbeats()) > 0 })
		b := f.HeartbeatBuilds()[0]
		if b.SDK == nil || b.SDK.Name == "" || b.SDK.Version == "" {
			t.Errorf("the heartbeat does not name the SDK (\"sdk\": {name, version}): %s", f.Heartbeats()[0])
		}
	})

	t.Run("Manifest", func(t *testing.T) {
		f := newFake(t)
		run(t, f)
		suiteWait(t, timeout, "a heartbeat", func() bool { return len(f.Heartbeats()) > 0 })
		if !announcesManifest(f.Heartbeats()) {
			t.Skip("the sensor announces no manifest digest; nothing to register")
		}
		suiteWait(t, timeout, "the manifest to be registered", func() bool { return len(f.Manifests()) > 0 })
	})

	// unknownCommand queues a command of a type no sensor handles next to
	// the sensor's own command (when there is one): the sensor must leave
	// the unknown one for a sensor that handles it (pending) or fail it,
	// never claim it and abandon it, and keep polling.
	unknownCommand := func(t *testing.T, future bool) {
		f := newFake(t)
		f.SetFutureFields(future)
		const unknown = "0192a3b4-0000-7000-8000-00000000c0f1"
		const known = "0192a3b4-0000-7000-8000-00000000c0f3"
		f.QueueCommandPayload(unknown, UnknownCommandType, json.RawMessage(`{}`))
		if len(opts.ScanPayload) > 0 {
			f.QueueCommandPayload(known, opts.ScanType, opts.ScanPayload)
		}
		run(t, f)
		polls := func() int { return len(f.RequestsTo(http.MethodGet, protov2.PathPrefix+protov2.CommandsPath)) }
		suiteWait(t, timeout, "two command polls", func() bool { return polls() >= 2 })
		if len(opts.ScanPayload) > 0 {
			suiteWait(t, timeout, "the sensor's own command to finish", func() bool {
				s, _ := f.CommandState(known)
				return s == "failed" || s == "completed"
			})
			if s, e := f.CommandState(known); s != "completed" {
				t.Errorf("the sensor's own command ended %q (%s), want completed", s, e)
			}
		}
		if s, _ := f.CommandState(unknown); s != "pending" && s != "failed" {
			t.Errorf("a command of a type the sensor does not handle is %q; want it left pending for another sensor, or failed", s)
		}
	}
	t.Run("UnknownCommand", func(t *testing.T) { unknownCommand(t, false) })
	t.Run("ForwardCompatible", func(t *testing.T) { unknownCommand(t, true) })

	t.Run("Command", func(t *testing.T) {
		if len(opts.ScanPayload) == 0 {
			t.Skip("no SuiteOptions.ScanPayload")
		}
		f := newFake(t)
		const id = "0192a3b4-0000-7000-8000-00000000c0f2"
		f.QueueCommandPayload(id, opts.ScanType, opts.ScanPayload)
		run(t, f)
		suiteWait(t, timeout, "the command to finish", func() bool {
			s, _ := f.CommandState(id)
			return s == "failed" || s == "completed"
		})
		if s, e := f.CommandState(id); s != "completed" {
			t.Fatalf("the command ended %q (%s), want completed", s, e)
		}
		for rid, r := range f.Reports() {
			if r.CommandID == id && !r.Committed {
				t.Errorf("report %s of the command is not committed", rid)
			}
		}
	})

	t.Run("TargetGuard", func(t *testing.T) {
		if opts.GuardScanner == "" || opts.GuardTarget == "" {
			t.Skip("no SuiteOptions.GuardScanner")
		}
		f := newFake(t)
		const mixed = "0192a3b4-0000-7000-8000-00000000c0f4"
		const refused = "0192a3b4-0000-7000-8000-00000000c0f5"
		payload := func(targets []string) json.RawMessage {
			raw, _ := json.Marshal(map[string]any{"scanner": opts.GuardScanner, "targets": targets})
			return raw
		}
		f.QueueCommandPayload(mixed, "scan", payload(append([]string{opts.GuardTarget}, GuardRefusedTargets...)))
		f.QueueCommandPayload(refused, "scan", payload(GuardRefusedTargets))
		run(t, f)
		for _, id := range []string{mixed, refused} {
			suiteWait(t, timeout, "the guard commands to finish", func() bool {
				s, _ := f.CommandState(id)
				return s == "failed" || s == "completed"
			})
		}
		if s, e := f.CommandState(refused); s != "failed" || e == "" {
			t.Errorf("a scan whose every target is refused ended %q (%q); want failed with a reason", s, e)
		}
		if s, e := f.CommandState(mixed); s != "completed" {
			t.Fatalf("a scan with one good target ended %q (%s); want completed on it", s, e)
		}
		var res struct {
			Metadata       map[string]json.RawMessage `json:"metadata"`
			TargetOutcomes []outcome.Target           `json:"target_outcomes"`
		}
		if err := json.Unmarshal(f.CommandResult(mixed), &res); err != nil {
			t.Fatalf("result: %v", err)
		}
		var listed []struct {
			Target string `json:"target"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(res.Metadata["refused_targets"], &listed)
		got := map[string]string{}
		for _, r := range listed {
			got[r.Target] = r.Reason
		}
		for _, want := range GuardRefusedTargets {
			if got[want] == "" {
				t.Errorf("refused target %q is not listed with a reason in the result (refused_targets: %s)", want, res.Metadata["refused_targets"])
			}
		}
		if _, ok := got[opts.GuardTarget]; ok {
			t.Errorf("the good target %q is listed as refused", opts.GuardTarget)
		}
		settled := map[string]outcome.Target{}
		for _, o := range res.TargetOutcomes {
			settled[o.Target] = o
		}
		for _, want := range GuardRefusedTargets {
			if o := settled[want]; o.State != outcome.Skipped || o.Class != outcome.Refused {
				t.Errorf("refused target %q has outcome %+v; want skipped/refused", want, o)
			}
		}
		if o := settled[opts.GuardTarget]; o.State == outcome.Skipped {
			t.Errorf("the good target %q was skipped: %+v", opts.GuardTarget, o)
		}
	})
}

// announcesManifest reports whether any heartbeat names a manifest digest.
func announcesManifest(beats []json.RawMessage) bool {
	for _, b := range beats {
		var hb struct {
			ManifestDigest string `json:"manifest_digest"`
		}
		if json.Unmarshal(b, &hb) == nil && strings.TrimSpace(hb.ManifestDigest) != "" {
			return true
		}
	}
	return false
}

func suiteWait(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}
