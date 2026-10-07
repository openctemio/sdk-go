package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

// TestKit_PolicyPartialAndRefusalLogs: with a local policy, a scan job with
// one unresolvable target runs on the rest and completes with the refused
// target in its result; a job whose every target is refused fails, and its
// log on the platform says why: the lines reach the platform before the
// failure although no tool ever started.
func TestKit_PolicyPartialAndRefusalLogs(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetLogs(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.ToolCredentials = func(string) map[string]string { return map[string]string{"api_key": "k-123456"} }
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\", \"*.example.com\"]\n"),
		core.LocalPolicyOptions{LookupEnv: func(string) (string, bool) { return "", false },
			LookupIP: func(context.Context, string) ([]net.IP, error) { return nil, errors.New("no such host") }})
	if err != nil {
		t.Fatal(err)
	}
	opts.LocalPolicy = lp
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddTool(loggingTool)
	partial, refused := "0192a3b4-0000-7000-8000-0000000000e1", "0192a3b4-0000-7000-8000-0000000000e2"
	f.QueueCommandPayload(partial, "scan", json.RawMessage(`{"scanner":"kit-logging","targets":["203.0.113.9","api.example.com"]}`))
	f.QueueCommandPayload(refused, "scan", json.RawMessage(`{"scanner":"kit-logging","targets":["gone.example.com","*.example.com"]}`))
	stop := runKit(t, k)
	waitCompleted(t, f, partial, out, errw)
	waitFor(t, "refused command", func() bool { s, _ := f.CommandState(refused); return s == "failed" })
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var res struct {
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(f.CommandResult(partial), &res); err != nil {
		t.Fatal(err)
	}
	list, _ := res.Metadata[core.MetaRefusedTargets].([]any)
	if len(list) != 1 || res.Metadata[core.MetaPartial] != true {
		t.Fatalf("partial result metadata %+v", res.Metadata)
	}
	if r := list[0].(map[string]any); r["target"] != "api.example.com" || r["reason"] != core.RefusedTargetUnresolvable {
		t.Fatalf("refused target %+v", r)
	}

	_, msg := f.CommandState(refused)
	if !strings.Contains(msg, "unresolvable") || !strings.Contains(msg, "wildcard_pattern") {
		t.Fatalf("failure %q must list the refused targets", msg)
	}
	var lines []string
	for _, l := range f.CommandLogs(refused) {
		lines = append(lines, l.Msg)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"Received by the sensor", "Local policy check", "Target refused by the local policy: gone.example.com",
		"Target refused by the local policy: *.example.com", "Refused before running: refused by local policy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("refused command log lacks %q:\n%s", want, joined)
		}
	}
	var logAt, failAt int
	for i, r := range f.Requests() {
		switch {
		case strings.HasSuffix(r.Path, "/"+refused+"/logs") && logAt == 0:
			logAt = i + 1
		case strings.HasSuffix(r.Path, "/"+refused+"/fail") && failAt == 0:
			failAt = i + 1
		}
	}
	if logAt == 0 || failAt == 0 || logAt > failAt {
		t.Fatalf("logs request #%d, fail #%d: the log must reach the platform before the failure", logAt, failAt)
	}
}
