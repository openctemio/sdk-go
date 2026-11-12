package sensorkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	serveOnlyScan    = "0192a3b4-0000-7000-8000-0000000000a1"
	serveOnlyCollect = "0192a3b4-0000-7000-8000-0000000000a2"
	serveOnlyHealth  = "0192a3b4-0000-7000-8000-0000000000a3"
	serveOnlyJob     = "0192a3b4-0000-7000-8000-0000000000a4"
)

// exampleOutput has a key order and number formats encoding/json would
// change if it decoded and encoded it again.
var exampleOutput = json.RawMessage(`{"state":"done","score":0.50,"count":1e2,"subject":"example.com"}`)

func released(f *conformance.FakePlatform) []string {
	var ids []string
	for _, r := range f.Releases() {
		ids = append(ids, r.CommandID)
	}
	return ids
}

// A worker that serves only its own command types: the scan, collect and
// health_check commands queued for it are never claimed, started or failed,
// and its own command completes with its typed output byte for byte.
func TestKit_ServeOnlyCommandTypes(t *testing.T) {
	for _, viaEnv := range []bool{false, true} {
		name := "option"
		if viaEnv {
			name = "env"
		}
		t.Run(name, func(t *testing.T) {
			f := conformance.NewFakePlatform(true)
			f.SetControl(true)
			t.Cleanup(f.Close)
			opts, out, errw := baseOptions(t, f)
			opts.CommandPollInterval = 100 * time.Millisecond
			if viaEnv {
				t.Setenv(EnvCommandTypes, " example_job ,example_job")
			} else {
				opts.CommandTypes = []string{"example_job"}
			}
			k, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			k.HandleCommand("example_job", commandExecFunc(func(context.Context, *core.Command) (*core.CommandExecutionResult, error) {
				return &core.CommandExecutionResult{Output: exampleOutput}, nil
			}))
			f.QueueCommandPayload(serveOnlyScan, "scan", scanPayload("nuclei", "203.0.113.10"))
			f.QueueCommandPayload(serveOnlyCollect, "collect", json.RawMessage(`{}`))
			f.QueueCommandPayload(serveOnlyHealth, "health_check", json.RawMessage(`{}`))
			f.QueueCommandPayload(serveOnlyJob, "example_job", json.RawMessage(`{"subject":"example.com"}`))
			stop := runKit(t, k)
			waitCompleted(t, f, serveOnlyJob, out, errw)
			// A few more polls after the job: the other types are never
			// claimed, started or failed. They stay pending for a sensor that
			// serves them (a platform that claims on poll gets them released).
			polls := func() int {
				n := 0
				for _, r := range f.Requests() {
					if r.Method == "GET" && strings.Contains(r.Path, "/commands") {
						n++
					}
				}
				return n
			}
			after := polls()
			waitFor(t, "more polls", func() bool { return polls() >= after+2 })
			if err := stop(); err != nil {
				t.Fatalf("Run: %v", err)
			}
			others := []string{serveOnlyScan, serveOnlyCollect, serveOnlyHealth}
			for _, id := range others {
				if s, msg := f.CommandState(id); s != "pending" {
					t.Errorf("command %s is %s (%s), want it left pending", id, s, msg)
				}
			}
			for _, r := range f.Requests() {
				for _, id := range others {
					if strings.Contains(r.Path, id) {
						t.Errorf("the worker acted on command %s: %s %s", id, r.Method, r.Path)
					}
				}
			}
			for _, rel := range released(f) {
				if !slices.Contains(others, rel) {
					t.Errorf("unexpected release of %s", rel)
				}
			}
			var res struct {
				Status string          `json:"status"`
				Output json.RawMessage `json:"output"`
			}
			if err := json.Unmarshal(f.CommandResult(serveOnlyJob), &res); err != nil {
				t.Fatal(err)
			}
			if res.Status != "completed" || !bytes.Equal(res.Output, exampleOutput) {
				t.Fatalf("stored result %s, want output %s", f.CommandResult(serveOnlyJob), exampleOutput)
			}
		})
	}
}

// A listed type nothing serves stops Run before the sensor starts: its
// commands would be claimed and then fail.
func TestKit_ServeOnlyRefusesAnUnservedType(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	opts.CommandTypes = []string{"example_job", "health_check", "other_job"}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.HandleCommand("example_job", commandExecFunc(func(context.Context, *core.Command) (*core.CommandExecutionResult, error) {
		return &core.CommandExecutionResult{}, nil
	}))
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), signalKey{}, true))
	defer cancel()
	err = k.Run(ctx)
	var kerr *Error
	if err == nil || !errors.As(err, &kerr) || kerr.Code != ExitUsage || !strings.Contains(err.Error(), "other_job") ||
		strings.Contains(err.Error(), "lists example_job") {
		t.Fatalf("Run = %v, want a usage error naming other_job only", err)
	}
	for _, r := range f.Requests() {
		if strings.Contains(r.Path, "/commands") || strings.Contains(r.Path, "heartbeat") {
			t.Fatalf("the sensor started: %s %s", r.Method, r.Path)
		}
	}
}

func TestResolveCommandTypes(t *testing.T) {
	clearEnv(t)
	if got := resolveCommandTypes(nil); got != nil {
		t.Fatalf("unset = %v, want nil", got)
	}
	t.Setenv(EnvCommandTypes, " a, ,b,a ")
	if got := resolveCommandTypes(nil); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("env = %v", got)
	}
	if got := resolveCommandTypes([]string{"c"}); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("option over env = %v", got)
	}
	t.Setenv(EnvCommandTypes, " , ")
	if got := resolveCommandTypes(nil); got != nil {
		t.Fatalf("blank env = %v, want nil", got)
	}
}
