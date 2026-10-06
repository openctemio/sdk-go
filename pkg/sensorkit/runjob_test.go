package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

// TestKit_RunJob: a sensor started for one command claims that command by
// id, runs it, delivers its result and returns; it never takes other work.
// A command it cannot claim, or does not serve, is an error (the latter
// released to the platform).
func TestKit_RunJob(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	other, job, foreign := "0192a3b4-0000-7000-8000-0000000000a1", "0192a3b4-0000-7000-8000-0000000000a2", "0192a3b4-0000-7000-8000-0000000000a3"
	f.QueueCommandPayload(other, "scan", scanPayload("kit-contract", "8.8.8.8"))
	f.QueueCommandPayload(job, "scan", scanPayload("kit-contract", "1.1.1.1"))
	f.QueueCommandPayload(foreign, "x_not_served", json.RawMessage(`{}`))

	run := func(id string) (*syncBuffer, error) {
		opts, out, errw := baseOptions(t, f)
		k, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		k.AddTool(contractTool)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = k.RunJob(ctx, id)
		_ = out
		return errw, err
	}

	if errw, err := run(job); err != nil {
		t.Fatalf("RunJob: %v\n%s", err, errw.String())
	}
	if st, msg := f.CommandState(job); st != "completed" {
		t.Fatalf("job: %s %s", st, msg)
	}
	if st, _ := f.CommandState(other); st != "pending" {
		t.Fatalf("a job sensor took other work: %s", st)
	}
	if !strings.Contains(strings.Join(acceptedTitles(f), "\n"), "contract finding on 1.1.1.1") {
		t.Fatalf("the job's results were not delivered: %v", acceptedTitles(f))
	}

	if _, err := run(foreign); !errors.Is(err, core.ErrNotRun) {
		t.Fatalf("a command type the sensor does not serve: %v", err)
	}
	if st, _ := f.CommandState(foreign); st == "completed" || st == "running" {
		t.Fatalf("the unserved command is %s, want released", st)
	}
	if _, err := run("0192a3b4-0000-7000-8000-0000000000ff"); err == nil || !strings.Contains(err.Error(), "claim") {
		t.Fatalf("an unknown command: %v", err)
	}
	if _, err := run("not-a-uuid"); err == nil {
		t.Fatal("a malformed id was accepted")
	}
}
