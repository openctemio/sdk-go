package core

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// decodedReport is a report as the executor sees it after the tool host's
// JSON went through the parser: list properties are []any.
func decodedReport(t *testing.T, props map[string]any) *ctis.Report {
	t.Helper()
	raw, err := json.Marshal(props)
	if err != nil {
		t.Fatal(err)
	}
	r := ctis.NewReport()
	if err := json.Unmarshal(raw, &r.Properties); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTargetOutcomes_FromReport(t *testing.T) {
	targets := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	report := decodedReport(t, map[string]any{
		outcome.ResultKey: []outcome.Target{
			{Target: "a.example", State: outcome.Done},
			{Target: "b.example", State: outcome.Failed, Class: outcome.Timeout},
			{Target: "x.example", State: outcome.Done}, // not a job target
		},
		"unfinished_targets": []string{"c.example"},
		"failed_targets":     []map[string]string{{"target": "d.example", "error": "exit 2"}},
	})
	got := TargetOutcomes(targets, report)
	want := []outcome.Target{
		{Target: "a.example", State: outcome.Done},
		{Target: "b.example", State: outcome.Failed, Class: outcome.Timeout},
		{Target: "c.example", State: outcome.Unfinished},
		{Target: "d.example", State: outcome.Failed, Class: outcome.ToolError},
		{Target: "e.example", State: outcome.Done},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %+v\nwant %+v", got, want)
	}
}

func TestTargetOutcomes_NoReportIsAllDone(t *testing.T) {
	got := TargetOutcomes([]string{"a", "b"}, nil)
	if c := outcome.Count(got); c != (outcome.Counts{Done: 2}) {
		t.Fatalf("counts = %+v", c)
	}
	if TargetOutcomes(nil, nil) != nil {
		t.Fatal("outcomes without targets")
	}
}

// Outcomes name the payload's own values, and targets the executor's
// policy refused are skipped, so the platform never reads them as
// unfinished.
func TestPayloadOutcomes_AliasesAndRefused(t *testing.T) {
	p := &ScanCommandPayload{aliases: map[string]string{"/real/repo": "/link/repo"}}
	got := p.outcomes([]outcome.Target{{Target: "/real/repo", State: outcome.Done}},
		[]RefusedTarget{{Target: "10.0.0.1", Reason: RefusedTargetDenied}})
	want := []outcome.Target{
		{Target: "10.0.0.1", State: outcome.Skipped, Class: outcome.Refused},
		{Target: "/link/repo", State: outcome.Done},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outcomes = %+v", got)
	}
}
