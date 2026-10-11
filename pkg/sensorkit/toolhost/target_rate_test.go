package toolhost

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY (RFC-040): the forwarder's rate ceiling is the lowest of every
// limit; a platform asking for more than the sensor-local policy allows
// gets the local maximum, never more.
func TestRateCeilingIsTheLowestLimit(t *testing.T) {
	withParam := tool.Manifest{Name: "t", Safety: &tool.Safety{RateParam: "rate"}}
	cfg := json.RawMessage(`{"rate":500}`)
	cases := []struct {
		name   string
		m      tool.Manifest
		cfg    json.RawMessage
		caller float64
		pol    Policy
		want   float64
	}{
		{"local policy lower than the platform", withParam, cfg, 300, &ratePolicy{max: 20}, 20},
		{"caller lower than the platform", withParam, cfg, 300, &fakePolicy{}, 300},
		{"platform lowest", withParam, cfg, 0, &ratePolicy{max: 900}, 500},
		{"no rate param: connect default capped locally", tool.Manifest{Name: "t"}, nil, 0, &ratePolicy{max: 50}, 50},
		{"no rate param, no policy", tool.Manifest{Name: "t"}, nil, 0, &fakePolicy{}, 1000},
	}
	for _, tc := range cases {
		h := &Host{Policy: tc.pol}
		got := h.rateCeiling(&prepared{m: tc.m, task: tool.Task{Config: tc.cfg}, targetRate: tc.caller})
		if got != tc.want {
			t.Errorf("%s: ceiling %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The outcome carries the rate summary and the coverage gaps, and the log
// says why the rate moved.
func TestFinishReportsRateAndGaps(t *testing.T) {
	fw := egress.New(egress.Scope{}, egress.Limits{Rate: 40, PerHostRate: 40})
	e := &taskEgress{fw: fw, dir: t.TempDir(), cancel: func() {}}
	fw.TargetRate().OnChange = e.change
	fw.TargetRate().ReportHTTP("busy.example", 429, "")
	fw.TargetRate().ReportHTTP("blocked.example", 200, "")
	for range adapt.TargetRate.BlockRun {
		fw.TargetRate().ReportHTTP("blocked.example", 403, "")
	}
	out := &Outcome{}
	lines := e.finish(out)
	if out.TargetRate == nil || out.TargetRate.Ceiling != 40 || out.TargetRate.Throttled != 2 {
		t.Fatalf("summary %+v", out.TargetRate)
	}
	var text []string
	for _, l := range lines {
		text = append(text, l.Msg)
	}
	all := strings.Join(text, "\n")
	for _, want := range []string{"target rate busy.example: 10/s -> 5/s (http_429)", "ceiling 40/s", "2 throttled",
		"coverage gap blocked.example (blocked)"} {
		if !strings.Contains(all, want) {
			t.Errorf("log lacks %q:\n%s", want, all)
		}
	}
	if out.TargetRate.GapsTotal != 1 || out.TargetRate.Gaps[0].Host != "blocked.example" {
		t.Errorf("gaps %+v", out.TargetRate.Gaps)
	}
	var nilEgress *taskEgress
	if nilEgress.finish(out) != nil {
		t.Fatal("finish without a forwarder logged")
	}
}
