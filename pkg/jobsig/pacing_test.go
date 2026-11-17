package jobsig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// A statement may carry the job's per-host budget; one the sensor cannot
// read is refused under a valid signature, never run at the sensor's
// default instead.
func TestVerifyPacing(t *testing.T) {
	cases := map[string]struct {
		pacing *adapt.JobBudget
		reason string
	}{
		"none":               {nil, ""},
		"gentle":             {&adapt.JobBudget{Level: "gentle"}, ""},
		"numbers":            {&adapt.JobBudget{RPS: 3, Inflight: 1}, ""},
		"custom":             {&adapt.JobBudget{Level: "custom", RPS: 40, Inflight: 10}, ""},
		"above any ceiling":  {&adapt.JobBudget{Level: "custom", RPS: 90000, Inflight: 90000}, ""},
		"empty":              {&adapt.JobBudget{}, ReasonPacing},
		"unknown level":      {&adapt.JobBudget{Level: "ludicrous"}, ReasonPacing},
		"negative":           {&adapt.JobBudget{RPS: -5}, ReasonPacing},
		"nonsense":           {&adapt.JobBudget{RPS: adapt.MaxJobBudget + 1}, ReasonPacing},
		"custom, no numbers": {&adapt.JobBudget{Level: "custom"}, ReasonPacing},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "")
			st := f.statement()
			st.Pacing = tc.pacing
			got, err := f.ver.Verify(context.Background(), f.envelope(t, st), f.b)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("valid job refused: %v", err)
				}
				if (got.Pacing == nil) != (tc.pacing == nil) || (got.Pacing != nil && *got.Pacing != *tc.pacing) {
					t.Fatalf("pacing %+v, want %+v", got.Pacing, tc.pacing)
				}
				return
			}
			if ReasonOf(err) != tc.reason {
				t.Fatalf("err = %v, want reason %q", err, tc.reason)
			}
		})
	}
}

// A statement without a budget encodes without the member: a sensor from
// before the field (which refuses unknown members) still accepts every job
// a platform signs without one.
func TestStatementWithoutPacingHasNoMember(t *testing.T) {
	f := newFixture(t, "")
	raw, err := json.Marshal(f.statement())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "pacing") {
		t.Fatalf("statement without a budget encodes a pacing member: %s", raw)
	}
	st := f.statement()
	st.Pacing = &adapt.JobBudget{Level: "gentle", RPS: 4}
	raw, _ = json.Marshal(st)
	if !strings.Contains(string(raw), `"pacing":{"level":"gentle","target_rps":4}`) {
		t.Fatalf("pacing member: %s", raw)
	}
}
