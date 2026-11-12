package lookupjob

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

type fakePlatform struct {
	jobs    []*Job
	results map[string]Result
}

func (p *fakePlatform) NextLookup(context.Context) (*Job, time.Duration, error) {
	if len(p.jobs) == 0 {
		return nil, 30 * time.Second, nil
	}
	j := p.jobs[0]
	p.jobs = p.jobs[1:]
	return j, 0, nil
}

func (p *fakePlatform) LookupDone(_ context.Context, id string, r Result) error {
	p.results[id] = r
	return nil
}

// fakeVerifier accepts a job whose signed_job is {"tenant": "..."} and
// refuses anything else, as a bad signature.
type fakeVerifier struct{}

func (fakeVerifier) VerifyLookup(_ context.Context, _ string, _, signed []byte) (*jobsig.Statement, error) {
	var s struct{ Tenant string }
	if json.Unmarshal(signed, &s) != nil || s.Tenant == "" {
		return nil, errors.New("bad signature")
	}
	return &jobsig.Statement{TenantID: s.Tenant}, nil
}

type call struct{ tenant, target, input string }

func newRunner(t *testing.T, p *fakePlatform, calls *[]call) *Runner {
	t.Helper()
	r, err := New(Config{Platform: p, Verifier: fakeVerifier{}, Services: map[string]Service{
		"lookup.ct@1": {Tool: "ctlog", Run: func(_ context.Context, tenant, target string, input json.RawMessage) (any, error) {
			*calls = append(*calls, call{tenant, target, string(input)})
			if target == "fail.example" {
				return nil, errors.New("upstream text that never leaves")
			}
			return map[string]any{"records": []any{}}, nil
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func job(id, tenant, payload string) *Job {
	signed := `{"tenant":"` + tenant + `"}`
	if tenant == "" {
		signed = `{}`
	}
	return &Job{ID: id, Payload: json.RawMessage(payload), SignedJob: json.RawMessage(signed)}
}

const okPayload = `{"scanner":"ctlog","targets":["example.com"],"capability":"lookup.ct@1","input":{"domain":"example.com"}}`

func TestRunnerServesAndBindsTheTenant(t *testing.T) {
	p := &fakePlatform{results: map[string]Result{}}
	var calls []call
	r := newRunner(t, p, &calls)
	p.jobs = []*Job{job("j1", "tenant-a", okPayload)}
	served, err := r.RunOnce(context.Background())
	if err != nil || !served {
		t.Fatalf("served %v err %v", served, err)
	}
	if len(calls) != 1 || calls[0].tenant != "tenant-a" || calls[0].target != "example.com" {
		t.Fatalf("calls %+v", calls)
	}
	if res := p.results["j1"]; string(res.Output) != `{"records":[]}` || res.Refused != "" || res.Error != "" {
		t.Fatalf("result %+v", res)
	}
}

// SECURITY: nothing is asked upstream for a job this sensor must not run.
func TestRunnerRefuses(t *testing.T) {
	for name, j := range map[string]*Job{
		"unsigned":         job("j", "", okPayload),
		"platform tenant":  job("j", jobsig.PlatformTenantID, okPayload),
		"unknown field":    job("j", "t", `{"scanner":"ctlog","targets":["example.com"],"capability":"lookup.ct@1","input":{},"url":"x"}`),
		"other capability": job("j", "t", `{"scanner":"ctlog","targets":["example.com"],"capability":"scan.ports@1","input":{}}`),
		"other tool":       job("j", "t", `{"scanner":"nuclei","targets":["example.com"],"capability":"lookup.ct@1","input":{}}`),
		"two targets":      job("j", "t", `{"scanner":"ctlog","targets":["example.com","example.org"],"capability":"lookup.ct@1","input":{}}`),
		"no target":        job("j", "t", `{"scanner":"ctlog","targets":[],"capability":"lookup.ct@1","input":{}}`),
		"id too long":      job(string(make([]byte, MaxIDLength+1)), "t", okPayload),
	} {
		t.Run(name, func(t *testing.T) {
			p := &fakePlatform{results: map[string]Result{}, jobs: []*Job{j}}
			var calls []call
			r := newRunner(t, p, &calls)
			if _, err := r.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 0 {
				t.Fatalf("handler ran: %+v", calls)
			}
			if p.results[j.ID].Refused == "" {
				t.Fatalf("result %+v", p.results[j.ID])
			}
		})
	}
}

func TestRunnerReportsAShortErrorCode(t *testing.T) {
	p := &fakePlatform{results: map[string]Result{}}
	var calls []call
	r := newRunner(t, p, &calls)
	p.jobs = []*Job{job("j2", "t", `{"scanner":"ctlog","targets":["fail.example"],"capability":"lookup.ct@1","input":{}}`)}
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res := p.results["j2"]; res.Error != "failed" || res.Output != nil {
		t.Fatalf("result %+v", res)
	}
}

func TestNextPoll(t *testing.T) {
	r := &Runner{cfg: Config{Interval: 5 * time.Second}}
	if d := r.nextPoll(true, 0, nil); d != 0 {
		t.Errorf("after a job: %s", d)
	}
	if d := r.nextPoll(false, 30*time.Second, nil); d != 30*time.Second {
		t.Errorf("retry-after: %s", d)
	}
	if d := r.nextPoll(false, time.Hour, nil); d != maxPoll {
		t.Errorf("capped: %s", d)
	}
	if d := r.nextPoll(false, 0, errors.New("x")); d != 5*time.Second {
		t.Errorf("error: %s", d)
	}
}
