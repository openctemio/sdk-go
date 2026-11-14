package adapt

import (
	"testing"
	"time"
)

// The Standard level is the adopted default: 20 requests/s and 8 in flight
// per host, start at 5, host error budget 15.
func TestPacingStandardIsTheDefault(t *testing.T) {
	p, ok := PacingFor("")
	if !ok || p.Name != "standard" {
		t.Fatalf("PacingFor(\"\") = %+v, %v; want standard", p, ok)
	}
	want := Pacing{
		Name: "standard", TargetRPS: 20, StartRPS: 5, TargetInflight: 8, ParallelHosts: 8,
		SweepRPS: 50, SweepInflight: 25, ProbePPS: 300,
		RequestTimeout: 10 * time.Second, Retries: 1, HostErrorBudget: 15, MaxBulkHosts: 25,
	}
	if p != want {
		t.Fatalf("standard = %+v\nwant      %+v", p, want)
	}
}

func TestPacingFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		ok   bool
	}{
		{"", "standard", true},
		{"gentle", "gentle", true},
		{"standard", "standard", true},
		{"fast", "fast", true},
		{"Fast", "", false},
		{"insane", "", false},
	} {
		p, ok := PacingFor(tc.name)
		if ok != tc.ok || p.Name != tc.want {
			t.Errorf("PacingFor(%q) = %q, %v; want %q, %v", tc.name, p.Name, ok, tc.want, tc.ok)
		}
	}
}

// The levels are ordered: Gentle never works a host harder than Standard,
// Standard never harder than Fast, and every level backs off (it has a
// positive error budget and timeout).
func TestPacingLevelsAreOrdered(t *testing.T) {
	levels := []Pacing{PacingGentle, PacingStandard, PacingFast}
	for i, p := range levels {
		if p.TargetRPS <= 0 || p.StartRPS <= 0 || p.StartRPS > p.TargetRPS || p.TargetInflight <= 0 ||
			p.SweepRPS <= 0 || p.SweepInflight <= 0 || p.ProbePPS <= 0 || p.RequestTimeout <= 0 ||
			p.HostErrorBudget <= 0 || p.MaxBulkHosts <= 0 || p.ParallelHosts <= 0 {
			t.Errorf("%s has a value out of range: %+v", p.Name, p)
		}
		if i == 0 {
			continue
		}
		q := levels[i-1]
		if q.TargetRPS > p.TargetRPS || q.TargetInflight > p.TargetInflight || q.SweepRPS > p.SweepRPS ||
			q.ProbePPS > p.ProbePPS || q.JobRate(100) > p.JobRate(100) {
			t.Errorf("%s is harder than %s", q.Name, p.Name)
		}
	}
}

// A process-wide rate is the per-host rate times the hosts worked at once:
// one host gets exactly the per-host rate, never the whole job's.
func TestPacingJobRateAndBulk(t *testing.T) {
	p := PacingStandard
	for _, tc := range []struct {
		hosts, rate, bulk int
	}{
		{-3, 20, 1},
		{0, 20, 1},
		{1, 20, 1},
		{2, 40, 2},
		{8, 160, 8},
		{9, 160, 9},
		{25, 160, 25},
		{1000, 160, 25},
	} {
		if got := p.JobRate(tc.hosts); got != tc.rate {
			t.Errorf("JobRate(%d) = %d, want %d", tc.hosts, got, tc.rate)
		}
		if got := p.BulkHosts(tc.hosts); got != tc.bulk {
			t.Errorf("BulkHosts(%d) = %d, want %d", tc.hosts, got, tc.bulk)
		}
	}
	if got := (Pacing{}).JobRate(5); got != 0 {
		t.Errorf("zero level JobRate = %d, want 0", got)
	}
}
