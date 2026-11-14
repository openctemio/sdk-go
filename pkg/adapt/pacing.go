package adapt

import "time"

// Pacing is how hard a scan works one target host: the one place a pacing
// level is written down. Each tool adapter maps it to its own flags (nuclei
// -rate-limit/-c/-bs/-mhe, httpx -rl/-t, katana -rl/-c, naabu -rate), so
// every tool runs a level the same way and a tool can be swapped without
// changing what a level means.
//
// A level is a default, never a ceiling a scan can pass: a value a person
// set in a settings layer (tenant, sensor, profile, scan) replaces the
// level's value for that key, and the operator's ceilings and the local
// policy cap the result last. Back-off on 429, 503, Retry-After and blocks
// (HostRate, ThrottleTally) applies at every level.
type Pacing struct {
	// Name is the level's name: "gentle", "standard" or "fast".
	Name string
	// TargetRPS is the most requests per second toward one host.
	TargetRPS int
	// StartRPS is where a host starts before anything was learned about it.
	StartRPS int
	// TargetInflight is the most requests in flight toward one host.
	TargetInflight int
	// ParallelHosts is how many hosts of one job may each get TargetRPS at
	// the same time. A tool whose rate flag is global to the process (nuclei
	// -rate-limit) gets TargetRPS × min(hosts, ParallelHosts) (JobRate).
	ParallelHosts int
	// SweepRPS and SweepInflight bound a tool that sends a few requests to
	// each of many hosts (an HTTP probe over a host list): its global rate
	// and its parallel workers. Each host gets only a handful of requests.
	SweepRPS      int
	SweepInflight int
	// ProbePPS is the most packets per second of a port scan (per sensor:
	// a SYN scan spreads over its targets, it does not hammer one host).
	ProbePPS int
	// RequestTimeout is the per-request timeout.
	RequestTimeout time.Duration
	// Retries is how often a failed request is retried.
	Retries int
	// HostErrorBudget is the per-host error budget handed to a tool that
	// keeps its own host breaker (nuclei -max-host-error).
	HostErrorBudget int
	// MaxBulkHosts bounds the hosts a template-driven tool works per
	// template at once (nuclei -bulk-size).
	MaxBulkHosts int
}

// The pacing levels. Why the values:
//
//   - Standard (the default): 20 requests/s and 8 in flight per host stay
//     under the usual per-client limits of web application firewalls and
//     rate limiters, so a scan does not trip the target's own protections
//     (which turns block and rate-limit pages into false matches). A job
//     over several hosts runs up to 8 of them at full rate (160/s in all).
//     An HTTP probe sweep keeps 50/s over 25 workers: each host gets one or
//     two requests. Ports: 300 packets/s. Timeout 10 s, 1 retry, and a host
//     error budget of 15 (8 checks in flight fail together on a host that
//     went away, so 15 is about two rounds of them).
//   - Gentle: for fragile or production applications; a quarter of
//     Standard per host.
//   - Fast: for a lab or staging host the tenant owns; above Standard only
//     with ownership evidence (the platform clamps it, never this table).
var (
	PacingGentle = Pacing{
		Name: "gentle", TargetRPS: 5, StartRPS: 2, TargetInflight: 2, ParallelHosts: 4,
		SweepRPS: 15, SweepInflight: 10, ProbePPS: 100,
		RequestTimeout: 15 * time.Second, Retries: 1, HostErrorBudget: 10, MaxBulkHosts: 10,
	}
	PacingStandard = Pacing{
		Name: "standard", TargetRPS: 20, StartRPS: 5, TargetInflight: 8, ParallelHosts: 8,
		SweepRPS: 50, SweepInflight: 25, ProbePPS: 300,
		RequestTimeout: 10 * time.Second, Retries: 1, HostErrorBudget: 15, MaxBulkHosts: 25,
	}
	PacingFast = Pacing{
		Name: "fast", TargetRPS: 100, StartRPS: 25, TargetInflight: 25, ParallelHosts: 8,
		SweepRPS: 150, SweepInflight: 50, ProbePPS: 1000,
		RequestTimeout: 10 * time.Second, Retries: 1, HostErrorBudget: 30, MaxBulkHosts: 25,
	}
)

// DefaultPacing is the level a scan runs at when nobody chose one.
var DefaultPacing = PacingStandard

// PacingFor returns the level named name ("" is DefaultPacing), and false
// for a name that is not a level.
func PacingFor(name string) (Pacing, bool) {
	switch name {
	case "":
		return DefaultPacing, true
	case PacingGentle.Name:
		return PacingGentle, true
	case PacingStandard.Name:
		return PacingStandard, true
	case PacingFast.Name:
		return PacingFast, true
	}
	return Pacing{}, false
}

// JobHosts bounds hosts to [1, ParallelHosts]: the hosts of a job that run
// at full per-host rate at once.
func (p Pacing) JobHosts(hosts int) int {
	return min(max(hosts, 1), max(p.ParallelHosts, 1))
}

// JobRate is the process-wide request rate of a tool whose rate flag is
// global (nuclei -rate-limit) for a job over hosts hosts: TargetRPS for
// each host it works at once, at most ParallelHosts of them.
func (p Pacing) JobRate(hosts int) int {
	return p.TargetRPS * p.JobHosts(hosts)
}

// BulkHosts is how many hosts a template-driven tool works per template
// (nuclei -bulk-size): the job's hosts, at most MaxBulkHosts, at least 1.
func (p Pacing) BulkHosts(hosts int) int {
	return min(max(hosts, 1), max(p.MaxBulkHosts, 1))
}
