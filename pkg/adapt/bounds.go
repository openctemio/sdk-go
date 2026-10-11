// Package adapt holds the sensor's adaptive controllers and the one table
// of their bounds (RFC-074 in openctemio/openctem api/docs/rfcs,
// RFC-074-adaptive-sensor-control.md).
//
// A controller moves a value from a measured signal, inside a floor and a
// ceiling. The ceiling is always the lowest of the limits a human or a
// policy set: a controller may go below it, never above. Every number a
// controller uses is in this file; code elsewhere refers to the table, never
// to a literal.
//
// Stability: Experimental (docs/STABILITY.md).
package adapt

import "time"

// TargetRateBounds bound the per-host request rate toward scan targets
// (HostRate). Rates are requests (connections, and requests on a connection
// the forwarder reads) per second.
type TargetRateBounds struct {
	// Floor is the lowest rate the controller paces a host at. A host that
	// still pushes back at the floor is reported as a coverage gap
	// (GapRateFloor) instead of being slowed further.
	Floor float64
	// DefaultCeiling is the ceiling when no limit was given at all (the
	// forwarder's historical default; never "unlimited").
	DefaultCeiling float64
	// StartFraction of the ceiling is where a host starts (slow start).
	StartFraction float64
	// Window is how often a host's rate is re-evaluated: a window with
	// answers and no push-back raises the rate.
	Window time.Duration
	// IncreaseFraction of the ceiling is added per clean window once slow
	// start ended (additive increase).
	IncreaseFraction float64
	// DecreaseFactor multiplies the rate on push-back (multiplicative
	// decrease), at most once per window.
	DecreaseFactor float64
	// BreakerFailures consecutive failures open a host's breaker.
	BreakerFailures int
	// BreakerOpen is how long a breaker stays open the first time; it
	// doubles on each further trip up to BreakerOpenMax.
	BreakerOpen    time.Duration
	BreakerOpenMax time.Duration
	// BreakerJitter spreads the open time by ± this fraction.
	BreakerJitter float64
	// BreakerMaxTrips trips give a host up for the rest of the task.
	BreakerMaxTrips int
	// ProbeTimeout is how long a half-open probe may stay unanswered before
	// another one is allowed.
	ProbeTimeout time.Duration
	// RetryAfterMax caps a target's Retry-After.
	RetryAfterMax time.Duration
	// HoldMax is the longest a connection is held to honor a Retry-After;
	// a longer one refuses connections to the host until it passes.
	HoldMax time.Duration
	// FloorStrikes push-backs while at the floor make a host a coverage gap
	// (GapRateFloor).
	FloorStrikes int
	// BlockRun consecutive 403 answers, from a host that answered otherwise
	// before, read as a block.
	BlockRun int
	// MaxHosts bounds the hosts one task tracks; further hosts share one
	// conservative state.
	MaxHosts int
	// MaxOpenPorts bounds the reachable ports remembered per host.
	MaxOpenPorts int
	// MaxGaps bounds the coverage gaps one result lists (the total is
	// still counted).
	MaxGaps int
	// MaxChanges bounds the rate changes one task logs.
	MaxChanges int
	// ToolHostErrors is the per-host error budget handed to a tool that
	// keeps its own host breaker (nuclei -max-host-error): errors on one
	// host, over all its requests, before the tool skips the host.
	ToolHostErrors int
}

// TargetRate is the table of target-rate bounds. Why each value:
//
//   - Floor 1/s: the slowest pace still useful for a scan in a job's time;
//     slower than that the result is reported as a gap, not stretched.
//   - DefaultCeiling 100/s: the forwarder's default before this controller.
//   - StartFraction 0.25: a new host is probed at a quarter of the ceiling;
//     doubling per clean window reaches the ceiling in two windows.
//   - Window 2s: several round trips to a distant host, and at least two
//     requests at the floor, so a window has evidence before it moves.
//   - IncreaseFraction 0.10, DecreaseFactor 0.5: additive increase of a
//     tenth of the ceiling per clean window, halving on push-back; one
//     decrease per window so the replies to a burst already in flight do
//     not collapse the rate.
//   - BreakerFailures 5, BreakerOpen 15s doubling to 2m, ±20 % jitter,
//     3 trips: a host that stops answering is left alone for a while and
//     probed once; after three trips (about 1.5 minutes of silence) it is a
//     coverage gap for the task.
//   - RetryAfterMax 5m: the same cap the control client honors.
//   - HoldMax 10s: within a tool's usual connect timeout; longer waits are
//     refused instead of hanging the tool.
//   - FloorStrikes 3, BlockRun 20: enough repetitions that one refusal or
//     a handful of forbidden paths do not count as a block.
//   - ToolHostErrors 30: a tool's own breaker counts every failed request
//     of every concurrent check (not consecutive failures), so it needs a
//     larger budget than BreakerFailures × BreakerMaxTrips (15); 30 lets a
//     few slow checks fail without dropping a live host.
var TargetRate = TargetRateBounds{
	Floor:            1,
	DefaultCeiling:   100,
	StartFraction:    0.25,
	Window:           2 * time.Second,
	IncreaseFraction: 0.10,
	DecreaseFactor:   0.5,
	BreakerFailures:  5,
	BreakerOpen:      15 * time.Second,
	BreakerOpenMax:   2 * time.Minute,
	BreakerJitter:    0.2,
	BreakerMaxTrips:  3,
	ProbeTimeout:     30 * time.Second,
	RetryAfterMax:    5 * time.Minute,
	HoldMax:          10 * time.Second,
	FloorStrikes:     3,
	BlockRun:         20,
	MaxHosts:         65536,
	MaxOpenPorts:     64,
	MaxGaps:          100,
	MaxChanges:       20,
	ToolHostErrors:   30,
}

// Ceiling is the lowest of the positive limits (a scan's rate_limit, a scan
// window's, a program rule's, the local policy's rate.max_rps, the sensor's
// own setting): the rate a controller never exceeds. Limits of zero or less
// are "not set"; with none set it is TargetRate.DefaultCeiling.
func Ceiling(limits ...float64) float64 {
	c := 0.0
	for _, l := range limits {
		if l > 0 && (c == 0 || l < c) {
			c = l
		}
	}
	if c == 0 {
		return TargetRate.DefaultCeiling
	}
	return c
}
