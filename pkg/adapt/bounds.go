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

// SharedRateBounds bound the sensor-wide state of SensorRate: what every
// task of the sensor shares about a target host.
type SharedRateBounds struct {
	// CooldownBase is how long a target is left alone after the first
	// edge block (a WAF or CDN block or challenge page, or a run of 403
	// answers); each further block of the same target doubles it, up to
	// CooldownMax.
	CooldownBase time.Duration
	CooldownMax  time.Duration
	// ShareIdle is how long a tenant that stopped asking for a host still
	// counts for the host's fair share.
	ShareIdle time.Duration
	// HostIdle is how long a host nobody asked for is kept (its rate, and
	// the cooldowns and Retry-After it set, once they passed).
	HostIdle time.Duration
	// MaxHosts bounds the hosts the sensor tracks; MaxTenantsPerHost the
	// tenants sharing one host. A task whose host or tenant does not fit
	// paces itself alone (as it did before the sensor-wide state): state is
	// never shared between hosts or tenants to make room.
	MaxHosts          int
	MaxTenantsPerHost int
}

// SharedRate is the table of sensor-wide bounds. Why each value:
//
//   - CooldownBase 15m doubling to CooldownMax 6h: an edge that blocked
//     the scanner's address keeps blocking it for a while; asking again at
//     once only deepens the block. Six hours bounds what a hostile target
//     can withhold from a tenant's scans (each cooldown is reported as a
//     coverage gap with its reason, never as "no findings").
//   - ShareIdle 30s: a few windows; a tenant whose tool pauses between
//     phases keeps its share.
//   - HostIdle 10m: long enough to carry what one task learned to the
//     next one on the same host.
//   - MaxHosts 65536, MaxTenantsPerHost 64: the per-task MaxHosts, and
//     more tenants on one target at once than a shared sensor runs.
var SharedRate = SharedRateBounds{
	CooldownBase:      15 * time.Minute,
	CooldownMax:       6 * time.Hour,
	ShareIdle:         30 * time.Second,
	HostIdle:          10 * time.Minute,
	MaxHosts:          65536,
	MaxTenantsPerHost: 64,
}

// SourcePaceBounds bound the request rate toward a system of record a
// collector or importer reads (an inventory API such as vCenter, a
// directory, a monitoring server): SourcePacer.
type SourcePaceBounds struct {
	// Floor is the slowest pace. A source still slow or busy at the floor
	// keeps being read at the floor; the caller's breaker and run budget
	// decide when to stop.
	Floor float64
	// DefaultCeiling is the ceiling when no limit was given.
	DefaultCeiling float64
	// StartFraction of the ceiling is where a new source starts.
	StartFraction float64
	// Window is how often the rate is re-evaluated, MinSamples the answers
	// a window needs before its latency counts.
	Window     time.Duration
	MinSamples int
	// IncreaseFraction of the ceiling is added per clean window;
	// DecreaseFactor multiplies the rate on push-back (at most once per
	// window).
	IncreaseFraction float64
	DecreaseFactor   float64
	// LatencyFactor: a window whose median latency is above this multiple
	// of the source's baseline (and above LatencyFloor) is push-back.
	LatencyFactor float64
	LatencyFloor  time.Duration
	// BaselineDrift is the fraction by which the baseline moves toward each
	// window's median when that median is higher: a source that became
	// slower for good becomes the new normal instead of being held at the
	// floor forever. A lower median replaces the baseline at once.
	BaselineDrift float64
	// MaxSamples bounds the latencies one window keeps.
	MaxSamples int
	// RetryAfterMax caps a source's Retry-After.
	RetryAfterMax time.Duration
}

// SourcePace is the table of source-pace bounds. Why each value:
//
//   - Floor 0.2/s: one request every five seconds still finishes a
//     paged inventory of ten thousand objects in minutes, and leaves a
//     struggling server essentially alone.
//   - DefaultCeiling 5/s: what an operator would accept from one read-only
//     account against a production vCenter or domain controller.
//   - StartFraction 0.5: a new source is read at half the ceiling until
//     its answers show it is healthy.
//   - Window 10s, MinSamples 3: at a few requests per second a window holds
//     enough answers for a median; one slow answer does not move the rate.
//   - IncreaseFraction 0.1, DecreaseFactor 0.5: additive increase, halving
//     on push-back (429, 503, a busy fault, a timeout, a reset, or the
//     latency signal), once per window.
//   - LatencyFactor 3, LatencyFloor 250ms: a server that answers three
//     times slower than its own normal is under load (a vpxd or DC at full
//     CPU slows down before it errors); answers under 250ms are fast
//     whatever their ratio.
//   - BaselineDrift 0.1: about twenty windows (a few minutes) for a source
//     that stays slower to become the new normal.
//   - RetryAfterMax 5m: the same cap HostRate and the control client honor.
var SourcePace = SourcePaceBounds{
	Floor:            0.2,
	DefaultCeiling:   5,
	StartFraction:    0.5,
	Window:           10 * time.Second,
	MinSamples:       3,
	IncreaseFraction: 0.1,
	DecreaseFactor:   0.5,
	LatencyFactor:    3,
	LatencyFloor:     250 * time.Millisecond,
	BaselineDrift:    0.1,
	MaxSamples:       64,
	RetryAfterMax:    5 * time.Minute,
}
