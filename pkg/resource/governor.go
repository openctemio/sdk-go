package resource

// The governor (research/318 §6.1): it rates the host's pressure with
// hysteresis, holds tool launches while the host is overloaded, narrows the
// effective concurrency, scales the start handshake to the measured stall,
// and counts transient start failures for the heartbeat.
//
// It never decides where work goes: it only holds or narrows this sensor's
// own launches and reports why. The platform reads the report and places
// work (owner rule: the platform orchestrates, the sensor reports).

import (
	"context"
	"sync"
	"time"
)

// GovernorConfig configures a Governor. Zero fields take the defaults.
type GovernorConfig struct {
	// Bounds rate the signals (DefaultPressureBounds when zero).
	Bounds PressureBounds
	// ExitRatio scales the bounds a level must fall under before the
	// governor leaves it (default 0.7).
	ExitRatio float64
	// ExitProbes is how many consecutive probes under the scaled bounds
	// leave a level (default 2).
	ExitProbes int
	// Recheck is how often a held launch looks again (default the
	// manager's probe interval).
	Recheck time.Duration
	// OnHold is called once per held launch, with the level and reasons
	// that hold it (a command log line). It must not block.
	OnHold func(ctx context.Context, tool string, p Pressure)
}

// Transient start failure kinds (TransientCounts members; Governor.Transient).
const (
	TransientHandshakeTimeout = "handshake_timeout"
	TransientSlowStart        = "slow_start"
	TransientOOMKill          = "oom_kill"
	TransientStartEAGAIN      = "start_eagain"
	TransientRetried          = "retried"
	TransientRecovered        = "recovered"
)

// TransientCounts are the transient start failures since the sensor
// started, as a heartbeat carries them in capacity.transient.
type TransientCounts struct {
	HandshakeTimeouts uint64 `json:"handshake_timeouts"`
	SlowStarts        uint64 `json:"slow_starts"`
	OOMKills          uint64 `json:"oom_kills"`
	StartEAGAIN       uint64 `json:"start_eagain"`
	// Retried is how many failed starts were tried once more; Recovered how
	// many of those then succeeded.
	Retried   uint64 `json:"retried"`
	Recovered uint64 `json:"recovered"`
}

// Governor holds and narrows tool launches under host pressure. The zero
// value is not usable; a Manager creates one (Manager.Governor). Safe for
// concurrent use.
type Governor struct {
	cfg     GovernorConfig
	bounds  PressureBounds
	exit    PressureBounds
	refresh func() ProbeResult
	now     func() time.Time
	// slots is the manager's current slot count (the elevated limit is
	// half of it).
	slots func() int

	mu        sync.Mutex
	level     PressureLevel
	since     time.Time
	quiet     int
	last      PressureSignals
	reasons   []string
	running   int
	held      int
	wake      chan struct{}
	transient TransientCounts
}

func newGovernor(cfg GovernorConfig, refresh func() ProbeResult, now func() time.Time, slots func() int, probeInterval time.Duration) *Governor {
	if cfg.ExitRatio <= 0 || cfg.ExitRatio >= 1 {
		cfg.ExitRatio = 0.7
	}
	if cfg.ExitProbes <= 0 {
		cfg.ExitProbes = 2
	}
	if cfg.Recheck <= 0 {
		cfg.Recheck = probeInterval
	}
	b := cfg.Bounds.orDefault()
	return &Governor{cfg: cfg, bounds: b, exit: b.scaled(cfg.ExitRatio), refresh: refresh, now: now, slots: slots,
		level: PressureOK, wake: make(chan struct{})}
}

// observe rates a fresh probe: a higher level is entered at once; a level
// is left only after ExitProbes consecutive probes under the scaled bounds.
func (g *Governor) observe(s PressureSignals) {
	raw, reasons := g.bounds.rate(s)
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.last = s
	prev := g.level
	switch {
	case raw.rank() >= g.level.rank():
		if raw.rank() > g.level.rank() {
			g.level = raw
		}
		g.quiet = 0
	default:
		exitLevel, _ := g.exit.rate(s)
		if exitLevel.rank() < g.level.rank() {
			g.quiet++
			if g.quiet >= g.cfg.ExitProbes {
				g.level = levelOfRank(max(exitLevel.rank(), raw.rank()))
				g.quiet = 0
			}
		} else {
			g.quiet = 0
		}
	}
	if len(reasons) == 0 && g.level != PressureOK {
		// Held by hysteresis: name what keeps it above the exit bounds.
		_, reasons = g.exit.rate(s)
	}
	g.reasons = reasons
	if g.level != prev || g.since.IsZero() {
		g.since = now
	}
	if g.level.rank() < prev.rank() {
		g.broadcastLocked()
	}
}

func (g *Governor) broadcastLocked() {
	close(g.wake)
	g.wake = make(chan struct{})
}

// Level is the current pressure level (from the last probe).
func (g *Governor) Level() PressureLevel {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.level
}

// Pressure is the heartbeat's pressure picture.
func (g *Governor) Pressure() Pressure {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pressureLocked()
}

func (g *Governor) pressureLocked() Pressure {
	s := g.last
	p := Pressure{
		Level: g.level, Reasons: append([]string(nil), g.reasons...), PSI: s.PSI,
		CPUSome10: s.CPUSome10, MemSome10: s.MemSome10, MemFull10: s.MemFull10,
		IOSome10: s.IOSome10, IOFull10: s.IOFull10, CPUThrottledPct: s.CPUThrottledPct,
		LoadPerCPU: round2(s.LoadPerCPU), FDUsedPct: round1(s.FDUsedPct),
		HostCPUBusyPct: s.HostCPUBusyPct, ForeignCPUPct: s.ForeignCPUPct,
	}
	if !g.since.IsZero() {
		p.LevelSeconds = int64(g.now().Sub(g.since) / time.Second)
	}
	p.NoisyNeighbor = s.ForeignKnown && g.level != PressureOK && s.ForeignCPUPct >= NoisyNeighborForeignPct
	return p
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// limitLocked is how many tools may run at the current level: no limit of
// its own when ok (the slots bound the jobs), the manager's slot count
// (already halved for the level) when elevated, one when overloaded.
func (g *Governor) limitLocked() int {
	switch g.level {
	case PressureElevated:
		if g.slots != nil {
			return max(g.slots(), 1)
		}
		return 1
	case PressureOverloaded:
		return 1
	}
	return int(^uint(0) >> 1)
}

// Admit is called right before a tool process starts. It returns at once
// when the host is ok, or when it is elevated and fewer tools run than the
// elevated limit. While the host is overloaded it holds the launch until
// the level drops or ctx ends, except when no tool of this sensor runs:
// one tool always runs, so a host loaded by others for good still makes
// progress one tool at a time. release must be called when the process
// has ended. held is how long the launch waited.
func (g *Governor) Admit(ctx context.Context, tool string) (release func(), held time.Duration, err error) {
	start := g.now()
	waiting := false
	defer func() {
		if waiting {
			g.mu.Lock()
			g.held--
			g.mu.Unlock()
		}
	}()
	for {
		if g.refresh != nil {
			g.refresh()
		}
		g.mu.Lock()
		if g.running == 0 || g.running < g.limitLocked() {
			g.running++
			g.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					g.mu.Lock()
					g.running--
					g.broadcastLocked()
					g.mu.Unlock()
				})
			}, g.now().Sub(start), nil
		}
		wake := g.wake
		first := !waiting
		if first {
			waiting = true
			g.held++
		}
		p := g.pressureLocked()
		g.mu.Unlock()
		if first && g.cfg.OnHold != nil {
			g.cfg.OnHold(ctx, tool, p)
		}
		t := time.NewTimer(g.cfg.Recheck)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, g.now().Sub(start), ctx.Err()
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// Running is how many admitted tools have not been released.
func (g *Governor) Running() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.running
}

// Held is how many launches wait now.
func (g *Governor) Held() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.held
}

// Bounds of the start timeout factor.
const (
	MinStartFactor = 1.0
	MaxStartFactor = 4.0
)

// StartTimeoutFactor is what a tool's start handshake timeout is
// multiplied by now: 1 when ok, 2 when elevated, 4 when overloaded, or
// 1/(1 - CPU stall share) when that is larger, within [1, 4].
func (g *Governor) StartTimeoutFactor() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := MinStartFactor
	switch g.level {
	case PressureElevated:
		f = 2
	case PressureOverloaded:
		f = MaxStartFactor
	}
	if g.last.PSI && g.last.CPUSome10 > 0 {
		stall := min(g.last.CPUSome10, 99) / 100
		f = max(f, 1/(1-stall))
	}
	return min(max(f, MinStartFactor), MaxStartFactor)
}

// Transient counts a transient start failure, a retry or a recovery (the
// Transient* kinds). Unknown kinds are ignored.
func (g *Governor) Transient(kind string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := &g.transient
	switch kind {
	case TransientHandshakeTimeout:
		t.HandshakeTimeouts++
	case TransientSlowStart:
		t.SlowStarts++
	case TransientOOMKill:
		t.OOMKills++
	case TransientStartEAGAIN:
		t.StartEAGAIN++
	case TransientRetried:
		t.Retried++
	case TransientRecovered:
		t.Recovered++
	}
}

// TransientCounts returns the counters.
func (g *Governor) TransientCounts() TransientCounts {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.transient
}
