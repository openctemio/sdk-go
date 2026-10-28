package resource

// Host pressure (research/318): how much the host stalls the sensor's work,
// not how much of it is in use. A host can show plausible CPU and memory
// use while every runnable task waits for a CPU, for the disk or for memory
// reclaim, typically because other heavy programs share it. A tool started
// into that stall cannot even complete its start handshake.
//
// Signals, each optional (an unreadable file is unknown and never raises
// the level):
//
//   - Linux PSI (pressure stall information) for cpu, memory and io: the
//     host's /proc/pressure files, which a container sees unnamespaced, and
//     the sensor's own cgroup's *.pressure files; the larger value counts;
//   - load per CPU (load1 over the host's CPUs), only where PSI is missing;
//   - available memory as a share of what the sensor may use;
//   - open file descriptors: the sensor's own against its limit, and the
//     host's table;
//   - foreign CPU: the host's busy CPU minus what the sensor's cgroup (the
//     sensor and its tools) used, the noisy-neighbor signal.

import (
	"os"
	"strconv"
	"strings"
)

// PressureLevel is the host's pressure as the governor rates it.
type PressureLevel string

// Pressure levels, in increasing order.
const (
	PressureOK         PressureLevel = "ok"
	PressureElevated   PressureLevel = "elevated"
	PressureOverloaded PressureLevel = "overloaded"
)

func (l PressureLevel) rank() int {
	switch l {
	case PressureElevated:
		return 1
	case PressureOverloaded:
		return 2
	}
	return 0
}

func levelOfRank(r int) PressureLevel {
	switch r {
	case 1:
		return PressureElevated
	case 2:
		return PressureOverloaded
	}
	return PressureOK
}

// Pressure reasons: the signals over their bound (closed set, wire values).
const (
	ReasonCPU          = "cpu"
	ReasonMemory       = "memory"
	ReasonIO           = "io"
	ReasonLoad         = "load"
	ReasonMemAvailable = "mem_available"
	ReasonFDs          = "fds"
)

// NoisyNeighborForeignPct is the share of the host's CPU that processes
// outside the sensor must use, while the host is pressured, for the
// heartbeat to flag a noisy neighbor.
const NoisyNeighborForeignPct = 50

// Pressure is the pressure picture a heartbeat carries as
// resources.pressure. Percentages are 0-100.
type Pressure struct {
	Level PressureLevel `json:"level"`
	// Reasons are the signals over their bound now.
	Reasons []string `json:"reasons,omitempty"`
	// LevelSeconds is how long the host has been at Level.
	LevelSeconds int64 `json:"level_seconds,omitempty"`
	// PSI says whether the kernel's pressure stall information was read.
	PSI       bool    `json:"psi"`
	CPUSome10 float64 `json:"cpu_some_avg10"`
	MemSome10 float64 `json:"mem_some_avg10"`
	MemFull10 float64 `json:"mem_full_avg10"`
	IOSome10  float64 `json:"io_some_avg10"`
	IOFull10  float64 `json:"io_full_avg10"`
	// CPUThrottledPct is the share of CPU periods in which the sensor's
	// cgroup was held back by its CPU quota.
	CPUThrottledPct float64 `json:"cpu_throttled_pct"`
	// LoadPerCPU is the one-minute load average over the host's CPUs.
	LoadPerCPU float64 `json:"load_per_cpu"`
	// FDUsedPct is the larger of the sensor's open descriptors against its
	// limit and the host's descriptor table.
	FDUsedPct float64 `json:"fd_used_pct"`
	// HostCPUBusyPct is how busy the whole host's CPU was.
	HostCPUBusyPct float64 `json:"host_cpu_busy_pct"`
	// ForeignCPUPct is the share of the host's CPU used by processes
	// outside the sensor and its tools.
	ForeignCPUPct float64 `json:"foreign_cpu_pct"`
	// NoisyNeighbor is set when the host is pressured and processes
	// outside the sensor use most of its CPU.
	NoisyNeighbor bool `json:"noisy_neighbor"`
}

// PressureSignals are the raw readings of one probe. A value whose Known
// flag is false was not readable.
type PressureSignals struct {
	PSI                           bool
	CPUSome10, MemSome10          float64
	MemFull10, IOSome10, IOFull10 float64
	LoadPerCPU                    float64
	LoadKnown                     bool
	MemAvailPct                   float64
	MemKnown                      bool
	FDUsedPct                     float64
	FDKnown                       bool
	HostCPUBusyPct, ForeignCPUPct float64
	HostCPUKnown, ForeignKnown    bool
	// CPUThrottledPct is the share of CPU periods in which the sensor's
	// cgroup was held back by its own CPU quota. PSI does not count a
	// throttled task as waiting, yet a tool starting in a throttled cgroup
	// stalls the same way.
	CPUThrottledPct float64
	ThrottleKnown   bool
	hostCPUs        int
}

// psi reads a PSI file ("some avg10=… …\nfull avg10=… …") and returns the
// some and full ten-second averages.
func parsePSI(s string) (some, full float64, ok bool) {
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, found := strings.CutPrefix(f[1], "avg10=")
		if !found {
			continue
		}
		x, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "some":
			some, ok = x, true
		case "full":
			full = x
		}
	}
	return min(max(some, 0), 100), min(max(full, 0), 100), ok
}

// psi returns the larger of the host's and the cgroup's PSI averages for a
// resource ("cpu", "memory", "io").
func (p *Prober) psi(cg cgroup, res string) (some, full float64, ok bool) {
	if s, found := p.read("proc", "pressure", res); found {
		some, full, ok = parsePSI(s)
	}
	if s, found := cg.readV2(res + ".pressure"); found {
		if cs, cf, cok := parsePSI(s); cok {
			some, full, ok = max(some, cs), max(full, cf), true
		}
	}
	return some, full, ok
}

// hostCPUs counts the host's CPUs in /proc/stat ("cpuN" lines); 0 when
// unknown.
func (p *Prober) hostCPUs() int {
	s, ok := p.read("proc", "stat")
	if !ok {
		return 0
	}
	n := 0
	for line := range strings.SplitSeq(s, "\n") {
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	return n
}

// fdUsedPct is the larger of the process's open descriptors against its
// soft limit and the host's allocated descriptors against the host's
// maximum.
func (p *Prober) fdUsedPct() (float64, bool) {
	pct, known := 0.0, false
	if p.FDLimit != nil || p.Root == "" || p.Root == "/" {
		limit := fdSoftLimit()
		if p.FDLimit != nil {
			limit = p.FDLimit()
		}
		if entries, err := os.ReadDir(p.path("proc", "self", "fd")); err == nil && limit > 0 {
			pct, known = 100*float64(len(entries))/float64(limit), true
		}
	}
	if s, ok := p.read("proc", "sys", "fs", "file-nr"); ok {
		f := strings.Fields(s)
		if len(f) == 3 {
			used, err1 := strconv.ParseFloat(f[0], 64)
			limit, err2 := strconv.ParseFloat(f[2], 64)
			if err1 == nil && err2 == nil && limit > 0 {
				pct, known = max(pct, 100*used/limit), true
			}
		}
	}
	return min(pct, 100), known
}

// signals reads the pressure signals of a probe. cur and prev are the CPU
// samples of this probe and the one before (prev nil on the first probe:
// the CPU shares are then unknown).
func (p *Prober) signals(cg cgroup, res HostResources, cur, prev *cpuSample) PressureSignals {
	var s PressureSignals
	var ok bool
	if s.CPUSome10, _, ok = p.psi(cg, "cpu"); ok {
		s.PSI = true
	}
	if s.MemSome10, s.MemFull10, ok = p.psi(cg, "memory"); ok {
		s.PSI = true
	}
	if s.IOSome10, s.IOFull10, ok = p.psi(cg, "io"); ok {
		s.PSI = true
	}
	s.hostCPUs = p.hostCPUs()
	if cpus := s.hostCPUs; cpus > 0 && res.Load1 > 0 {
		s.LoadPerCPU, s.LoadKnown = res.Load1/float64(cpus), true
	} else if cpus > 0 {
		// A load of exactly 0 is an idle host, not an unknown one, when the
		// file was read.
		if _, read := p.read("proc", "loadavg"); read {
			s.LoadKnown = true
		}
	}
	if res.MemTotalBytes > 0 {
		s.MemAvailPct, s.MemKnown = 100*float64(res.MemAvailableBytes)/float64(res.MemTotalBytes), true
	}
	s.FDUsedPct, s.FDKnown = p.fdUsedPct()
	if prev != nil && cur.hostTotal > prev.hostTotal {
		busy := float64(cur.hostBusy-prev.hostBusy) / float64(cur.hostTotal-prev.hostTotal)
		s.HostCPUBusyPct, s.HostCPUKnown = pct(busy), true
		wall := cur.at.Sub(prev.at).Seconds()
		if s.hostCPUs > 0 && wall > 0 && cur.cgroupSec >= 0 && prev.cgroupSec >= 0 {
			hostBusyCores := busy * float64(s.hostCPUs)
			ownCores := (cur.cgroupSec - prev.cgroupSec) / wall
			s.ForeignCPUPct, s.ForeignKnown = pct(max(hostBusyCores-ownCores, 0)/float64(s.hostCPUs)), true
		}
	}
	return s
}

// PressureBound is one signal's elevated and overloaded bounds.
type PressureBound struct{ Elevated, Overloaded float64 }

// PressureBounds are the bounds the governor rates signals against. A zero
// bound disables its level for that signal.
type PressureBounds struct {
	CPUSome PressureBound
	// CPUThrottled rates CPUThrottledPct.
	CPUThrottled PressureBound
	MemSome      PressureBound
	MemFull      PressureBound
	IOSome       PressureBound
	IOFull       PressureBound
	LoadPerCPU   PressureBound
	// MemAvailLow is inverted: the level is reached when available memory
	// falls BELOW the bound (percent of what the sensor may use).
	MemAvailLow PressureBound
	FDUsed      PressureBound
}

// DefaultPressureBounds are the bounds research/318 §5 sets: a CPU stall
// share of 40 % is elevated, 75 % overloaded; memory and I/O stalls weigh
// more because a stalled page-in or reclaim stops a start outright.
func DefaultPressureBounds() PressureBounds {
	return PressureBounds{
		CPUSome:      PressureBound{40, 75},
		CPUThrottled: PressureBound{30, 60},
		MemSome:      PressureBound{10, 30},
		MemFull:      PressureBound{2, 10},
		IOSome:       PressureBound{40, 70},
		IOFull:       PressureBound{10, 30},
		LoadPerCPU:   PressureBound{1.5, 3},
		MemAvailLow:  PressureBound{15, 5},
		FDUsed:       PressureBound{80, 95},
	}
}

func (b PressureBounds) orDefault() PressureBounds {
	if b == (PressureBounds{}) {
		return DefaultPressureBounds()
	}
	return b
}

// scaled returns the bounds with every bound moved toward "quiet" by ratio
// (0-1): ratio of an upper bound, or the inverse for the inverted one. The
// governor leaves a level only below the scaled bounds (hysteresis).
func (b PressureBounds) scaled(ratio float64) PressureBounds {
	up := func(x PressureBound) PressureBound { return PressureBound{x.Elevated * ratio, x.Overloaded * ratio} }
	inv := func(x PressureBound) PressureBound {
		if ratio <= 0 {
			return x
		}
		return PressureBound{x.Elevated / ratio, x.Overloaded / ratio}
	}
	return PressureBounds{
		CPUSome: up(b.CPUSome), CPUThrottled: up(b.CPUThrottled), MemSome: up(b.MemSome), MemFull: up(b.MemFull),
		IOSome: up(b.IOSome), IOFull: up(b.IOFull), LoadPerCPU: up(b.LoadPerCPU),
		MemAvailLow: inv(b.MemAvailLow), FDUsed: up(b.FDUsed),
	}
}

// rate returns the level the signals reach against the bounds and the
// reasons (signals at or over their elevated bound), in a fixed order.
func (b PressureBounds) rate(s PressureSignals) (PressureLevel, []string) {
	rank := 0
	var reasons []string
	over := func(v float64, bd PressureBound) int {
		switch {
		case bd.Overloaded > 0 && v >= bd.Overloaded:
			return 2
		case bd.Elevated > 0 && v >= bd.Elevated:
			return 1
		}
		return 0
	}
	under := func(v float64, bd PressureBound) int {
		switch {
		case bd.Overloaded > 0 && v < bd.Overloaded:
			return 2
		case bd.Elevated > 0 && v < bd.Elevated:
			return 1
		}
		return 0
	}
	add := func(r int, reason string) {
		if r == 0 {
			return
		}
		rank = max(rank, r)
		if len(reasons) == 0 || reasons[len(reasons)-1] != reason {
			reasons = append(reasons, reason)
		}
	}
	cpu := 0
	if s.ThrottleKnown {
		cpu = over(s.CPUThrottledPct, b.CPUThrottled)
	}
	if s.PSI {
		add(max(cpu, over(s.CPUSome10, b.CPUSome)), ReasonCPU)
		add(max(over(s.MemSome10, b.MemSome), over(s.MemFull10, b.MemFull)), ReasonMemory)
		add(max(over(s.IOSome10, b.IOSome), over(s.IOFull10, b.IOFull)), ReasonIO)
	} else {
		add(cpu, ReasonCPU)
		if s.LoadKnown {
			// Without PSI the load average is the only host stall signal
			// (research/318 D1).
			add(over(s.LoadPerCPU, b.LoadPerCPU), ReasonLoad)
		}
	}
	if s.MemKnown {
		add(under(s.MemAvailPct, b.MemAvailLow), ReasonMemAvailable)
	}
	if s.FDKnown {
		add(over(s.FDUsedPct, b.FDUsed), ReasonFDs)
	}
	return levelOfRank(rank), reasons
}
