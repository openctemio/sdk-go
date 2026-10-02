package resource

// Host resources as a sensor reports them to the platform (api RFC-030):
// what this sensor may actually use, which inside a container is the
// cgroup's share, not the machine's. Linux cgroup v2 and v1 are read; on
// other systems, or when a file is missing, the probe falls back to what
// the Go runtime knows (CPU count) and leaves the rest 0 (unknown).

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostResources is the resource snapshot a heartbeat carries as
// "resources". 0 means unknown, except CPUUsedPct (0-100, 0 on the first
// probe: usage needs two samples).
type HostResources struct {
	// CPUCores is the CPU this sensor may use: the online CPUs, narrowed by
	// the cgroup's cpuset and CPU quota (cpu.max / cfs_quota_us).
	CPUCores float64 `json:"cpu_cores"`
	// CPUUsedPct is how busy that CPU was since the previous probe, 0-100:
	// the cgroup's usage against its quota when it has one, else the host's.
	CPUUsedPct float64 `json:"cpu_used_pct"`
	// MemTotalBytes is the memory this sensor may use: the host's, or the
	// cgroup's limit when lower.
	MemTotalBytes int64 `json:"mem_total_bytes"`
	// MemAvailableBytes is what is left of it now (page cache that can be
	// reclaimed counts as available).
	MemAvailableBytes int64 `json:"mem_available_bytes"`
	// Load1 is the host's one-minute load average.
	Load1 float64 `json:"load1"`
	// DiskFreeBytes is the space available to the sensor on its work
	// directory's file system.
	DiskFreeBytes int64 `json:"disk_free_bytes"`
}

// ProbeResult is one probe: the snapshot plus the pressure signals seen
// since the previous probe.
type ProbeResult struct {
	Resources HostResources
	// ThrottledRatio is the share of CPU periods (0-1) in which the cgroup
	// was throttled by its quota since the previous probe.
	ThrottledRatio float64
	// OOMKills is how many processes the cgroup's OOM killer ended since the
	// previous probe.
	OOMKills uint64
}

// Prober reads the host's resources. The zero value probes the running
// system; tests set Root to a directory holding proc/ and sys/fs/cgroup/
// fixtures. Safe for concurrent use.
type Prober struct {
	// Root is prepended to /proc and /sys paths ("" or "/": the real ones).
	Root string
	// WorkDir is the directory whose file system DiskFreeBytes reports
	// ("" skips it).
	WorkDir string
	// NumCPU returns the CPUs the process may run on (default
	// runtime.NumCPU).
	NumCPU func() int
	// DiskFree returns the bytes available on dir's file system (default:
	// statfs; 0 where unsupported).
	DiskFree func(dir string) int64
	// Now is the clock (default time.Now).
	Now func() time.Time

	mu   sync.Mutex
	prev *cpuSample
}

type cpuSample struct {
	at        time.Time
	cgroupSec float64 // cgroup CPU usage, seconds (-1: unknown)
	hostBusy  uint64  // /proc/stat busy jiffies
	hostTotal uint64  // /proc/stat total jiffies
	periods   uint64
	throttled uint64
	oomKills  uint64
	hasOOM    bool
}

// noLimit is what cgroup v1 reports for "no memory limit" (a page-rounded
// MaxInt64); anything at or above it is no limit.
const noLimit = int64(math.MaxInt64 / 2)

// Probe takes a snapshot.
func (p *Prober) Probe() ProbeResult {
	cg := p.cgroup()
	now := p.now()

	res := HostResources{CPUCores: p.cpuCores(cg)}

	hostTotal, hostAvail := p.meminfo()
	res.MemTotalBytes, res.MemAvailableBytes = hostTotal, hostAvail
	if limit, used, ok := cg.memory(); ok && limit > 0 && limit < noLimit && (hostTotal == 0 || limit < hostTotal) {
		res.MemTotalBytes = limit
		avail := max(limit-used, 0)
		if hostAvail > 0 {
			avail = min(avail, hostAvail)
		}
		res.MemAvailableBytes = avail
	}
	res.Load1 = p.load1()
	if p.WorkDir != "" {
		if p.DiskFree != nil {
			res.DiskFreeBytes = p.DiskFree(p.WorkDir)
		} else {
			res.DiskFreeBytes = diskFree(p.WorkDir)
		}
	}

	cur := &cpuSample{at: now, cgroupSec: cg.cpuUsageSeconds()}
	cur.hostBusy, cur.hostTotal = p.procStat()
	cur.periods, cur.throttled = cg.throttling()
	cur.oomKills, cur.hasOOM = cg.oomKills()

	out := ProbeResult{}
	p.mu.Lock()
	prev := p.prev
	p.prev = cur
	p.mu.Unlock()
	if prev != nil {
		quota := cg.cpuQuota() > 0
		wall := cur.at.Sub(prev.at).Seconds()
		switch {
		case quota && cur.cgroupSec >= 0 && prev.cgroupSec >= 0 && wall > 0 && res.CPUCores > 0:
			res.CPUUsedPct = pct((cur.cgroupSec - prev.cgroupSec) / (wall * res.CPUCores))
		case cur.hostTotal > prev.hostTotal:
			res.CPUUsedPct = pct(float64(cur.hostBusy-prev.hostBusy) / float64(cur.hostTotal-prev.hostTotal))
		}
		if cur.periods > prev.periods {
			out.ThrottledRatio = float64(cur.throttled-prev.throttled) / float64(cur.periods-prev.periods)
		}
		if cur.hasOOM && prev.hasOOM && cur.oomKills > prev.oomKills {
			out.OOMKills = cur.oomKills - prev.oomKills
		}
	}
	out.Resources = res
	return out
}

func pct(ratio float64) float64 {
	return math.Round(min(max(ratio, 0), 1)*1000) / 10
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Prober) path(parts ...string) string {
	root := p.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func (p *Prober) read(parts ...string) (string, bool) {
	b, err := os.ReadFile(p.path(parts...))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func (p *Prober) cpuCores(cg cgroup) float64 {
	n := runtime.NumCPU()
	if p.NumCPU != nil {
		n = p.NumCPU()
	}
	cores := float64(n)
	if set := cg.cpusetCount(); set > 0 && float64(set) < cores {
		cores = float64(set)
	}
	if q := cg.cpuQuota(); q > 0 && q < cores {
		cores = q
	}
	return math.Round(cores*100) / 100
}

// meminfo returns MemTotal and MemAvailable in bytes.
func (p *Prober) meminfo() (total, avail int64) {
	s, ok := p.read("proc", "meminfo")
	if !ok {
		return 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return total, avail
}

func (p *Prober) load1() float64 {
	s, ok := p.read("proc", "loadavg")
	if !ok {
		return 0
	}
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// procStat returns the busy and total jiffies of the "cpu" line.
func (p *Prober) procStat() (busy, total uint64) {
	s, ok := p.read("proc", "stat")
	if !ok {
		return 0, 0
	}
	line, _, _ := strings.Cut(s, "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0
	}
	var idle uint64
	for i, x := range f[1:] {
		v, err := strconv.ParseUint(x, 10, 64)
		if err != nil {
			continue
		}
		if i >= 8 { // guest, guest_nice are already counted in user/nice
			break
		}
		total += v
		if i == 3 || i == 4 { // idle, iowait
			idle += v
		}
	}
	return total - idle, total
}

// =============================================================================
// cgroups
// =============================================================================

// cgroup reads one cgroup's files: v2 (unified) or v1 (per controller).
type cgroup struct {
	p  *Prober
	v2 string // v2 directory ("" when not v2)
	v1 bool
}

func (p *Prober) cgroup() cgroup {
	base := p.path("sys", "fs", "cgroup")
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err == nil {
		dir := base
		// The process's own cgroup ("0::/path"); inside a container with a
		// cgroup namespace it is "/" and the mount is the container's.
		if s, ok := p.read("proc", "self", "cgroup"); ok {
			for line := range strings.SplitSeq(s, "\n") {
				if rest, ok := strings.CutPrefix(line, "0::"); ok && rest != "/" && rest != "" {
					cand := filepath.Join(base, filepath.Clean("/"+rest))
					if _, err := os.Stat(cand); err == nil {
						dir = cand
					}
				}
			}
		}
		return cgroup{p: p, v2: dir}
	}
	if _, err := os.Stat(filepath.Join(base, "memory")); err == nil {
		return cgroup{p: p, v1: true}
	}
	if _, err := os.Stat(filepath.Join(base, "cpu")); err == nil {
		return cgroup{p: p, v1: true}
	}
	return cgroup{p: p}
}

func (c cgroup) readV2(name string) (string, bool) {
	if c.v2 == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(c.v2, name))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// readV1 reads a v1 controller file; controllers may be co-mounted
// ("cpu,cpuacct").
func (c cgroup) readV1(name string, controllers ...string) (string, bool) {
	if !c.v1 {
		return "", false
	}
	for _, ctl := range controllers {
		if s, ok := c.p.read("sys", "fs", "cgroup", ctl, name); ok {
			return s, true
		}
	}
	return "", false
}

// cpuQuota is the CPU limit in cores; 0 when unlimited or unknown.
func (c cgroup) cpuQuota() float64 {
	if s, ok := c.readV2("cpu.max"); ok {
		f := strings.Fields(s)
		if len(f) == 2 && f[0] != "max" {
			q, err1 := strconv.ParseFloat(f[0], 64)
			per, err2 := strconv.ParseFloat(f[1], 64)
			if err1 == nil && err2 == nil && q > 0 && per > 0 {
				return q / per
			}
		}
		return 0
	}
	qs, ok1 := c.readV1("cpu.cfs_quota_us", "cpu", "cpu,cpuacct", "cpuacct,cpu")
	ps, ok2 := c.readV1("cpu.cfs_period_us", "cpu", "cpu,cpuacct", "cpuacct,cpu")
	if ok1 && ok2 {
		q, err1 := strconv.ParseFloat(qs, 64)
		per, err2 := strconv.ParseFloat(ps, 64)
		if err1 == nil && err2 == nil && q > 0 && per > 0 {
			return q / per
		}
	}
	return 0
}

// cpusetCount is the number of CPUs in the cgroup's cpuset; 0 when unknown.
func (c cgroup) cpusetCount() int {
	if s, ok := c.readV2("cpuset.cpus.effective"); ok {
		return cpuListCount(s)
	}
	if s, ok := c.readV1("cpuset.effective_cpus", "cpuset"); ok {
		return cpuListCount(s)
	}
	if s, ok := c.readV1("cpuset.cpus", "cpuset"); ok {
		return cpuListCount(s)
	}
	return 0
}

// cpuListCount counts a kernel CPU list ("0-3,6,8-9").
func cpuListCount(s string) int {
	n := 0
	for part := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return 0
		}
		if !isRange {
			n++
			continue
		}
		b, err := strconv.Atoi(hi)
		if err != nil || b < a {
			return 0
		}
		n += b - a + 1
	}
	return n
}

// memory returns the limit and the usage that cannot be reclaimed (usage
// minus inactive page cache), in bytes. ok is false without a memory cgroup.
func (c cgroup) memory() (limit, used int64, ok bool) {
	if s, ok2 := c.readV2("memory.max"); ok2 {
		if s == "max" {
			return 0, 0, false
		}
		limit, _ = strconv.ParseInt(s, 10, 64)
		cur, _ := c.readV2("memory.current")
		usage, _ := strconv.ParseInt(cur, 10, 64)
		stat, _ := c.readV2("memory.stat")
		return limit, max(usage-statValue(stat, "inactive_file"), 0), limit > 0
	}
	ls, ok1 := c.readV1("memory.limit_in_bytes", "memory")
	if !ok1 {
		return 0, 0, false
	}
	limit, _ = strconv.ParseInt(ls, 10, 64)
	us, _ := c.readV1("memory.usage_in_bytes", "memory")
	usage, _ := strconv.ParseInt(us, 10, 64)
	stat, _ := c.readV1("memory.stat", "memory")
	return limit, max(usage-statValue(stat, "total_inactive_file"), 0), limit > 0
}

// cpuUsageSeconds is the cgroup's total CPU time; -1 when unknown.
func (c cgroup) cpuUsageSeconds() float64 {
	if s, ok := c.readV2("cpu.stat"); ok {
		if v := statValue(s, "usage_usec"); v > 0 {
			return float64(v) / 1e6
		}
		return -1
	}
	if s, ok := c.readV1("cpuacct.usage", "cpuacct", "cpu,cpuacct", "cpuacct,cpu"); ok {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			return float64(v) / 1e9
		}
	}
	return -1
}

// throttling returns the cgroup's CPU periods and throttled periods.
func (c cgroup) throttling() (periods, throttled uint64) {
	s, ok := c.readV2("cpu.stat")
	if !ok {
		s, ok = c.readV1("cpu.stat", "cpu", "cpu,cpuacct", "cpuacct,cpu")
	}
	if !ok {
		return 0, 0
	}
	return uint64(max(statValue(s, "nr_periods"), 0)), uint64(max(statValue(s, "nr_throttled"), 0)) //nolint:gosec // clamped to >= 0
}

// oomKills is the cgroup's OOM-kill counter.
func (c cgroup) oomKills() (uint64, bool) {
	s, ok := c.readV2("memory.events")
	if !ok {
		s, ok = c.readV1("memory.oom_control", "memory")
	}
	if !ok || !strings.Contains(s, "oom_kill ") {
		return 0, false
	}
	return uint64(max(statValue(s, "oom_kill"), 0)), true //nolint:gosec // clamped to >= 0
}

// statValue returns key's value in a "key value" per line file; 0 when absent.
func statValue(s, key string) int64 {
	sc := bufio.NewScanner(bytes.NewReader([]byte(s)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if ok && k == key {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}
