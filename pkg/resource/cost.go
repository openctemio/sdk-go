package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ToolEstimate is what one job of a tool costs on this sensor, as a
// heartbeat carries it under capacity.per_tool.<tool>.
type ToolEstimate struct {
	// CPUSeconds is the CPU time one job uses (all its processes).
	CPUSeconds float64 `json:"est_cpu_s"`
	// MemBytes is the peak resident memory of one job.
	MemBytes int64 `json:"est_mem_bytes"`
	// ThroughputTargetsPerMin is how many targets one job slot scans per
	// minute.
	ThroughputTargetsPerMin float64 `json:"throughput_targets_per_min"`
}

// Outcome is how a job ended, for the cost history and the slot controller.
type Outcome int

const (
	// OutcomeSuccess: the job finished.
	OutcomeSuccess Outcome = iota
	// OutcomeFailed: the job failed for its own reasons (bad target, tool
	// error); says nothing about load.
	OutcomeFailed
	// OutcomeTimeout: the job ran out of time.
	OutcomeTimeout
	// OutcomeKilled: a process of the job was killed (SIGKILL), typically
	// by the OOM killer.
	OutcomeKilled
)

// JobSample is what a finished job cost.
type JobSample struct {
	Tool    string
	Targets int
	Wall    time.Duration
	// CPUSeconds and PeakRSSBytes come from the job's processes; 0 when
	// unknown (the job ran no measured process).
	CPUSeconds   float64
	PeakRSSBytes int64
	Outcome      Outcome
}

// toolDefault is the prior for a tool without history.
type toolDefault struct {
	cores            float64 // CPU cores one job keeps busy
	mem              int64   // peak memory of one job
	secondsPerTarget float64
}

const (
	mib = int64(1) << 20
	gib = int64(1) << 30
)

// toolDefaults are conservative priors; the history replaces them after a
// few jobs.
var toolDefaults = map[string]toolDefault{
	"nuclei":      {cores: 1.0, mem: 512 * mib, secondsPerTarget: 20},
	"trivy":       {cores: 1.0, mem: 1 * gib, secondsPerTarget: 60},
	"semgrep":     {cores: 1.0, mem: 1536 * mib, secondsPerTarget: 120},
	"betterleaks": {cores: 0.5, mem: 256 * mib, secondsPerTarget: 30},
	"codeql":      {cores: 2.0, mem: 4 * gib, secondsPerTarget: 600},
	"nmap":        {cores: 0.5, mem: 256 * mib, secondsPerTarget: 30},
	"naabu":       {cores: 0.5, mem: 256 * mib, secondsPerTarget: 10},
	"subfinder":   {cores: 0.5, mem: 256 * mib, secondsPerTarget: 30},
	"httpx":       {cores: 0.5, mem: 256 * mib, secondsPerTarget: 5},
	"dnsx":        {cores: 0.5, mem: 128 * mib, secondsPerTarget: 2},
	"katana":      {cores: 1.0, mem: 512 * mib, secondsPerTarget: 60},
}

// genericDefault is the prior for a tool not in toolDefaults.
var genericDefault = toolDefault{cores: 1.0, mem: 512 * mib, secondsPerTarget: 60}

// costAlpha is the EWMA weight of a new sample.
const costAlpha = 0.3

// toolCost is a tool's learned cost, as persisted.
type toolCost struct {
	// Cores is the CPU cores a running job keeps busy (CPU / wall).
	Cores float64 `json:"cores"`
	// CPUSeconds is the CPU time per job.
	CPUSeconds float64 `json:"cpu_seconds"`
	// MemBytes is the peak memory per job (tracks peaks up at once,
	// decays slowly).
	MemBytes int64 `json:"mem_bytes"`
	// SecondsPerTarget is the wall time per target.
	SecondsPerTarget float64 `json:"seconds_per_target"`
	// Samples counts the successful jobs learned from.
	Samples int `json:"samples"`
}

type costFile struct {
	Version int                  `json:"version"`
	Tools   map[string]*toolCost `json:"tools"`
}

// CostBook is the per-tool cost history: priors for tools it has not seen,
// learned from finished jobs, persisted to a small JSON file so it survives
// restarts. Safe for concurrent use.
type CostBook struct {
	mu    sync.Mutex
	path  string
	tools map[string]*toolCost
}

// NewCostBook opens the history at path ("" keeps it in memory). A missing
// file starts empty; an unreadable or corrupt one also starts empty and is
// returned as the error (the book is usable either way).
func NewCostBook(path string) (*CostBook, error) {
	b := &CostBook{path: path, tools: map[string]*toolCost{}}
	if path == "" {
		return b, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // the sensor's own state file
	if errors.Is(err, fs.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return b, fmt.Errorf("read tool cost history: %w", err)
	}
	var f costFile
	if err := json.Unmarshal(data, &f); err != nil {
		return b, fmt.Errorf("tool cost history %s is corrupt, starting over: %w", path, err)
	}
	for name, c := range f.Tools {
		if c != nil && name != "" && validCost(c) {
			b.tools[name] = c
		}
	}
	return b, nil
}

func validCost(c *toolCost) bool {
	ok := func(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 }
	return ok(c.Cores) && ok(c.CPUSeconds) && ok(c.SecondsPerTarget) && c.MemBytes >= 0 && c.Samples >= 0
}

func defaultFor(tool string) toolDefault {
	if d, ok := toolDefaults[tool]; ok {
		return d
	}
	return genericDefault
}

// Observe learns from a finished job. Only successes teach CPU and time; a
// kill raises the memory estimate (half again), since it was most likely
// the OOM killer.
func (b *CostBook) Observe(s JobSample) {
	if s.Tool == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.tools[s.Tool]
	if c == nil {
		d := defaultFor(s.Tool)
		c = &toolCost{Cores: d.cores, MemBytes: d.mem, SecondsPerTarget: d.secondsPerTarget, CPUSeconds: d.cores * d.secondsPerTarget}
		b.tools[s.Tool] = c
	}
	switch s.Outcome {
	case OutcomeKilled:
		c.MemBytes = max(c.MemBytes+c.MemBytes/2, s.PeakRSSBytes)
		return
	case OutcomeSuccess:
	default:
		return
	}
	wall := s.Wall.Seconds()
	if wall <= 0 {
		return
	}
	targets := max(s.Targets, 1)
	first := c.Samples == 0
	ewma := func(old, v float64) float64 {
		if first {
			return v
		}
		return (1-costAlpha)*old + costAlpha*v
	}
	c.SecondsPerTarget = ewma(c.SecondsPerTarget, wall/float64(targets))
	if s.CPUSeconds > 0 {
		c.CPUSeconds = ewma(c.CPUSeconds, s.CPUSeconds)
		c.Cores = ewma(c.Cores, s.CPUSeconds/wall)
	}
	if s.PeakRSSBytes > 0 {
		if first || s.PeakRSSBytes > c.MemBytes {
			c.MemBytes = s.PeakRSSBytes
		} else {
			c.MemBytes = int64(0.9*float64(c.MemBytes) + 0.1*float64(s.PeakRSSBytes))
		}
	}
	c.Samples++
}

// Estimate is a tool's per-job cost: learned, or the prior.
func (b *CostBook) Estimate(tool string) ToolEstimate {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.estimateLocked(tool)
}

func (b *CostBook) estimateLocked(tool string) ToolEstimate {
	if c := b.tools[tool]; c != nil {
		return toEstimate(c.CPUSeconds, c.MemBytes, c.SecondsPerTarget)
	}
	d := defaultFor(tool)
	return toEstimate(d.cores*d.secondsPerTarget, d.mem, d.secondsPerTarget)
}

func toEstimate(cpu float64, mem int64, secondsPerTarget float64) ToolEstimate {
	e := ToolEstimate{CPUSeconds: round2(cpu), MemBytes: mem}
	if secondsPerTarget > 0 {
		e.ThroughputTargetsPerMin = round2(60 / secondsPerTarget)
	}
	return e
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// jobDemand is the CPU cores and memory one running job of the tool needs.
func (b *CostBook) jobDemand(tool string) (cores float64, mem int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.tools[tool]; c != nil && c.Cores > 0 && c.MemBytes > 0 {
		return c.Cores, c.MemBytes
	}
	d := defaultFor(tool)
	return d.cores, d.mem
}

// Tools returns the tools with a learned history, sorted.
func (b *CostBook) Tools() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.tools))
	for t := range b.tools {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Save writes the history (atomically: temp file + rename, mode 0600).
func (b *CostBook) Save() error {
	if b.path == "" {
		return nil
	}
	b.mu.Lock()
	f := costFile{Version: 1, Tools: make(map[string]*toolCost, len(b.tools))}
	for k, v := range b.tools {
		c := *v
		f.Tools[k] = &c
	}
	b.mu.Unlock()
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(b.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tool cost history: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tool-costs-*.json")
	if err != nil {
		return fmt.Errorf("tool cost history: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tool cost history: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("tool cost history: %w", err)
	}
	if err := os.Rename(tmp.Name(), b.path); err != nil {
		return fmt.Errorf("tool cost history: %w", err)
	}
	return nil
}
