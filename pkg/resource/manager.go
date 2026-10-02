package resource

import (
	"sort"
	"sync"
	"time"
)

// Capacity is the slot picture a heartbeat carries as "capacity".
type Capacity struct {
	// SlotsTotal is how many jobs the sensor runs at once now (dynamic, at
	// most the configured cap).
	SlotsTotal int `json:"slots_total"`
	// SlotsFree is SlotsTotal minus ActiveJobs (never negative).
	SlotsFree int `json:"slots_free"`
	// ActiveJobs is the jobs it holds now.
	ActiveJobs int `json:"active_jobs"`
	// PerTool is the per-job cost of each tool the sensor runs.
	PerTool map[string]ToolEstimate `json:"per_tool,omitempty"`
}

// ManagerConfig configures a Manager.
type ManagerConfig struct {
	// Cap is the operator's limit on concurrent jobs; 0 sets none (the
	// slots then follow the resources, up to HardMax).
	Cap int
	// HardMax bounds the slots whatever the resources (default
	// DefaultHardMaxSlots).
	HardMax int
	// Tools are the tools the sensor runs; the slots are sized for the most
	// demanding of them. Empty: a generic job (1 core, 512 MiB).
	Tools []string
	// CostHints are the sensor's own per-job cost estimates, the prior of a
	// tool without history (instead of the built-in default); see
	// core.ToolRegistry.CostHints.
	CostHints map[string]ToolCostHint
	// StateFile persists the per-tool cost history ("" keeps it in memory).
	StateFile string
	// Prober reads the resources (nil: the running system, no work dir).
	Prober *Prober
	// ProbeInterval is the longest a probe is reused (default 10s).
	ProbeInterval time.Duration
	// OnError receives non-fatal errors (loading or saving the history).
	OnError func(error)
}

// Manager turns the sensor's resources and its tools' learned costs into a
// live slot count: the jobs that fit the CPU and memory it may use, at most
// the configured cap, narrowed by an AIMD window that halves on OOM kills,
// timeouts and CPU throttling and slowly grows back on success. Safe for
// concurrent use.
type Manager struct {
	cfg    ManagerConfig
	prober *Prober
	book   *CostBook
	aimd   *AIMD

	mu       sync.Mutex
	tools    []string
	last     ProbeResult
	lastAt   time.Time
	probed   bool
	lastCong time.Time
	// lastSlots is the last slot count computed (what a congestion
	// signal halves).
	lastSlots int
}

// NewManager creates a Manager. A history that cannot be loaded is reported
// to OnError and started over.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.HardMax <= 0 {
		cfg.HardMax = DefaultHardMaxSlots
	}
	if cfg.Cap > cfg.HardMax {
		cfg.HardMax = cfg.Cap
	}
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = 10 * time.Second
	}
	p := cfg.Prober
	if p == nil {
		p = &Prober{}
	}
	book, err := NewCostBook(cfg.StateFile)
	if err != nil && cfg.OnError != nil {
		cfg.OnError(err)
	}
	for tool, h := range cfg.CostHints {
		book.SetPrior(tool, h)
	}
	return &Manager{
		cfg:    cfg,
		prober: p,
		book:   book,
		aimd:   NewAIMD(cfg.MaxSlots()),
		tools:  append([]string(nil), cfg.Tools...),
	}
}

// MaxSlots is the most slots there can be: the cap, else HardMax.
func (c ManagerConfig) MaxSlots() int {
	if c.Cap > 0 {
		return c.Cap
	}
	if c.HardMax > 0 {
		return c.HardMax
	}
	return DefaultHardMaxSlots
}

// MaxSlots is the most slots this manager hands out.
func (m *Manager) MaxSlots() int { return m.cfg.MaxSlots() }

// Cap is the operator's limit on concurrent jobs (ManagerConfig.Cap); 0 when
// the operator set none and the slots follow the resources alone (up to
// HardMax, which is a safety bound, not a capacity).
func (m *Manager) Cap() int { return m.cfg.Cap }

// SetTools sets the tools the slots are sized for.
func (m *Manager) SetTools(tools []string) {
	m.mu.Lock()
	m.tools = append([]string(nil), tools...)
	m.mu.Unlock()
}

// Book is the cost history.
func (m *Manager) Book() *CostBook { return m.book }

// probe returns a probe no older than ProbeInterval (force: a new one),
// and applies its congestion signals to the AIMD window.
func (m *Manager) probe(force bool) ProbeResult {
	now := m.prober.now()
	m.mu.Lock()
	if m.probed && !force && now.Sub(m.lastAt) < m.cfg.ProbeInterval {
		r := m.last
		m.mu.Unlock()
		return r
	}
	m.mu.Unlock()

	r := m.prober.Probe()

	m.mu.Lock()
	m.last, m.lastAt, m.probed = r, now, true
	congested := r.OOMKills > 0 || r.ThrottledRatio > 0.5
	// One decrease per probe interval, however many signals.
	if congested && now.Sub(m.lastCong) >= m.cfg.ProbeInterval {
		m.lastCong = now
		cur := m.lastSlots
		m.mu.Unlock()
		m.aimd.DecreaseFrom(cur)
		return r
	}
	m.mu.Unlock()
	return r
}

// demand is the per-job CPU and memory the slots are sized for: the most
// demanding of the sensor's tools.
func (m *Manager) demand() (cores float64, mem int64) {
	m.mu.Lock()
	tools := append([]string(nil), m.tools...)
	m.mu.Unlock()
	if len(tools) == 0 {
		return genericDefault.cores, genericDefault.mem
	}
	for _, t := range tools {
		c, b := m.book.jobDemand(t)
		cores = max(cores, c)
		mem = max(mem, b)
	}
	return cores, mem
}

// slots computes the slot count from a probe, with active jobs running.
func (m *Manager) slots(r ProbeResult, active int) int {
	cores, mem := m.demand()
	res := r.Resources
	// The memory the running jobs hold comes back when they end: count it
	// as budget, so the slot count does not shrink because jobs run.
	budget := res.MemAvailableBytes
	if budget > 0 {
		budget += int64(active) * mem
		if res.MemTotalBytes > 0 {
			budget = min(budget, res.MemTotalBytes)
		}
	}
	n := ComputeSlots(m.cfg.Cap, m.cfg.HardMax, res.CPUCores, budget, cores, mem)
	n = max(min(n, m.aimd.Limit()), 1)
	m.mu.Lock()
	m.lastSlots = n
	m.mu.Unlock()
	return n
}

// Slots is how many jobs the sensor may hold now, with active running.
func (m *Manager) Slots(active int) int {
	return m.slots(m.probe(false), active)
}

// Observe learns from a finished job and moves the AIMD window: down on a
// timeout or kill, up on success. The history is saved.
func (m *Manager) Observe(s JobSample) {
	m.book.Observe(s)
	switch s.Outcome {
	case OutcomeSuccess:
		m.aimd.Increase()
	case OutcomeTimeout, OutcomeKilled:
		m.mu.Lock()
		cur := m.lastSlots
		m.mu.Unlock()
		m.aimd.DecreaseFrom(cur)
	case OutcomeFailed:
	}
	if err := m.book.Save(); err != nil && m.cfg.OnError != nil {
		m.cfg.OnError(err)
	}
}

// Snapshot is a fresh probe and the capacity with active jobs running, for
// a heartbeat.
func (m *Manager) Snapshot(active int) (HostResources, Capacity) {
	r := m.probe(true)
	total := m.slots(r, active)
	c := Capacity{SlotsTotal: total, SlotsFree: max(total-active, 0), ActiveJobs: active}

	m.mu.Lock()
	names := append([]string(nil), m.tools...)
	m.mu.Unlock()
	names = append(names, m.book.Tools()...)
	sort.Strings(names)
	for _, t := range names {
		if t == "" {
			continue
		}
		if c.PerTool == nil {
			c.PerTool = map[string]ToolEstimate{}
		}
		c.PerTool[t] = m.book.Estimate(t)
	}
	return r.Resources, c
}
