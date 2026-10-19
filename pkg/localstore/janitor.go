package localstore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// Watermark is how full the sensor's storage is.
type Watermark string

// Watermarks.
const (
	// WatermarkOK: room for new work.
	WatermarkOK Watermark = "ok"
	// WatermarkHigh: 85 % of the quota used or less than 15 % of the volume
	// free. Cold cache is evicted; when that is not enough the sensor stops
	// claiming new jobs (results beat new work).
	WatermarkHigh Watermark = "high"
	// WatermarkCritical: less than the store's critical free space. Only
	// acknowledgements and deletions proceed.
	WatermarkCritical Watermark = "critical"
)

// Defaults of Policy.
const (
	DefaultDeadLetterMaxAge = 7 * 24 * time.Hour
	DefaultJournalTombstone = 24 * time.Hour
	DefaultWorkspaceBudget  = 4 << 30
	DefaultPackBudget       = 2 << 30
	DefaultPackMaxUnused    = 14 * 24 * time.Hour
	DefaultLogMaxBytes      = 100 << 20
	DefaultLogMaxAge        = 7 * 24 * time.Hour
	DefaultStoreQuota       = 8 << 30
	DefaultHighFreeFraction = 0.15
	DefaultSweepEvery       = 10 * time.Minute
	DefaultSweepMaxDuration = 30 * time.Second
	DefaultSweepMaxOps      = 5000
	highQuotaFraction       = 0.85
	DefaultAckDelay         = 2 * time.Second
)

// Policy is the retention and cap policy. The platform sends it with the
// sensor's other policy; a zero field means the default and every value is
// clamped to a sane range (Normalize), so a policy can tune cleanup but
// never switch it off or lift a cap without bound.
type Policy struct {
	// DeadLetterMaxAge: dead letters older than this are deleted.
	DeadLetterMaxAge time.Duration `json:"dead_letter_max_age,omitempty"`
	// JournalTombstoneAge: finished or interrupted job records older than
	// this are deleted.
	JournalTombstoneAge time.Duration `json:"journal_tombstone_age,omitempty"`
	// WorkspaceBudgetBytes is the total bytes all job workspaces may hold.
	WorkspaceBudgetBytes int64 `json:"workspace_budget_bytes,omitempty"`
	// PackBudgetBytes caps the content packs.
	PackBudgetBytes int64 `json:"pack_budget_bytes,omitempty"`
	// PackMaxUnused: a pack no assignment names and nothing used for this
	// long is deleted.
	PackMaxUnused time.Duration `json:"pack_max_unused,omitempty"`
	// LogMaxBytes and LogMaxAge are handed to the log rotation hook.
	LogMaxBytes int64         `json:"log_max_bytes,omitempty"`
	LogMaxAge   time.Duration `json:"log_max_age,omitempty"`
	// StoreQuotaBytes is the total the sensor's local data may use; the
	// high watermark is 85 % of it.
	StoreQuotaBytes int64 `json:"store_quota_bytes,omitempty"`
	// HighFreeFraction: free share of the volume below which the high
	// watermark is reached (0.05 to 0.5).
	HighFreeFraction float64 `json:"high_free_fraction,omitempty"`
}

func clampDur(v, def, lo, hi time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return min(max(v, lo), hi)
}

func clampInt(v, def, lo, hi int64) int64 {
	if v <= 0 {
		return def
	}
	return min(max(v, lo), hi)
}

// Normalize fills the defaults and clamps every field.
func (p Policy) Normalize() Policy {
	const h, d, mib, gib = time.Hour, 24 * time.Hour, int64(1) << 20, int64(1) << 30
	p.DeadLetterMaxAge = clampDur(p.DeadLetterMaxAge, DefaultDeadLetterMaxAge, h, 30*d)
	p.JournalTombstoneAge = clampDur(p.JournalTombstoneAge, DefaultJournalTombstone, h, 7*d)
	p.WorkspaceBudgetBytes = clampInt(p.WorkspaceBudgetBytes, DefaultWorkspaceBudget, 256*mib, 32*gib)
	p.PackBudgetBytes = clampInt(p.PackBudgetBytes, DefaultPackBudget, 64*mib, 8*gib)
	p.PackMaxUnused = clampDur(p.PackMaxUnused, DefaultPackMaxUnused, d, 90*d)
	p.LogMaxBytes = clampInt(p.LogMaxBytes, DefaultLogMaxBytes, mib, gib)
	p.LogMaxAge = clampDur(p.LogMaxAge, DefaultLogMaxAge, h, 30*d)
	p.StoreQuotaBytes = clampInt(p.StoreQuotaBytes, DefaultStoreQuota, gib, 64*gib)
	if p.HighFreeFraction <= 0 {
		p.HighFreeFraction = DefaultHighFreeFraction
	}
	p.HighFreeFraction = min(max(p.HighFreeFraction, 0.05), 0.5)
	return p
}

// PackPolicy is what the janitor asks a content pack cache to prune.
type PackPolicy struct {
	// Budget caps the cache's bytes.
	Budget int64
	// MaxUnused deletes a pack no assignment names that was not used for
	// this long.
	MaxUnused time.Duration
	// EvictCold deletes every pack no assignment names and nothing uses
	// (the high watermark's response).
	EvictCold bool
	// Limit bounds the packs removed in one call (0: no limit).
	Limit int
}

// PackResult is what a prune removed.
type PackResult struct {
	Removed int
	Freed   int64
	// Bytes is what the cache holds afterwards.
	Bytes int64
}

// OutboxCleaner is the outbox as the janitor sees it. Delivered items are
// deleted by the outbox itself on the platform's acknowledgement; the
// janitor deletes what is left behind.
type OutboxCleaner interface {
	// Bytes is the pending and the dead letter bytes on disk.
	Bytes() (pending, dead int64)
	// PurgeDead deletes dead letters older than maxAge (at most limit).
	PurgeDead(ctx context.Context, maxAge time.Duration, limit int) (int, int64)
	// DropTenant removes a tenant's items.
	DropTenant(tenant string) (int, error)
}

// PackCache is the content pack cache as the janitor sees it.
type PackCache interface {
	Prune(ctx context.Context, p PackPolicy) PackResult
	Bytes() int64
}

// Workspaces is the per-job workspace manager as the janitor sees it.
type Workspaces interface {
	// SweepBounded removes the job directories that are not live and that
	// keep does not name, at most limit of them.
	SweepBounded(ctx context.Context, keep func(tenant, job string) bool, limit int) (int, error)
	Bytes() int64
	EraseTenant(tenant string) error
}

// JanitorConfig configures a Janitor. Store is required; give the others
// that the sensor has.
type JanitorConfig struct {
	Store      *Store
	Outbox     OutboxCleaner
	Packs      PackCache
	Workspaces Workspaces
	// RotateLogs rotates the sensor's own logs to the policy's limits and
	// returns the bytes freed.
	RotateLogs func(ctx context.Context, maxBytes int64, maxAge time.Duration) (int64, error)
	// KeepWorkspace overrides which job directories survive a sweep.
	// Default: those of a job with an open journal record.
	KeepWorkspace func(tenant, job string) bool
	Policy        Policy
	// Every is the interval between sweeps (default 10 minutes).
	Every time.Duration
	// MaxDuration and MaxOps bound one sweep (defaults 30 s, 5000 removals);
	// what is left waits for the next sweep.
	MaxDuration time.Duration
	MaxOps      int
	// AckDelay lets a burst of acknowledgements finish before the sweep
	// they trigger (default 2 s).
	AckDelay time.Duration
	Logf     func(format string, args ...any)

	now func() time.Time
}

// Report is what one sweep did.
type Report struct {
	At       time.Time     `json:"at"`
	Duration time.Duration `json:"duration"`
	// Truncated: the time or operation bound ended the sweep early.
	Truncated bool `json:"truncated,omitempty"`
	// Removed counts the items removed per class.
	Removed map[Class]int `json:"removed,omitempty"`
	// FreedBytes is what packs, dead letters and logs gave back.
	FreedBytes int64    `json:"freed_bytes,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// Status is the janitor's state for the heartbeat: bytes per class, the
// watermark, whether new jobs may be claimed and the last sweep.
type Status struct {
	Level Watermark `json:"level"`
	// StopClaiming: do not claim new jobs (storage is high even after the
	// cold cache went, a workspace budget is exceeded, or the disk is
	// critical).
	StopClaiming bool   `json:"stop_claiming"`
	Reason       string `json:"reason,omitempty"`
	// Bytes is the bytes per class; Total their sum.
	Bytes map[Class]int64 `json:"bytes"`
	Total int64           `json:"total"`
	// QuotaBytes is the policy's quota.
	QuotaBytes int64 `json:"quota_bytes"`
	// FreeBytes and FreeFraction describe the volume (0 when unknown).
	FreeBytes    uint64  `json:"free_bytes,omitempty"`
	FreeFraction float64 `json:"free_fraction,omitempty"`
	// Sweeps counts sweeps since start; Last is the latest.
	Sweeps int64  `json:"sweeps"`
	Last   Report `json:"last"`
	// PendingErasures are tenants whose erasure is waiting for in-flight
	// work.
	PendingErasures []string `json:"pending_erasures,omitempty"`
}

// Janitor deletes what the sensor no longer needs and keeps the local data
// within its caps: delivered results, old dead letters, journal
// tombstones, orphaned workspaces, cold content packs, rotated logs and
// the data of tenants that left. Unacknowledged results are never deleted
// for space: when storage runs high the sensor stops claiming instead.
type Janitor struct {
	cfg JanitorConfig

	sweepMu sync.Mutex // one sweep at a time

	mu       sync.Mutex
	policy   Policy
	status   Status
	erasures map[string]bool
	trigger  chan struct{}
}

// NewJanitor builds a janitor; call Run to start it, or Sweep directly.
func NewJanitor(cfg JanitorConfig) (*Janitor, error) {
	if cfg.Store == nil {
		return nil, errors.New("localstore: janitor needs a store")
	}
	if cfg.Every <= 0 {
		cfg.Every = DefaultSweepEvery
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = DefaultSweepMaxDuration
	}
	if cfg.MaxOps <= 0 {
		cfg.MaxOps = DefaultSweepMaxOps
	}
	if cfg.AckDelay <= 0 {
		cfg.AckDelay = DefaultAckDelay
	}
	if cfg.Logf == nil {
		cfg.Logf = func(format string, args ...any) { log.Printf("[janitor] "+format, args...) }
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &Janitor{cfg: cfg, policy: cfg.Policy.Normalize(), erasures: map[string]bool{}, trigger: make(chan struct{}, 1)}, nil
}

// SetPolicy replaces the policy (normalized) from the next sweep on.
func (j *Janitor) SetPolicy(p Policy) {
	j.mu.Lock()
	j.policy = p.Normalize()
	j.mu.Unlock()
}

// Policy returns the policy in force.
func (j *Janitor) Policy() Policy {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.policy
}

// Status returns the janitor's state (a copy).
func (j *Janitor) Status() Status {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := j.status
	st.Bytes = make(map[Class]int64, len(j.status.Bytes))
	for k, v := range j.status.Bytes {
		st.Bytes[k] = v
	}
	st.PendingErasures = sortedKeys(j.erasures)
	if st.Level == "" {
		st.Level = WatermarkOK
	}
	return st
}

// AcceptsWork reports whether the sensor may claim new jobs, with the
// reason when not. Before the first sweep it falls back to the volume's
// own free space check.
func (j *Janitor) AcceptsWork() (bool, string) {
	st := j.Status()
	if st.StopClaiming {
		return false, st.Reason
	}
	return j.cfg.Store.AcceptsWork()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NoteAcks tells the janitor the platform acknowledged results (the
// outbox's delivery hook): a sweep follows shortly, once per burst.
func (j *Janitor) NoteAcks() {
	select {
	case j.trigger <- struct{}{}:
	default:
	}
}

// Unassign records that a tenant left this sensor: its workspaces, queued
// items and journal are removed and its key crypto-erased at the next
// sweep (and at every later one until it all succeeded, for instance
// while one of its items is being delivered).
func (j *Janitor) Unassign(tenant string) error {
	if err := validName(tenant); err != nil {
		return err
	}
	j.mu.Lock()
	j.erasures[tenant] = true
	j.mu.Unlock()
	j.NoteAcks()
	return nil
}

// Run sweeps at start, after every burst of acknowledgements and every
// Every until ctx ends.
func (j *Janitor) Run(ctx context.Context) {
	j.runSweep(ctx)
	t := time.NewTicker(j.cfg.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-j.trigger:
			select { // let a burst of acknowledgements finish
			case <-ctx.Done():
				return
			case <-time.After(j.cfg.AckDelay):
			}
			select {
			case <-j.trigger:
			default:
			}
		}
		j.runSweep(ctx)
	}
}

func (j *Janitor) runSweep(ctx context.Context) {
	if _, err := j.Sweep(ctx); err != nil && ctx.Err() == nil {
		j.cfg.Logf("sweep: %v", err)
	}
}

// sweepBudget bounds one sweep.
type sweepBudget struct {
	ctx  context.Context
	left int
	cut  bool
}

func (b *sweepBudget) done() bool {
	if b.ctx.Err() != nil || b.left <= 0 {
		b.cut = true
		return true
	}
	return false
}

func (b *sweepBudget) spend(n int) { b.left -= n }

// Sweep runs one bounded pass over every class, then measures and sets the
// watermark. It is safe to call concurrently (calls queue) and to stop at
// any point: every removal is one independent file operation.
func (j *Janitor) Sweep(ctx context.Context) (Report, error) {
	j.sweepMu.Lock()
	defer j.sweepMu.Unlock()
	start := j.cfg.now()
	pol := j.Policy()
	sctx, cancel := context.WithTimeout(ctx, j.cfg.MaxDuration)
	defer cancel()
	b := &sweepBudget{ctx: sctx, left: j.cfg.MaxOps}
	rep := Report{At: start, Removed: map[Class]int{}}
	fail := func(what string, err error) {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			rep.Errors = append(rep.Errors, what+": "+err.Error())
		}
	}
	step := func(what string, f func()) {
		defer func() {
			if r := recover(); r != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: panic: %v", what, r))
			}
		}()
		if !b.done() {
			f()
		}
	}

	step("dead letters", func() {
		if j.cfg.Outbox == nil {
			return
		}
		n, freed := j.cfg.Outbox.PurgeDead(sctx, pol.DeadLetterMaxAge, b.left)
		b.spend(n)
		rep.Removed[ClassDeadLetter] += n
		rep.FreedBytes += freed
	})
	step("journal", func() {
		n, err := j.cfg.Store.CompactJournal(sctx, pol.JournalTombstoneAge, b.left)
		b.spend(n)
		rep.Removed[ClassJournal] += n
		fail("journal", err)
	})
	step("workspaces", func() {
		if j.cfg.Workspaces == nil {
			return
		}
		n, err := j.cfg.Workspaces.SweepBounded(sctx, j.keepWorkspace, b.left)
		b.spend(n)
		rep.Removed[ClassWorkspace] += n
		fail("workspaces", err)
	})
	step("content packs", func() {
		if j.cfg.Packs == nil {
			return
		}
		r := j.cfg.Packs.Prune(sctx, PackPolicy{Budget: pol.PackBudgetBytes, MaxUnused: pol.PackMaxUnused, Limit: b.left})
		b.spend(r.Removed)
		rep.Removed[ClassContentPack] += r.Removed
		rep.FreedBytes += r.Freed
	})
	step("logs", func() {
		if j.cfg.RotateLogs == nil {
			return
		}
		freed, err := j.cfg.RotateLogs(sctx, pol.LogMaxBytes, pol.LogMaxAge)
		rep.FreedBytes += freed
		fail("logs", err)
	})
	step("tenant erasure", func() { j.eraseTenants(rep.addErr) })

	// Watermarks: measure, answer a high one by evicting the cold cache,
	// measure again.
	st := j.assess(pol)
	if st.Level != WatermarkOK && j.cfg.Packs != nil {
		step("cold cache", func() {
			r := j.cfg.Packs.Prune(sctx, PackPolicy{Budget: pol.PackBudgetBytes, MaxUnused: pol.PackMaxUnused, EvictCold: true, Limit: b.left})
			b.spend(r.Removed)
			rep.Removed[ClassContentPack] += r.Removed
			rep.FreedBytes += r.Freed
		})
		st = j.assess(pol)
	}
	rep.Truncated = b.cut
	rep.Duration = j.cfg.now().Sub(start)
	for c, n := range rep.Removed {
		if n == 0 {
			delete(rep.Removed, c)
		}
	}
	j.mu.Lock()
	st.Sweeps = j.status.Sweeps + 1
	st.Last = rep
	j.status = st
	j.mu.Unlock()
	if st.Level != WatermarkOK {
		j.cfg.Logf("storage %s: %s", st.Level, st.Reason)
	}
	return rep, ctx.Err()
}

func (r *Report) addErr(s string) { r.Errors = append(r.Errors, s) }

func (j *Janitor) keepWorkspace(tenant, job string) bool {
	if j.cfg.KeepWorkspace != nil {
		return j.cfg.KeepWorkspace(tenant, job)
	}
	if !j.cfg.Store.HasTenant(tenant) {
		return false
	}
	jr, err := j.cfg.Store.Journal(tenant)
	if err != nil {
		return true // cannot tell: keep
	}
	rec, err := jr.Get(job)
	if err != nil {
		return errors.Is(err, ErrTampered) // a record we cannot read is not proof the job is gone
	}
	return !rec.tombstone()
}

// eraseTenants completes the pending tenant erasures it can.
func (j *Janitor) eraseTenants(addErr func(string)) {
	j.mu.Lock()
	pending := sortedKeys(j.erasures)
	j.mu.Unlock()
	for _, t := range pending {
		if err := j.eraseTenant(t); err != nil {
			addErr(fmt.Sprintf("erase tenant %s: %v", t, err))
			continue
		}
		j.mu.Lock()
		delete(j.erasures, t)
		j.mu.Unlock()
	}
}

func (j *Janitor) eraseTenant(t string) error {
	if j.cfg.Workspaces != nil {
		if err := j.cfg.Workspaces.EraseTenant(t); err != nil {
			return err
		}
	}
	if j.cfg.Outbox != nil {
		if _, err := j.cfg.Outbox.DropTenant(t); err != nil {
			return err
		}
	}
	return j.cfg.Store.EraseTenant(t)
}

// assess measures the bytes per class and derives the watermark.
func (j *Janitor) assess(pol Policy) Status {
	u := j.cfg.Store.Usage()
	st := Status{Bytes: u.ByClass, Total: u.Total, QuotaBytes: pol.StoreQuotaBytes, Level: WatermarkOK}
	if st.Bytes == nil {
		st.Bytes = map[Class]int64{}
	}
	var wsBytes int64
	if j.cfg.Outbox != nil {
		p, d := j.cfg.Outbox.Bytes()
		st.Bytes[ClassOutbox], st.Bytes[ClassDeadLetter] = p, d
		st.Total += p + d
	}
	if j.cfg.Workspaces != nil {
		wsBytes = j.cfg.Workspaces.Bytes()
		st.Bytes[ClassWorkspace] = wsBytes
		st.Total += wsBytes
	}
	if j.cfg.Packs != nil {
		n := j.cfg.Packs.Bytes()
		st.Bytes[ClassContentPack] = n
		st.Total += n
	}
	var reasons []string
	frac, free, known := j.cfg.Store.freeFraction()
	if known {
		st.FreeBytes, st.FreeFraction = free, frac
		if free < uint64(j.cfg.Store.opts.CriticalFreeBytes) { //nolint:gosec // defaults make it positive
			st.Level = WatermarkCritical
			reasons = append(reasons, fmt.Sprintf("%d MiB free, below the critical mark", free>>20))
		} else if frac < pol.HighFreeFraction {
			st.Level = WatermarkHigh
			reasons = append(reasons, fmt.Sprintf("%.0f %% of the volume free, below %.0f %%", frac*100, pol.HighFreeFraction*100))
		}
	}
	if float64(st.Total) >= highQuotaFraction*float64(pol.StoreQuotaBytes) {
		if st.Level == WatermarkOK {
			st.Level = WatermarkHigh
		}
		reasons = append(reasons, fmt.Sprintf("%d MiB of the %d MiB quota used", st.Total>>20, pol.StoreQuotaBytes>>20))
	}
	if wsBytes > pol.WorkspaceBudgetBytes {
		if st.Level == WatermarkOK {
			st.Level = WatermarkHigh
		}
		reasons = append(reasons, fmt.Sprintf("workspaces hold %d MiB, over the %d MiB budget", wsBytes>>20, pol.WorkspaceBudgetBytes>>20))
	}
	st.StopClaiming = st.Level != WatermarkOK
	for i, r := range reasons {
		if i > 0 {
			st.Reason += "; "
		}
		st.Reason += r
	}
	return st
}
