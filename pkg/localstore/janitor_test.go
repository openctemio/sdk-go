package localstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeOutbox struct {
	mu      sync.Mutex
	pending int64
	dead    []time.Time // DeadAt of each dead letter
	dropped []string
	dropErr error
	purged  int
}

func (f *fakeOutbox) Bytes() (int64, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending, int64(len(f.dead)) * 100
}

func (f *fakeOutbox) PurgeDead(_ context.Context, maxAge time.Duration, limit int) (int, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keep []time.Time
	n := 0
	for _, at := range f.dead {
		if time.Since(at) > maxAge && (limit == 0 || n < limit) {
			n++
			continue
		}
		keep = append(keep, at)
	}
	f.dead = keep
	f.purged += n
	return n, int64(n) * 100
}

func (f *fakeOutbox) DropTenant(t string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dropErr != nil {
		return 0, f.dropErr
	}
	f.dropped = append(f.dropped, t)
	return 1, nil
}

type fakePacks struct {
	bytes      int64
	coldBytes  int64 // freed by an EvictCold prune
	coldCalled int
	panics     bool
}

func (f *fakePacks) Bytes() int64 { return f.bytes }
func (f *fakePacks) Prune(_ context.Context, p PackPolicy) PackResult {
	if f.panics {
		panic("boom")
	}
	if p.EvictCold {
		f.coldCalled++
		freed := f.coldBytes
		f.bytes -= freed
		f.coldBytes = 0
		return PackResult{Removed: 1, Freed: freed, Bytes: f.bytes}
	}
	return PackResult{Bytes: f.bytes}
}

type fakeWS struct {
	bytes  int64
	erased []string
	swept  int
	block  bool
}

func (f *fakeWS) Bytes() int64 { return f.bytes }
func (f *fakeWS) EraseTenant(t string) error {
	f.erased = append(f.erased, t)
	return nil
}
func (f *fakeWS) SweepBounded(ctx context.Context, _ func(string, string) bool, _ int) (int, error) {
	f.swept++
	if f.block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return 0, nil
}

func janitorT(t *testing.T, s *Store, mod func(*JanitorConfig)) *Janitor {
	t.Helper()
	cfg := JanitorConfig{Store: s, Logf: quiet}
	if mod != nil {
		mod(&cfg)
	}
	j, err := NewJanitor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func okSpace(o *Options) {
	o.space = func(string) (space, bool) {
		return space{freeBytes: 50 << 30, totalBytes: 100 << 30, freeFiles: 1e6, totalFiles: 2e6}, true
	}
}

func TestPolicyNormalizeClampsAndDefaults(t *testing.T) {
	d := Policy{}.Normalize()
	if d.DeadLetterMaxAge != DefaultDeadLetterMaxAge || d.PackBudgetBytes != DefaultPackBudget || d.PackMaxUnused != DefaultPackMaxUnused ||
		d.JournalTombstoneAge != DefaultJournalTombstone || d.HighFreeFraction != DefaultHighFreeFraction {
		t.Fatalf("defaults %+v", d)
	}
	// A policy tunes cleanup; it cannot switch it off or lift a cap
	// without bound.
	p := Policy{DeadLetterMaxAge: 1000 * 24 * time.Hour, PackBudgetBytes: 1 << 50, StoreQuotaBytes: 1 << 60,
		JournalTombstoneAge: time.Nanosecond, HighFreeFraction: 0.0001}.Normalize()
	if p.DeadLetterMaxAge > 30*24*time.Hour || p.PackBudgetBytes > 8<<30 || p.StoreQuotaBytes > 64<<30 ||
		p.JournalTombstoneAge < time.Hour || p.HighFreeFraction < 0.05 {
		t.Fatalf("not clamped %+v", p)
	}
}

func TestUsagePerTenantNamespaceAndClass(t *testing.T) {
	s := openT(t, t.TempDir())
	_ = kvT(t, s, "org-a", "policy").Put("p", []byte("0123456789"))
	_ = kvT(t, s, "org-b", "policy").Put("p", []byte("x"))
	j, _ := s.Journal("org-a")
	_ = j.Begin(JobRecord{CommandID: "c1"})
	u := s.Usage()
	if len(u.Entries) != 3 || u.Total <= 0 || u.ByClass[ClassJournal] <= 0 || u.ByClass[ClassState] <= 0 {
		t.Fatalf("usage %+v", u)
	}
	var sum int64
	for _, e := range u.Entries {
		sum += e.Bytes
		if e.Namespace == "journal" && e.Class != ClassJournal {
			t.Fatalf("journal class %+v", e)
		}
	}
	if sum != u.Total {
		t.Fatalf("total %d != %d", u.Total, sum)
	}
	if err := s.EraseTenant("org-b"); err != nil {
		t.Fatal(err)
	}
	if got := s.Usage(); len(got.Entries) != 2 {
		t.Fatalf("erased tenant still counted: %+v", got)
	}
}

func TestSweepCompactsTombstonesKeepsOpenJobs(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	s := openT(t, dir, okSpace, func(o *Options) { o.now = func() time.Time { return now } })
	j, _ := s.Journal(SensorTenant)
	finishedJob(t, j, "done")
	_ = j.Begin(JobRecord{CommandID: "open"})
	jan := janitorT(t, s, nil)
	if _, err := jan.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Get("done"); err != nil {
		t.Fatalf("a fresh tombstone was removed: %v", err)
	}
	now = now.Add(25 * time.Hour)
	rep, err := jan.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Get("done"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an old tombstone was kept: %v", err)
	}
	if _, err := j.Get("open"); err != nil {
		t.Fatalf("an open job was removed: %v", err)
	}
	if rep.Removed[ClassJournal] != 1 {
		t.Fatalf("report %+v", rep)
	}
}

func TestSweepPurgesOldDeadLettersOnly(t *testing.T) {
	s := openT(t, t.TempDir(), okSpace)
	ob := &fakeOutbox{pending: 5000, dead: []time.Time{time.Now().Add(-8 * 24 * time.Hour), time.Now().Add(-time.Hour)}}
	jan := janitorT(t, s, func(c *JanitorConfig) { c.Outbox = ob })
	rep, _ := jan.Sweep(context.Background())
	if rep.Removed[ClassDeadLetter] != 1 || len(ob.dead) != 1 {
		t.Fatalf("report %+v dead %d", rep, len(ob.dead))
	}
	if ob.pending != 5000 {
		t.Fatal("pending results touched")
	}
}

// Unacknowledged results are never deleted for space: storage pressure
// stops claiming and leaves the outbox alone.
func TestUnackedSurviveDiskPressure(t *testing.T) {
	sp := space{freeBytes: 10 << 30, totalBytes: 100 << 30, freeFiles: 1e6, totalFiles: 2e6}
	s := openT(t, t.TempDir(), func(o *Options) { o.space = func(string) (space, bool) { return sp, true } })
	ob := &fakeOutbox{pending: 700 << 20}
	pk := &fakePacks{bytes: 100 << 20, coldBytes: 100 << 20}
	jan := janitorT(t, s, func(c *JanitorConfig) { c.Outbox, c.Packs = ob, pk })

	// 10 % free: high. The cold cache goes first; the results stay.
	if _, err := jan.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := jan.Status()
	if st.Level != WatermarkHigh || !st.StopClaiming || pk.coldCalled != 1 || ob.pending != 700<<20 {
		t.Fatalf("high: %+v cold=%d pending=%d", st, pk.coldCalled, ob.pending)
	}
	if ok, why := jan.AcceptsWork(); ok || why == "" {
		t.Fatalf("accepts work at high: %v %q", ok, why)
	}
	// Critical: still nothing unacked is deleted.
	sp.freeBytes = 10 << 20
	_, _ = jan.Sweep(context.Background())
	st = jan.Status()
	if st.Level != WatermarkCritical || !st.StopClaiming || ob.pending != 700<<20 {
		t.Fatalf("critical: %+v", st)
	}
	// Room again: claiming resumes.
	sp.freeBytes = 60 << 30
	_, _ = jan.Sweep(context.Background())
	if st = jan.Status(); st.Level != WatermarkOK || st.StopClaiming {
		t.Fatalf("recovered: %+v", st)
	}
	if ok, _ := jan.AcceptsWork(); !ok {
		t.Fatal("still refusing work")
	}
}

func TestQuotaWatermarkEvictsColdCacheThenStopsClaiming(t *testing.T) {
	s := openT(t, t.TempDir(), okSpace)
	ob := &fakeOutbox{pending: 7 << 30}
	pk := &fakePacks{bytes: 1 << 30, coldBytes: 1 << 30}
	jan := janitorT(t, s, func(c *JanitorConfig) { c.Outbox, c.Packs = ob, pk }) // quota 8 GiB, high at 6.8
	_, _ = jan.Sweep(context.Background())
	// 8 GiB used, 1 GiB evicted: 7 GiB still above 85 % of the quota.
	st := jan.Status()
	if pk.coldCalled != 1 || !st.StopClaiming || st.Level != WatermarkHigh {
		t.Fatalf("%+v cold=%d", st, pk.coldCalled)
	}
	ob.pending = 1 << 30
	_, _ = jan.Sweep(context.Background())
	if st = jan.Status(); st.StopClaiming {
		t.Fatalf("below the watermark: %+v", st)
	}
	jan.SetPolicy(Policy{StoreQuotaBytes: 2 << 30}) // 1 GiB of 2 GiB: 50 %
	_, _ = jan.Sweep(context.Background())
	if st = jan.Status(); st.StopClaiming || st.QuotaBytes != 2<<30 {
		t.Fatalf("policy quota: %+v", st)
	}
}

func TestWorkspaceBudgetStopsClaiming(t *testing.T) {
	s := openT(t, t.TempDir(), okSpace)
	ws := &fakeWS{bytes: 5 << 30}
	jan := janitorT(t, s, func(c *JanitorConfig) { c.Workspaces = ws })
	_, _ = jan.Sweep(context.Background())
	if st := jan.Status(); !st.StopClaiming || st.Bytes[ClassWorkspace] != 5<<30 {
		t.Fatalf("%+v", st)
	}
}

func TestSweepIsBoundedInOperations(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	s := openT(t, t.TempDir(), okSpace, func(o *Options) { o.now = func() time.Time { return now } })
	j, _ := s.Journal(SensorTenant)
	for i := range 25 {
		id := fmt.Sprintf("c%02d", i)
		finishedJob(t, j, id)
	}
	now = now.Add(48 * time.Hour)
	jan := janitorT(t, s, func(c *JanitorConfig) { c.MaxOps = 10 })
	rep, _ := jan.Sweep(context.Background())
	if rep.Removed[ClassJournal] != 10 || !rep.Truncated {
		t.Fatalf("first sweep %+v", rep)
	}
	_, _ = jan.Sweep(context.Background())
	rep, _ = jan.Sweep(context.Background())
	if rep.Removed[ClassJournal] != 5 {
		t.Fatalf("third sweep %+v", rep)
	}
	if names, _ := j.kv.List(); len(names) != 0 {
		t.Fatalf("left %v", names)
	}
}

func TestSweepIsBoundedInTime(t *testing.T) {
	s := openT(t, t.TempDir(), okSpace)
	ws := &fakeWS{block: true}
	jan := janitorT(t, s, func(c *JanitorConfig) {
		c.Workspaces = ws
		c.MaxDuration = 100 * time.Millisecond
	})
	start := time.Now()
	rep, err := jan.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("sweep took %v", d)
	}
	if !rep.Truncated {
		t.Fatalf("not flagged as truncated: %+v", rep)
	}
}

// A crash (here a panic in one class, then a canceled sweep) leaves the
// store usable and the next sweep finishes the job.
func TestCrashMidSweepIsSafe(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	s := openT(t, dir, okSpace, func(o *Options) { o.now = func() time.Time { return now } })
	j, _ := s.Journal(SensorTenant)
	finishedJob(t, j, "old")
	_ = j.Begin(JobRecord{CommandID: "open"})
	now = now.Add(48 * time.Hour)
	pk := &fakePacks{panics: true}
	jan := janitorT(t, s, func(c *JanitorConfig) { c.Packs = pk })
	rep, err := jan.Sweep(context.Background())
	if err != nil || len(rep.Errors) == 0 {
		t.Fatalf("panic not reported: %v %+v", err, rep)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := jan.Sweep(ctx); err == nil {
		t.Fatal("canceled sweep reports no error")
	}
	_ = s.Close()
	s2 := openT(t, dir, okSpace, func(o *Options) { o.now = func() time.Time { return now } })
	jan2 := janitorT(t, s2, nil)
	if _, err := jan2.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	j2, _ := s2.Journal(SensorTenant)
	if _, err := j2.Get("open"); err != nil {
		t.Fatalf("open job lost: %v", err)
	}
	if _, err := j2.Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tombstone kept: %v", err)
	}
}

func TestUnassignErasesTenantAndRetries(t *testing.T) {
	s := openT(t, t.TempDir(), okSpace)
	_ = kvT(t, s, "org-a", "policy").Put("p", []byte("x"))
	_ = kvT(t, s, "org-b", "policy").Put("p", []byte("y"))
	ob := &fakeOutbox{dropErr: errors.New("busy")}
	ws := &fakeWS{}
	jan := janitorT(t, s, func(c *JanitorConfig) { c.Outbox, c.Workspaces = ob, ws })
	if err := jan.Unassign("../etc"); err == nil {
		t.Fatal("invalid tenant accepted")
	}
	if err := jan.Unassign("org-a"); err != nil {
		t.Fatal(err)
	}
	rep, _ := jan.Sweep(context.Background())
	if len(rep.Errors) == 0 || !s.HasTenant("org-a") {
		t.Fatalf("erased while its queue was busy: %+v", rep)
	}
	if st := jan.Status(); len(st.PendingErasures) != 1 {
		t.Fatalf("pending %v", st.PendingErasures)
	}
	ob.dropErr = nil
	if _, err := jan.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.HasTenant("org-a") || !s.HasTenant("org-b") {
		t.Fatalf("tenants %v", s.Tenants())
	}
	if len(ws.erased) == 0 || len(ob.dropped) != 1 || len(jan.Status().PendingErasures) != 0 {
		t.Fatalf("ws %v ob %v", ws.erased, ob.dropped)
	}
}

func TestRunSweepsAtStartAfterAcksAndOnTick(t *testing.T) {
	s := openT(t, t.TempDir(), okSpace)
	ob := &fakeOutbox{dead: []time.Time{time.Now().Add(-9 * 24 * time.Hour)}}
	jan := janitorT(t, s, func(c *JanitorConfig) {
		c.Outbox = ob
		c.Every = time.Hour
		c.AckDelay = 10 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { jan.Run(ctx); close(done) }()
	waitSweeps := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for jan.Status().Sweeps < n {
			if time.Now().After(deadline) {
				t.Fatalf("sweeps %d, want %d", jan.Status().Sweeps, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitSweeps(1) // at start
	ob.mu.Lock()
	ob.dead = append(ob.dead, time.Now().Add(-9*24*time.Hour))
	ob.mu.Unlock()
	jan.NoteAcks()
	jan.NoteAcks() // a burst is one sweep
	waitSweeps(2)
	ob.mu.Lock()
	n := len(ob.dead)
	ob.mu.Unlock()
	if n != 0 {
		t.Fatalf("dead letters left after the ack-triggered sweep: %d", n)
	}
	cancel()
	<-done
}

// finishedJob leaves a tombstone: a job with a non-repeatable step.
func finishedJob(t *testing.T, j *Journal, id string) {
	t.Helper()
	if err := j.Begin(JobRecord{CommandID: id}); err != nil {
		t.Fatal(err)
	}
	if err := j.StepStarted(id, "report", false); err != nil {
		t.Fatal(err)
	}
	if err := j.StepDone(id, "report"); err != nil {
		t.Fatal(err)
	}
	if err := j.Finish(id); err != nil {
		t.Fatal(err)
	}
}
