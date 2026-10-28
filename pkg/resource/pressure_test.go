package resource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// pressureRoot is a fake /proc and /sys for the pressure signals.
type pressureRoot struct {
	t    *testing.T
	root string
}

func newPressureRoot(t *testing.T) *pressureRoot {
	t.Helper()
	r := &pressureRoot{t: t, root: t.TempDir()}
	r.write("proc/self/cgroup", "0::/sensor\n")
	r.write("sys/fs/cgroup/cgroup.controllers", "cpu memory pids\n")
	r.write("sys/fs/cgroup/sensor/cpu.stat", "usage_usec 1\n")
	r.write("proc/loadavg", "0.50 0.40 0.30 1/100 1\n")
	r.write("proc/meminfo", "MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n")
	r.stat(0, 0)
	r.psi(0, 0, 0, 0, 0)
	return r
}

func (r *pressureRoot) write(rel, s string) {
	r.t.Helper()
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// stat writes a 4-CPU /proc/stat with busy and idle jiffies.
func (r *pressureRoot) stat(busy, idle uint64) {
	line := func(name string, b, i uint64) string {
		return name + " " + strconv.FormatUint(b, 10) + " 0 0 " + strconv.FormatUint(i, 10) + " 0 0 0 0 0 0\n"
	}
	s := line("cpu", busy, idle)
	for c := range 4 {
		s += line("cpu"+strconv.Itoa(c), busy/4, idle/4)
	}
	r.write("proc/stat", s)
}

func (r *pressureRoot) psi(cpu, memSome, memFull, ioSome, ioFull float64) {
	f := func(some, full float64) string {
		return "some avg10=" + strconv.FormatFloat(some, 'f', 2, 64) + " avg60=0.00 avg300=0.00 total=1\n" +
			"full avg10=" + strconv.FormatFloat(full, 'f', 2, 64) + " avg60=0.00 avg300=0.00 total=1\n"
	}
	r.write("proc/pressure/cpu", f(cpu, 0))
	r.write("proc/pressure/memory", f(memSome, memFull))
	r.write("proc/pressure/io", f(ioSome, ioFull))
}

func TestParsePSI(t *testing.T) {
	some, full, ok := parsePSI("some avg10=12.50 avg60=1.00 avg300=0.00 total=5\nfull avg10=3.25 avg60=0 avg300=0 total=1\n")
	if !ok || some != 12.5 || full != 3.25 {
		t.Fatalf("got %v %v %v", some, full, ok)
	}
	if _, _, ok := parsePSI("garbage"); ok {
		t.Fatal("garbage parsed")
	}
	if some, _, _ := parsePSI("some avg10=250 avg60=0"); some != 100 {
		t.Fatalf("not clamped: %v", some)
	}
}

func TestProbeReadsPressureSignals(t *testing.T) {
	r := newPressureRoot(t)
	r.psi(20, 1, 0, 5, 0)
	// The sensor's own cgroup stalls more than the host: the larger counts.
	r.write("sys/fs/cgroup/sensor/cpu.pressure", "some avg10=55.00 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\n")
	r.write("proc/sys/fs/file-nr", "1000\t0\t10000\n")
	r.write("proc/self/fd/0", "")
	r.write("proc/self/fd/1", "")
	now := time.Unix(1000, 0)
	p := &Prober{Root: r.root, NumCPU: fixedCPU(4), FDLimit: func() uint64 { return 4 }, Now: func() time.Time { return now }}
	r.stat(1000, 3000)
	p.Probe()
	// 10 s later: the host was 75 % busy (3 of 4 CPUs); the sensor's
	// cgroup used 5 CPU-seconds (0.5 CPU): 2.5 CPUs are someone else's.
	now = now.Add(10 * time.Second)
	r.stat(1000+3000, 3000+1000)
	r.write("sys/fs/cgroup/sensor/cpu.stat", "usage_usec 5000001\n")
	s := p.Probe().Signals
	if !s.PSI || s.CPUSome10 != 55 || s.MemSome10 != 1 || s.IOSome10 != 5 {
		t.Fatalf("psi %+v", s)
	}
	if !s.LoadKnown || s.LoadPerCPU != 0.125 {
		t.Fatalf("load %+v", s)
	}
	if !s.FDKnown || s.FDUsedPct != 50 { // 2 of 4 own descriptors beats 10 % of the host table
		t.Fatalf("fds %+v", s)
	}
	if !s.HostCPUKnown || s.HostCPUBusyPct != 75 || !s.ForeignKnown || s.ForeignCPUPct != 62.5 {
		t.Fatalf("cpu shares %+v", s)
	}
	if !s.MemKnown || s.MemAvailPct != 75 {
		t.Fatalf("memory %+v", s)
	}
}

// A host without PSI files: nothing is invented, the load average decides.
func TestProbeWithoutPSI(t *testing.T) {
	r := newPressureRoot(t)
	for _, f := range []string{"cpu", "memory", "io"} {
		_ = os.Remove(filepath.Join(r.root, "proc/pressure", f))
	}
	r.write("proc/loadavg", "14.00 1 1 1/1 1\n")
	p := &Prober{Root: r.root, NumCPU: fixedCPU(4)}
	s := p.Probe().Signals
	if s.PSI {
		t.Fatal("PSI reported without files")
	}
	lvl, reasons := DefaultPressureBounds().rate(s)
	if lvl != PressureOverloaded || !slices.Equal(reasons, []string{ReasonLoad}) {
		t.Fatalf("level %s reasons %v", lvl, reasons)
	}
}

func TestRateBounds(t *testing.T) {
	b := DefaultPressureBounds()
	for _, c := range []struct {
		name    string
		s       PressureSignals
		want    PressureLevel
		reasons []string
	}{
		{"quiet", PressureSignals{PSI: true, CPUSome10: 10, MemKnown: true, MemAvailPct: 60}, PressureOK, nil},
		{"cpu elevated", PressureSignals{PSI: true, CPUSome10: 45}, PressureElevated, []string{ReasonCPU}},
		{"cpu overloaded", PressureSignals{PSI: true, CPUSome10: 80}, PressureOverloaded, []string{ReasonCPU}},
		{"memory full", PressureSignals{PSI: true, MemFull10: 12}, PressureOverloaded, []string{ReasonMemory}},
		{"io some", PressureSignals{PSI: true, IOSome10: 50}, PressureElevated, []string{ReasonIO}},
		{"load ignored with PSI", PressureSignals{PSI: true, LoadKnown: true, LoadPerCPU: 9}, PressureOK, nil},
		{"low memory", PressureSignals{MemKnown: true, MemAvailPct: 4}, PressureOverloaded, []string{ReasonMemAvailable}},
		{"fds", PressureSignals{FDKnown: true, FDUsedPct: 85}, PressureElevated, []string{ReasonFDs}},
		{"several", PressureSignals{PSI: true, CPUSome10: 50, IOFull10: 35, MemKnown: true, MemAvailPct: 10},
			PressureOverloaded, []string{ReasonCPU, ReasonIO, ReasonMemAvailable}},
		{"unknown is ok", PressureSignals{}, PressureOK, nil},
	} {
		lvl, reasons := b.rate(c.s)
		if lvl != c.want || !slices.Equal(reasons, c.reasons) {
			t.Errorf("%s: %s %v, want %s %v", c.name, lvl, reasons, c.want, c.reasons)
		}
	}
}

func newTestGovernor(cfg GovernorConfig, slots int) (*Governor, *time.Time) {
	now := time.Unix(0, 0)
	g := newGovernor(cfg, nil, func() time.Time { return now }, func() int { return slots }, time.Second)
	return g, &now
}

func TestGovernorHysteresis(t *testing.T) {
	g, now := newTestGovernor(GovernorConfig{}, 4)
	hot := PressureSignals{PSI: true, CPUSome10: 80}
	warm := PressureSignals{PSI: true, CPUSome10: 60} // under 75 but over 75*0.7=52.5
	cool := PressureSignals{PSI: true, CPUSome10: 30} // under 75*0.7=52.5, over 40*0.7=28
	cold := PressureSignals{PSI: true, CPUSome10: 10}
	g.observe(hot)
	if g.Level() != PressureOverloaded {
		t.Fatalf("entered %s", g.Level())
	}
	g.observe(warm) // above the exit bound: stays
	g.observe(warm)
	if g.Level() != PressureOverloaded {
		t.Fatalf("left too early: %s", g.Level())
	}
	if p := g.Pressure(); !slices.Equal(p.Reasons, []string{ReasonCPU}) {
		t.Fatalf("reasons while held %v", p.Reasons)
	}
	g.observe(cool) // one quiet probe is not enough
	if g.Level() != PressureOverloaded {
		t.Fatalf("left after one quiet probe: %s", g.Level())
	}
	g.observe(hot) // a spike resets the count
	g.observe(cool)
	*now = now.Add(20 * time.Second)
	g.observe(cool)
	if g.Level() != PressureElevated {
		t.Fatalf("after two quiet probes %s, want elevated (30 is over the elevated exit bound)", g.Level())
	}
	if g.Pressure().LevelSeconds != 0 {
		t.Fatalf("level age not reset: %d", g.Pressure().LevelSeconds)
	}
	g.observe(cold)
	g.observe(cold)
	if g.Level() != PressureOK {
		t.Fatalf("after cold probes %s", g.Level())
	}
}

func TestGovernorAdmission(t *testing.T) {
	var holds atomic.Int32
	g, _ := newTestGovernor(GovernorConfig{Recheck: 20 * time.Millisecond,
		OnHold: func(context.Context, string, Pressure) { holds.Add(1) }}, 4)
	g.observe(PressureSignals{PSI: true, CPUSome10: 90})
	ctx := context.Background()
	// Overloaded with nothing running: one tool still starts.
	rel1, held, err := g.Admit(ctx, "nuclei")
	if err != nil || held != 0 {
		t.Fatalf("first launch: %v %s", err, held)
	}
	// A second one waits until the first ends.
	done := make(chan struct{})
	go func() {
		rel2, _, err := g.Admit(ctx, "dnsx")
		if err == nil {
			rel2()
		}
		close(done)
	}()
	waitFor(t, func() bool { return g.Held() == 1 })
	select {
	case <-done:
		t.Fatal("second launch not held")
	case <-time.After(50 * time.Millisecond):
	}
	rel1()
	rel1() // release is idempotent
	<-done
	if g.Running() != 0 || g.Held() != 0 || holds.Load() != 1 {
		t.Fatalf("running %d held %d holds %d", g.Running(), g.Held(), holds.Load())
	}
	// A held launch whose job ends never starts.
	rel, _, _ := g.Admit(ctx, "a")
	cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, _, err := g.Admit(cctx, "b"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held past its deadline: %v", err)
	}
	if g.Held() != 0 || g.Running() != 1 {
		t.Fatalf("held %d running %d", g.Held(), g.Running())
	}
	// The pressure dropping wakes held launches.
	go func() {
		time.Sleep(30 * time.Millisecond)
		for range 3 {
			g.observe(PressureSignals{PSI: true, CPUSome10: 1})
		}
	}()
	rel2, _, err := g.Admit(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	rel2()
	rel()
}

func TestGovernorElevatedLimitFollowsSlots(t *testing.T) {
	g, _ := newTestGovernor(GovernorConfig{Recheck: 10 * time.Millisecond}, 2)
	g.observe(PressureSignals{PSI: true, CPUSome10: 50})
	ctx := context.Background()
	r1, _, _ := g.Admit(ctx, "a")
	r2, _, _ := g.Admit(ctx, "b")
	cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, _, err := g.Admit(cctx, "c"); err == nil {
		t.Fatal("third launch admitted over the elevated limit")
	}
	r1()
	r2()
	// When ok the governor adds no limit of its own.
	g2, _ := newTestGovernor(GovernorConfig{}, 1)
	for range 10 {
		if _, _, err := g2.Admit(ctx, "x"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStartTimeoutFactor(t *testing.T) {
	g, _ := newTestGovernor(GovernorConfig{}, 1)
	if f := g.StartTimeoutFactor(); f != 1 {
		t.Fatalf("ok %v", f)
	}
	g.observe(PressureSignals{PSI: true, CPUSome10: 45})
	if f := g.StartTimeoutFactor(); f != 2 {
		t.Fatalf("elevated %v", f)
	}
	g.observe(PressureSignals{PSI: true, CPUSome10: 99})
	if f := g.StartTimeoutFactor(); f != MaxStartFactor {
		t.Fatalf("overloaded %v", f)
	}
	// Memory pressure alone with some CPU stall: the stall share counts.
	g2, _ := newTestGovernor(GovernorConfig{}, 1)
	g2.observe(PressureSignals{PSI: true, CPUSome10: 35})
	if f := g2.StartTimeoutFactor(); f < 1.5 || f > 1.6 {
		t.Fatalf("stall-derived factor %v", f)
	}
}

func TestNoisyNeighbor(t *testing.T) {
	g, _ := newTestGovernor(GovernorConfig{}, 1)
	g.observe(PressureSignals{PSI: true, CPUSome10: 10, ForeignKnown: true, ForeignCPUPct: 90})
	if g.Pressure().NoisyNeighbor {
		t.Fatal("a busy but unpressured host flagged")
	}
	g.observe(PressureSignals{PSI: true, CPUSome10: 80, ForeignKnown: true, ForeignCPUPct: 85})
	if !g.Pressure().NoisyNeighbor {
		t.Fatal("pressured host with foreign load not flagged")
	}
	g.observe(PressureSignals{PSI: true, CPUSome10: 80, ForeignKnown: true, ForeignCPUPct: 20})
	if g.Pressure().NoisyNeighbor {
		t.Fatal("the sensor's own load flagged as a neighbor")
	}
}

// The manager narrows the slots under pressure and reports it.
func TestManagerUnderPressure(t *testing.T) {
	r := newPressureRoot(t)
	now := time.Unix(5000, 0)
	m := NewManager(ManagerConfig{Cap: 8, ReservedMemBytes: -1, ProbeInterval: time.Second,
		Prober: &Prober{Root: r.root, NumCPU: fixedCPU(16), Now: func() time.Time { return now }}})
	if got := m.Slots(0); got != 8 {
		t.Fatalf("quiet slots %d", got)
	}
	r.psi(50, 0, 0, 0, 0)
	now = now.Add(2 * time.Second)
	if got := m.Slots(0); got != 4 {
		t.Fatalf("elevated slots %d, want 4", got)
	}
	r.psi(90, 0, 0, 0, 0)
	now = now.Add(2 * time.Second)
	if got := m.Slots(0); got != 1 {
		t.Fatalf("overloaded idle slots %d, want 1", got)
	}
	res, c := m.Snapshot(3)
	if c.SlotsTotal > 3 || c.SlotsFree != 0 {
		t.Fatalf("overloaded with 3 running: %+v", c)
	}
	if res.Pressure == nil || res.Pressure.Level != PressureOverloaded || !slices.Equal(res.Pressure.Reasons, []string{ReasonCPU}) {
		t.Fatalf("pressure %+v", res.Pressure)
	}
	m.Governor().Transient(TransientSlowStart)
	m.Governor().Transient(TransientRetried)
	m.Governor().Transient("bogus")
	_, c = m.Snapshot(0)
	if c.Transient == nil || c.Transient.SlowStarts != 1 || c.Transient.Retried != 1 {
		t.Fatalf("transient %+v", c.Transient)
	}
	// Overload also halves the AIMD window: recovery is gradual.
	if m.aimd.Limit() >= 8 {
		t.Fatalf("aimd window %d not narrowed", m.aimd.Limit())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
