//go:build linux

package resource

// Fault injection (research/318): a CPU hog and memory pressure inside a
// small container drive the governor through its levels on a real kernel.
// Run by scripts/fault-injection.sh (OPENCTEM_FAULT_INJECTION=1) in a
// container with a CPU quota and a memory limit; skipped elsewhere, so a
// developer machine or a shared CI runner is never loaded.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func faultInjection(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENCTEM_FAULT_INJECTION") != "1" {
		t.Skip("fault injection runs in a throwaway container (scripts/fault-injection.sh)")
	}
}

// liveManager probes the real kernel, but reads pressure from the
// container's own cgroup only: the host's PSI would make the test depend
// on whatever else the machine runs (the noisy neighbor this feature is
// about).
func liveManager(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	for _, link := range []string{"proc/self", "proc/stat", "proc/meminfo", "proc/loadavg", "proc/sys", "sys"} {
		dst := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/"+link, dst); err != nil {
			t.Fatal(err)
		}
	}
	return NewManager(ManagerConfig{Cap: 8, ProbeInterval: time.Second, ReservedMemBytes: -1,
		Prober:   &Prober{Root: root, FDLimit: fdSoftLimit},
		Governor: GovernorConfig{Recheck: 200 * time.Millisecond}})
}

// waitLevel probes every second until cond holds or the time is up.
func waitLevel(t *testing.T, m *Manager, within time.Duration, cond func(Pressure) bool) Pressure {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		m.Slots(0)
		p := m.Governor().Pressure()
		if cond(p) {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("not reached within %s; last %+v", within, p)
		}
		time.Sleep(time.Second)
	}
}

// A CPU hog inside a CPU quota: the cgroup is throttled, the level rises
// with reason cpu, a second launch is held, and the throttling clears when
// the hog stops. The host's own load may add CPU stall on top, so the test
// watches the throttle signal, not the level, for recovery.
func TestFaultInjectionCPUHog(t *testing.T) {
	faultInjection(t)
	m := liveManager(t)
	waitLevel(t, m, 30*time.Second, func(p Pressure) bool { return p.CPUThrottledPct < 30 })

	var stop atomic.Bool
	var wg sync.WaitGroup
	for range 4 * max(runtime.NumCPU(), 2) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			x := 0
			for !stop.Load() {
				x++
			}
			_ = x
		}()
	}
	p := waitLevel(t, m, 30*time.Second, func(p Pressure) bool { return p.Level == PressureOverloaded })
	t.Logf("under the hog: %+v", p)
	if !slices.Contains(p.Reasons, ReasonCPU) || p.CPUThrottledPct < 60 {
		t.Fatalf("reasons %v throttled %.1f %%, want cpu over 60 %%", p.Reasons, p.CPUThrottledPct)
	}
	if f := m.Governor().StartTimeoutFactor(); f != MaxStartFactor {
		t.Fatalf("start factor %v under a CPU hog", f)
	}
	ctx := context.Background()
	rel, _, _ := m.Governor().Admit(ctx, "first")
	cctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	if _, _, err := m.Governor().Admit(cctx, "second"); err == nil {
		t.Fatal("a second launch was admitted into an overloaded host")
	}
	cancel()
	rel()
	if _, c := m.Snapshot(1); c.SlotsFree != 0 {
		t.Fatalf("free slots %d while overloaded and busy", c.SlotsFree)
	}
	stop.Store(true)
	wg.Wait()
	p = waitLevel(t, m, 30*time.Second, func(p Pressure) bool { return p.CPUThrottledPct < 10 })
	t.Logf("after the hog: %+v", p)
}

// Memory held up to the container's limit: the level rises with reason
// mem_available and clears when the memory is given back.
func TestFaultInjectionMemoryPressure(t *testing.T) {
	faultInjection(t)
	m := liveManager(t)
	res, _ := m.Snapshot(0)
	if res.MemTotalBytes == 0 || res.MemTotalBytes > 2<<30 {
		t.Skipf("needs a container memory limit under 2 GiB, have %d", res.MemTotalBytes)
	}
	// Hold memory until less than 12 % of the limit is available.
	var hold [][]byte
	for range 400 {
		r, _ := m.Snapshot(0)
		if float64(r.MemAvailableBytes) < 0.12*float64(r.MemTotalBytes) {
			break
		}
		b := make([]byte, 4<<20)
		for i := range b {
			if i%4096 == 0 {
				b[i] = 1
			}
		}
		hold = append(hold, b)
	}
	p := waitLevel(t, m, 15*time.Second, func(p Pressure) bool { return slices.Contains(p.Reasons, ReasonMemAvailable) })
	t.Logf("under memory pressure (%d MiB held): %+v", len(hold)*4, p)
	if p.Level == PressureOK {
		t.Fatalf("level ok with reasons %v", p.Reasons)
	}
	runtime.KeepAlive(hold)
	// hold is not read again: the collector may take it back.
	runtime.GC()
	debug.FreeOSMemory()
	waitLevel(t, m, 60*time.Second, func(p Pressure) bool { return !slices.Contains(p.Reasons, ReasonMemAvailable) })
}
