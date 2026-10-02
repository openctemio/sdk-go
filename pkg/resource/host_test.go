package resource

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedCPU(n int) func() int { return func() int { return n } }

func TestProbe_CgroupV2(t *testing.T) {
	p := &Prober{Root: "testdata/cgroupv2", NumCPU: fixedCPU(8), WorkDir: "/work",
		DiskFree: func(dir string) int64 {
			if dir != "/work" {
				t.Fatalf("disk free asked for %q", dir)
			}
			return 50 << 30
		}}
	r := p.Probe().Resources
	want := HostResources{
		CPUCores:          1.5, // cpu.max 150000/100000 < cpuset 4 < 8 online
		MemTotalBytes:     2 << 30,
		MemAvailableBytes: 2<<30 - (1<<30 - 256<<20), // limit - (current - inactive_file)
		Load1:             1.25,
		DiskFreeBytes:     50 << 30,
	}
	if r != want {
		t.Fatalf("v2 probe\n got %+v\nwant %+v", r, want)
	}
}

func TestProbe_CgroupV1(t *testing.T) {
	p := &Prober{Root: "testdata/cgroupv1", NumCPU: fixedCPU(8)}
	r := p.Probe().Resources
	want := HostResources{
		CPUCores:          2.5, // quota 250000/100000 < cpuset 0-1,4-5 (4) < 8
		MemTotalBytes:     4 << 30,
		MemAvailableBytes: 2 << 30, // 4G - (3G - 1G inactive)
		Load1:             0.5,
	}
	if r != want {
		t.Fatalf("v1 probe\n got %+v\nwant %+v", r, want)
	}
}

func TestProbe_CgroupV1NoLimits(t *testing.T) {
	p := &Prober{Root: "testdata/cgroupv1-unlimited", NumCPU: fixedCPU(4)}
	r := p.Probe().Resources
	want := HostResources{CPUCores: 4, MemTotalBytes: 8000000 * 1024, MemAvailableBytes: 6000000 * 1024, Load1: 3}
	if r != want {
		t.Fatalf("unlimited probe\n got %+v\nwant %+v", r, want)
	}
}

func TestProbe_NoProcNoCgroup(t *testing.T) {
	p := &Prober{Root: t.TempDir(), NumCPU: fixedCPU(2)}
	r := p.Probe().Resources
	if r != (HostResources{CPUCores: 2}) {
		t.Fatalf("empty root: %+v", r)
	}
}

// writeV2 writes a minimal cgroup v2 tree whose counters a test changes
// between probes.
func writeV2(t *testing.T, root string, usageUsec, periods, throttled, oomKills int) {
	t.Helper()
	files := map[string]string{
		"proc/meminfo":                     "MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\n",
		"proc/self/cgroup":                 "0::/sensor.slice\n",
		"sys/fs/cgroup/cgroup.controllers": "cpu memory\n",
		// the process's own cgroup, resolved from /proc/self/cgroup
		"sys/fs/cgroup/sensor.slice/cpu.max":       "200000 100000\n",
		"sys/fs/cgroup/sensor.slice/memory.max":    "max\n",
		"sys/fs/cgroup/sensor.slice/cpu.stat":      "usage_usec " + itoa(usageUsec) + "\nnr_periods " + itoa(periods) + "\nnr_throttled " + itoa(throttled) + "\n",
		"sys/fs/cgroup/sensor.slice/memory.events": "oom 0\noom_kill " + itoa(oomKills) + "\n",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func itoa(n int) string { return formatInt(int64(n)) }

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// CPU use, throttling and OOM kills are deltas between probes, on the
// process's own (nested) cgroup.
func TestProbe_Deltas(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_000_000, 0)
	p := &Prober{Root: root, NumCPU: fixedCPU(8), Now: func() time.Time { return now }}

	writeV2(t, root, 1_000_000, 100, 0, 1)
	first := p.Probe()
	if first.Resources.CPUCores != 2 || first.Resources.CPUUsedPct != 0 || first.ThrottledRatio != 0 || first.OOMKills != 0 {
		t.Fatalf("first probe: %+v", first)
	}
	if first.Resources.MemTotalBytes != 4000000*1024 {
		t.Fatalf("memory.max=max must leave the host's memory: %+v", first.Resources)
	}

	// 10 s later: 15 CPU-seconds used of 2 cores x 10 s = 75 %; 60 of 100
	// periods throttled; 2 more OOM kills.
	now = now.Add(10 * time.Second)
	writeV2(t, root, 16_000_000, 200, 60, 3)
	second := p.Probe()
	if second.Resources.CPUUsedPct != 75 {
		t.Fatalf("cpu used %v, want 75", second.Resources.CPUUsedPct)
	}
	if second.ThrottledRatio != 0.6 || second.OOMKills != 2 {
		t.Fatalf("pressure: %+v", second)
	}
}

func TestProbe_HostCPUWithoutQuota(t *testing.T) {
	root := t.TempDir()
	stat := filepath.Join(root, "proc", "stat")
	_ = os.MkdirAll(filepath.Dir(stat), 0o755)
	_ = os.WriteFile(stat, []byte("cpu  100 0 100 800 0 0 0 0 0 0\n"), 0o600)
	p := &Prober{Root: root, NumCPU: fixedCPU(4)}
	p.Probe()
	// +300 busy, +100 idle → 75 %.
	_ = os.WriteFile(stat, []byte("cpu  300 0 200 900 0 0 0 0 0 0\n"), 0o600)
	if got := p.Probe().Resources.CPUUsedPct; got != 75 {
		t.Fatalf("host cpu used %v, want 75", got)
	}
}

func TestCPUListCount(t *testing.T) {
	for in, want := range map[string]int{"0": 1, "0-3": 4, "0-1,4-5": 4, "0,2,4": 3, "": 0, "3-1": 0, "x": 0, "0-63\n": 64} {
		if got := cpuListCount(in); got != want {
			t.Errorf("cpuListCount(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestDiskFreeReal(t *testing.T) {
	// The real statfs: the temp dir's file system has some space (0 only on
	// systems without statfs).
	if diskFree(t.TempDir()) < 0 {
		t.Fatal("negative disk free")
	}
}
