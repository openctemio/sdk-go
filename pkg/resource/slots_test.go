package resource

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeSlots(t *testing.T) {
	cases := []struct {
		name      string
		capSlots  int
		hardMax   int
		cores     float64
		mem       int64
		jobCores  float64
		jobMem    int64
		wantSlots int
	}{
		{"cpu bound", 0, 64, 4, 64 * gib, 1, 512 * mib, 4},
		{"memory bound", 0, 64, 16, 2 * gib, 1, 512 * mib, 4},
		{"cap bound", 3, 64, 16, 64 * gib, 1, 512 * mib, 3},
		{"hard max bound", 0, 8, 64, 512 * gib, 0.5, 128 * mib, 8},
		{"fractional cores", 0, 64, 1.5, 64 * gib, 0.5, 512 * mib, 3},
		{"never below one", 0, 64, 0.5, 100 * mib, 2, 4 * gib, 1},
		{"unknown resources do not limit", 5, 64, 0, 0, 1, 512 * mib, 5},
		{"unknown and no cap: hard max", 0, 0, 0, 0, 1, 512 * mib, DefaultHardMaxSlots},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ComputeSlots(c.capSlots, c.hardMax, c.cores, c.mem, c.jobCores, c.jobMem); got != c.wantSlots {
				t.Fatalf("ComputeSlots = %d, want %d", got, c.wantSlots)
			}
		})
	}
}

func TestAIMD(t *testing.T) {
	a := NewAIMD(8)
	if a.Limit() != 8 {
		t.Fatalf("start %d", a.Limit())
	}
	a.Decrease()
	a.Decrease()
	if a.Limit() != 2 {
		t.Fatalf("after two halvings %d, want 2", a.Limit())
	}
	a.Decrease()
	a.Decrease()
	if a.Limit() != 1 {
		t.Fatalf("floor %d, want 1", a.Limit())
	}
	// Additive increase: one slot per window of successes.
	a.Increase() // 1 → 2
	if a.Limit() != 2 {
		t.Fatalf("after one success at 1: %d", a.Limit())
	}
	a.Increase() // 2.5
	if a.Limit() != 2 {
		t.Fatalf("half a window grew the limit: %d", a.Limit())
	}
	a.Increase() // 2.9
	a.Increase() // 3.24
	if a.Limit() != 3 {
		t.Fatalf("after a window: %d, want 3", a.Limit())
	}
	for range 1000 {
		a.Increase()
	}
	if a.Limit() != 8 {
		t.Fatalf("ceiling %d, want 8", a.Limit())
	}
	a.SetMax(4)
	if a.Limit() != 4 {
		t.Fatalf("SetMax clamp %d", a.Limit())
	}
}

func TestCostBook_LearnAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "tool-costs.json")
	b, err := NewCostBook(path)
	if err != nil {
		t.Fatal(err)
	}
	if e := b.Estimate("nuclei"); e.MemBytes != 512*mib || e.ThroughputTargetsPerMin != 3 {
		t.Fatalf("nuclei prior %+v", e)
	}
	b.Observe(JobSample{Tool: "nuclei", Targets: 10, Wall: 100 * time.Second, CPUSeconds: 150, PeakRSSBytes: 300 * mib})
	e := b.Estimate("nuclei")
	if e.CPUSeconds != 150 || e.MemBytes != 300*mib || e.ThroughputTargetsPerMin != 6 {
		t.Fatalf("first sample replaces the prior: %+v", e)
	}
	if c, m := b.jobDemand("nuclei"); c != 1.5 || m != 300*mib {
		t.Fatalf("demand %v %v", c, m)
	}
	// A higher peak is taken at once; failures teach nothing; a kill
	// raises memory by half.
	b.Observe(JobSample{Tool: "nuclei", Targets: 10, Wall: 100 * time.Second, CPUSeconds: 150, PeakRSSBytes: 400 * mib})
	b.Observe(JobSample{Tool: "nuclei", Targets: 1, Wall: time.Hour, Outcome: OutcomeFailed})
	if got := b.Estimate("nuclei").MemBytes; got != 400*mib {
		t.Fatalf("peak %d", got)
	}
	b.Observe(JobSample{Tool: "nuclei", Outcome: OutcomeKilled})
	if got := b.Estimate("nuclei").MemBytes; got != 600*mib {
		t.Fatalf("after OOM kill %d, want 600 MiB", got)
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", st, err)
	}

	again, err := NewCostBook(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := again.Estimate("nuclei"), b.Estimate("nuclei"); got != want {
		t.Fatalf("after reload %+v, want %+v", got, want)
	}
	var f costFile
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &f); err != nil || f.Version != 1 || f.Tools["nuclei"].Samples != 2 {
		t.Fatalf("file %s: %v", data, err)
	}
}

func TestCostBook_FailureAddsNoTool(t *testing.T) {
	b, _ := NewCostBook("")
	b.Observe(JobSample{Tool: "fake", Outcome: OutcomeFailed})
	b.Observe(JobSample{Tool: "fake2", Outcome: OutcomeTimeout})
	if len(b.Tools()) != 0 {
		t.Fatalf("tools %v", b.Tools())
	}
}

func TestCostBook_CorruptFileStartsOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool-costs.json")
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	b, err := NewCostBook(path)
	if err == nil || b == nil {
		t.Fatalf("want a usable book and an error, got %v %v", b, err)
	}
	if e := b.Estimate("trivy"); e.MemBytes != 1*gib {
		t.Fatalf("prior after corrupt file: %+v", e)
	}
	_ = os.WriteFile(path, []byte(`{"version":1,"tools":{"x":{"cores":-1}}}`), 0o600)
	b, _ = NewCostBook(path)
	if len(b.Tools()) != 0 {
		t.Fatalf("invalid entry kept: %v", b.Tools())
	}
}

// The manager sizes slots for the sensor's most demanding tool and halves
// them after a congestion signal.
func TestManager_SlotsAndCongestion(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(2_000_000, 0)
	writeV2(t, root, 1_000_000, 100, 0, 0) // 2 cores, memory unlimited (host 3.8 GB available)
	prober := &Prober{Root: root, NumCPU: fixedCPU(8), Now: func() time.Time { return now }}

	m := NewManager(ManagerConfig{Cap: 10, Prober: prober, Tools: []string{"betterleaks"}})
	if got := m.Slots(0); got != 4 { // 2 cores / 0.5 core
		t.Fatalf("betterleaks slots %d, want 4", got)
	}
	m.SetTools([]string{"betterleaks", "semgrep"})
	// semgrep: 1 core, 1.5 GiB; 2 cores → 2; memory 3,072,000,000 / 1.5 GiB → 1.
	if got := m.Slots(0); got != 1 {
		t.Fatalf("semgrep-bound slots %d, want 1", got)
	}
	m.SetTools([]string{"betterleaks"})
	if got := m.Slots(0); got != 4 {
		t.Fatalf("back to betterleaks %d, want 4", got)
	}

	// An OOM kill on the next probe halves the window: 4 → 2.
	now = now.Add(time.Minute)
	writeV2(t, root, 2_000_000, 200, 0, 1)
	if got := m.Slots(0); got != 2 {
		t.Fatalf("after OOM kill %d, want 2", got)
	}
	// A timeout halves again; successes grow it back slowly.
	m.Observe(JobSample{Tool: "betterleaks", Outcome: OutcomeTimeout})
	if got := m.Slots(0); got != 1 {
		t.Fatalf("after timeout %d, want 1", got)
	}
	for range 3 {
		m.Observe(JobSample{Tool: "betterleaks", Wall: time.Minute, Targets: 1})
	}
	if got := m.Slots(0); got < 2 || got > 4 {
		t.Fatalf("after successes %d, want it to grow back (2-4)", got)
	}

	res, c := m.Snapshot(1)
	if res.CPUCores != 2 || c.ActiveJobs != 1 || c.SlotsFree != c.SlotsTotal-1 || c.PerTool["betterleaks"].ThroughputTargetsPerMin == 0 {
		t.Fatalf("snapshot %+v %+v", res, c)
	}
}

// Running jobs' memory counts as budget: slots do not shrink because the
// sensor is busy.
func TestManager_RunningJobsMemoryIsBudget(t *testing.T) {
	m := NewManager(ManagerConfig{Cap: 10, Tools: []string{"trivy"}})
	r := ProbeResult{Resources: HostResources{CPUCores: 16, MemTotalBytes: 8 * gib, MemAvailableBytes: 2 * gib}}
	if got := m.slots(r, 0); got != 2 {
		t.Fatalf("idle %d, want 2", got)
	}
	if got := m.slots(r, 4); got != 6 { // 2 GiB free + 4 x 1 GiB held
		t.Fatalf("with 4 running %d, want 6", got)
	}
	if got := m.slots(r, 100); got != 8 { // capped by total memory
		t.Fatalf("budget not capped by total: %d", got)
	}
}

func TestCapacityJSON(t *testing.T) {
	c := Capacity{SlotsTotal: 4, SlotsFree: 1, ActiveJobs: 3, PerTool: map[string]ToolEstimate{"nuclei": {CPUSeconds: 20, MemBytes: 1 << 29, ThroughputTargetsPerMin: 3}}}
	b, _ := json.Marshal(c)
	want := `{"slots_total":4,"slots_free":1,"active_jobs":3,"per_tool":{"nuclei":{"est_cpu_s":20,"est_mem_bytes":536870912,"throughput_targets_per_min":3}}}`
	if string(b) != want {
		t.Fatalf("capacity JSON\n got %s\nwant %s", b, want)
	}
	h, _ := json.Marshal(HostResources{CPUCores: 1.5, CPUUsedPct: 12.5, MemTotalBytes: 2, MemAvailableBytes: 1, Load1: 0.5, DiskFreeBytes: 9})
	wantH := `{"cpu_cores":1.5,"cpu_used_pct":12.5,"mem_total_bytes":2,"mem_available_bytes":1,"load1":0.5,"disk_free_bytes":9}`
	if string(h) != wantH {
		t.Fatalf("resources JSON\n got %s\nwant %s", h, wantH)
	}
}
