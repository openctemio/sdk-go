package conformance

// api RFC-030 Phase 0 (B6): the command poller takes a free slot before it
// claims a command, asks the platform for no more commands than it has free
// slots, and never runs a command whose start the platform refused. A
// sensor that claimed more than it could run held acknowledged commands the
// platform's reaper re-queued after 10 minutes, so two sensors scanned the
// same assets.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/resource"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// blockingExecutor runs until released and records the most commands it
// ran at once.
type blockingExecutor struct {
	release chan struct{}
	started chan string
	running atomic.Int32
	maxSeen atomic.Int32
	mu      sync.Mutex
	ran     []string
}

func newBlockingExecutor() *blockingExecutor {
	return &blockingExecutor{release: make(chan struct{}), started: make(chan string, 100)}
}

func (e *blockingExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	n := e.running.Add(1)
	defer e.running.Add(-1)
	for {
		m := e.maxSeen.Load()
		if n <= m || e.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	e.mu.Lock()
	e.ran = append(e.ran, cmd.ID)
	e.mu.Unlock()
	e.started <- cmd.ID
	select {
	case <-e.release:
	case <-ctx.Done():
	}
	return &core.CommandExecutionResult{}, nil
}

func (e *blockingExecutor) ranIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.ran...)
}

func cmdID(i int) string { return fmt.Sprintf("0192a3b4-0000-7000-8000-%012d", i) }

func states(f *FakePlatform, n int) map[string]int {
	out := map[string]int{}
	for i := 1; i <= n; i++ {
		s, _ := f.CommandState(cmdID(i))
		out[s]++
	}
	return out
}

// With 2 slots and 10 pending commands the sensor claims 2, leaves 8
// pending for others, asks for limit=2, and claims the rest only as slots
// free up.
func TestSlots_ClaimNoMoreThanFreeSlots(t *testing.T) {
	f := newControlFake(t)
	const total = 10
	for i := 1; i <= total; i++ {
		f.QueueCommand(cmdID(i))
	}
	var mu sync.Mutex
	var limits []string
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, protov2.CommandsPath) {
			mu.Lock()
			limits = append(limits, r.URL.Query().Get("limit"))
			mu.Unlock()
		}
		return nil
	})
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })

	exec := newBlockingExecutor()
	p := core.NewCommandPoller(c, exec, &core.CommandPollerConfig{PollInterval: time.Hour, MaxConcurrent: 2})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	for i := 0; i < 2; i++ {
		select {
		case <-exec.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the first two commands did not start")
		}
	}
	// Give an over-claiming poller time to show itself.
	time.Sleep(200 * time.Millisecond)
	if got := states(f, total); got["running"] != 2 || got["pending"] != 8 || got["acknowledged"] != 0 {
		t.Fatalf("with 2 slots: states %v, want 2 running and 8 pending", got)
	}
	if p.ActiveJobs() != 2 || p.MaxJobs() != 2 {
		t.Fatalf("load: active %d max %d, want 2/2", p.ActiveJobs(), p.MaxJobs())
	}
	mu.Lock()
	first := append([]string(nil), limits...)
	mu.Unlock()
	if len(first) == 0 || first[0] != "2" {
		t.Fatalf("poll limits %v, want the first poll to ask for limit=2", first)
	}

	// Release everything: freed slots pull the rest without waiting for
	// the (one-hour) poll interval, never more than 2 at once.
	close(exec.release)
	deadline := time.Now().Add(10 * time.Second)
	for states(f, total)["completed"] != total {
		if time.Now().After(deadline) {
			t.Fatalf("not all commands completed: %v", states(f, total))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m := exec.maxSeen.Load(); m > 2 {
		t.Fatalf("ran %d commands at once with 2 slots", m)
	}
	if n := len(exec.ranIDs()); n != total {
		t.Fatalf("executed %d commands, want %d (each exactly once)", n, total)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range limits {
		if l != "1" && l != "2" {
			t.Fatalf("poll limits %v: a poll asked for more than the free slots", limits)
		}
	}
}

// A command whose start the platform refuses (409: re-queued and handed to
// another sensor, or canceled) is not executed.
func TestSlots_FailedStartIsNotExecuted(t *testing.T) {
	f := newControlFake(t)
	f.QueueCommand(cmdID(1))
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/"+protov2.StartAction) {
			return &FaultAnswer{Status: http.StatusConflict, Problem: protov2.ProblemInvalidTransition}
		}
		return nil
	})
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })

	exec := newBlockingExecutor()
	close(exec.release)
	p := core.NewCommandPoller(c, exec, &core.CommandPollerConfig{PollInterval: time.Hour, MaxConcurrent: 2})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(f.RequestsTo(http.MethodPost, "")) == 0 || !startTried(f) {
		if time.Now().After(deadline) {
			t.Fatal("the poller never tried to start the command")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let a buggy poller run it.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if ran := exec.ranIDs(); len(ran) != 0 {
		t.Fatalf("executed %v after the platform refused the start", ran)
	}
	if s, _ := f.CommandState(cmdID(1)); s != "acknowledged" {
		t.Fatalf("state %q, want acknowledged (left for the platform to re-queue)", s)
	}
	if p.ActiveJobs() != 0 {
		t.Fatalf("the refused command still holds a slot: active %d", p.ActiveJobs())
	}
}

func startTried(f *FakePlatform) bool {
	for _, r := range f.Requests() {
		if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/"+protov2.StartAction) {
			return true
		}
	}
	return false
}

// A sensor with a LoadReporter sends active_jobs on every heartbeat, also
// when it is 0 (idle), and max_concurrent_jobs; without one, 0 is left out
// as before.
func TestSlots_HeartbeatCarriesLoad(t *testing.T) {
	for _, v2 := range []bool{true} {
		t.Run(fmt.Sprintf("v2=%v", v2), func(t *testing.T) {
			f := NewFakePlatform(v2)
			f.SetControl(v2)
			t.Cleanup(f.Close)
			c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
			t.Cleanup(func() { _ = c.Close() })

			p := core.NewCommandPoller(c, newBlockingExecutor(), &core.CommandPollerConfig{MaxConcurrent: 3})
			s := core.NewBaseSensor(&core.BaseSensorConfig{Name: "load", HeartbeatInterval: time.Hour}, c)
			s.SetLoadReporter(p)
			if _, err := s.FirstHeartbeat(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.SendHeartbeat(context.Background(), status()); err != nil {
				t.Fatal(err)
			}
			beats := f.Heartbeats()
			if len(beats) != 2 {
				t.Fatalf("%d heartbeats", len(beats))
			}
			var withLoad, without map[string]any
			_ = json.Unmarshal(beats[0], &withLoad)
			_ = json.Unmarshal(beats[1], &without)
			if v, ok := withLoad["active_jobs"]; !ok || v != float64(0) {
				t.Fatalf("active_jobs %v (present %v), want 0 sent: %s", v, ok, beats[0])
			}
			if withLoad["max_concurrent_jobs"] != float64(3) {
				t.Fatalf("max_concurrent_jobs %v, want 3: %s", withLoad["max_concurrent_jobs"], beats[0])
			}
			if _, ok := without["active_jobs"]; ok {
				t.Fatalf("active_jobs sent without a load reporter: %s", beats[1])
			}
		})
	}
}

// Stopping the poller with a scan running: after the drain grace the scan
// is canceled and RELEASED on v2 (the platform has it pending again at
// once), never reported failed, and it ran once.
func TestQueue_DrainReleasesOverV2(t *testing.T) {
	f := newControlFake(t)
	f.QueueCommand(cmdID(1))
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })
	exec := newBlockingExecutor() // never released: runs until canceled
	p := core.NewCommandPoller(c, exec, &core.CommandPollerConfig{PollInterval: time.Hour, MaxConcurrent: 2, DrainGrace: 100 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	<-exec.started
	cancel()
	<-done

	rel := f.Releases()
	if len(rel) != 1 || rel[0].CommandID != cmdID(1) || rel[0].Reason != core.ReleaseReasonShutdown {
		t.Fatalf("releases %+v", rel)
	}
	if s, _ := f.CommandState(cmdID(1)); s != "pending" {
		t.Fatalf("state %q, want pending (re-queued)", s)
	}
	if n := len(exec.ranIDs()); n != 1 {
		t.Fatalf("ran %d times", n)
	}
}

// A platform without the release transition (404 on v2): the
// command is failed with "released: <reason>" instead of waiting for a
// timeout.
func TestRelease_FallsBackToFail(t *testing.T) {
	for _, v2 := range []bool{true} {
		t.Run(fmt.Sprintf("v2=%v", v2), func(t *testing.T) {
			f := NewFakePlatform(v2)
			f.SetControl(v2)
			t.Cleanup(f.Close)
			f.OpenCommand(cmdID(7))
			f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
				if strings.HasSuffix(r.URL.Path, "/"+protov2.ReleaseAction) {
					return &FaultAnswer{Status: http.StatusNotFound} // route missing
				}
				return nil
			})
			c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
			t.Cleanup(func() { _ = c.Close() })
			if err := c.ReleaseCommand(context.Background(), cmdID(7), core.ReleaseReasonDraining); err != nil {
				t.Fatal(err)
			}
			s, msg := f.CommandState(cmdID(7))
			if s != "failed" || msg != "released: draining" {
				t.Fatalf("state %q %q", s, msg)
			}
		})
	}
}

// The heartbeat carries resources, capacity, queue and the held ids with
// the names the platform reads.
func TestHeartbeat_WorkBlocks(t *testing.T) {
	for _, v2 := range []bool{true} {
		t.Run(fmt.Sprintf("v2=%v", v2), func(t *testing.T) {
			f := NewFakePlatform(v2)
			f.SetControl(v2)
			t.Cleanup(f.Close)
			c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
			t.Cleanup(func() { _ = c.Close() })
			st := status()
			st.Resources = &resource.HostResources{CPUCores: 2, CPUUsedPct: 10, MemTotalBytes: 4 << 30, MemAvailableBytes: 2 << 30, Load1: 0.5, DiskFreeBytes: 1 << 40}
			st.Capacity = &resource.Capacity{SlotsTotal: 2, SlotsFree: 1, ActiveJobs: 1, PerTool: map[string]resource.ToolEstimate{"nuclei": {CPUSeconds: 20, MemBytes: 1 << 29, ThroughputTargetsPerMin: 3}}}
			st.Queue = &core.QueueStats{Claimed: 1, Running: 1, OldestAgeSeconds: 12}
			st.RunningCommands = []string{cmdID(1)}
			if err := c.SendHeartbeat(context.Background(), st); err != nil {
				t.Fatal(err)
			}
			var got struct {
				Resources struct {
					CPUCores          float64 `json:"cpu_cores"`
					CPUUsedPct        float64 `json:"cpu_used_pct"`
					MemTotalBytes     int64   `json:"mem_total_bytes"`
					MemAvailableBytes int64   `json:"mem_available_bytes"`
					Load1             float64 `json:"load1"`
					DiskFreeBytes     int64   `json:"disk_free_bytes"`
				} `json:"resources"`
				Capacity struct {
					SlotsTotal int `json:"slots_total"`
					SlotsFree  int `json:"slots_free"`
					ActiveJobs int `json:"active_jobs"`
					PerTool    map[string]struct {
						EstCPUS     float64 `json:"est_cpu_s"`
						EstMemBytes int64   `json:"est_mem_bytes"`
						Throughput  float64 `json:"throughput_targets_per_min"`
					} `json:"per_tool"`
				} `json:"capacity"`
				Queue struct {
					Claimed          int   `json:"claimed"`
					Running          int   `json:"running"`
					QueuedLocal      int   `json:"queued_local"`
					OldestAgeSeconds int64 `json:"oldest_age_seconds"`
				} `json:"queue"`
				Running []string `json:"running"`
			}
			beats := f.Heartbeats()
			if err := json.Unmarshal(beats[len(beats)-1], &got); err != nil {
				t.Fatal(err)
			}
			if got.Resources.CPUCores != 2 || got.Resources.MemAvailableBytes != 2<<30 || got.Resources.DiskFreeBytes != 1<<40 || got.Resources.Load1 != 0.5 || got.Resources.CPUUsedPct != 10 || got.Resources.MemTotalBytes != 4<<30 {
				t.Fatalf("resources %+v", got.Resources)
			}
			if got.Capacity.SlotsTotal != 2 || got.Capacity.SlotsFree != 1 || got.Capacity.ActiveJobs != 1 || got.Capacity.PerTool["nuclei"].EstMemBytes != 1<<29 || got.Capacity.PerTool["nuclei"].Throughput != 3 || got.Capacity.PerTool["nuclei"].EstCPUS != 20 {
				t.Fatalf("capacity %+v", got.Capacity)
			}
			if got.Queue.Claimed != 1 || got.Queue.Running != 1 || got.Queue.OldestAgeSeconds != 12 || len(got.Running) != 1 {
				t.Fatalf("queue %+v running %v", got.Queue, got.Running)
			}
		})
	}
}

// With the outbox (the daemon default) a command's complete reaches the
// platform BEFORE the slot it held is reused: the platform counts the
// command as held until then, so an earlier poll was refused (no free
// capacity) or over-filled the sensor (api RFC-030 E2E finding F1).
func TestSlots_CompleteBeforeNextPollWithOutbox(t *testing.T) {
	f := newControlFake(t)
	const total = 4
	for i := 1; i <= total; i++ {
		f.QueueCommand(cmdID(i))
	}
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	if err := c.EnableOutbox(client.OutboxConfig{Dir: t.TempDir(), LegacyRetryQueueDir: "-"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	exec := newBlockingExecutor()
	close(exec.release)
	p := core.NewCommandPoller(c, exec, &core.CommandPollerConfig{PollInterval: time.Hour, MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	deadline := time.Now().Add(10 * time.Second)
	for states(f, total)["completed"] != total {
		if time.Now().After(deadline) {
			t.Fatalf("not all completed: %v", states(f, total))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Request log: every claim after the first must follow the complete of
	// the command before it (1 slot: never two held at once).
	held := 0
	for _, r := range f.Requests() {
		if r.Method != http.MethodPost {
			continue
		}
		switch {
		case strings.HasSuffix(r.Path, "/"+protov2.ClaimAction):
			held++
			if held > 1 {
				t.Fatalf("claimed %s while another command was still held (complete not yet sent)", r.Path)
			}
		case strings.HasSuffix(r.Path, "/"+protov2.CompleteAction), strings.HasSuffix(r.Path, "/"+protov2.FailAction):
			held--
		}
	}
}

// Every heartbeat names the SDK and the sensor binary: a
// BaseSensor from its config, and a bare client.SendHeartbeat by itself.
func TestHeartbeat_SDKAndSensorBuild(t *testing.T) {
	for _, v2 := range []bool{true} {
		t.Run(fmt.Sprintf("v2=%v", v2), func(t *testing.T) {
			f := NewFakePlatform(v2)
			f.SetControl(v2)
			t.Cleanup(f.Close)
			c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
			t.Cleanup(func() { _ = c.Close() })

			s := core.NewBaseSensor(&core.BaseSensorConfig{Name: "s", Version: "v0.6.1", ProductName: "openctemio-sensor",
				Commit: "deadbeef", BuildTime: "2026-10-02T10:00:00Z", HeartbeatInterval: time.Hour}, c)
			if _, err := s.FirstHeartbeat(context.Background()); err != nil {
				t.Fatal(err)
			}
			// A sensor that builds its own status: the client fills both.
			if err := c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "bare", Status: core.SensorStateRunning, Version: "3.0.0"}); err != nil {
				t.Fatal(err)
			}
			b := f.HeartbeatBuilds()
			if len(b) != 2 {
				t.Fatalf("%d heartbeats", len(b))
			}
			for i, hb := range b {
				if hb.SDK == nil || hb.SDK.Name != "openctem-sdk-go" || hb.SDK.Version == "" {
					t.Fatalf("heartbeat %d sdk %+v", i, hb.SDK)
				}
			}
			got := *b[0].Sensor
			if got.Name != "openctemio-sensor" || got.Version != "0.6.1" || got.Commit != "deadbeef" || got.BuildTime != "2026-10-02T10:00:00Z" {
				t.Fatalf("base sensor block %+v", got)
			}
			if b[1].Sensor == nil || b[1].Sensor.Version != "3.0.0" || b[1].Sensor.Name == "" {
				t.Fatalf("bare heartbeat sensor block %+v", b[1].Sensor)
			}
		})
	}
}
