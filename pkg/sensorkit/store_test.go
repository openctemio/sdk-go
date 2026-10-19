package sensorkit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/localstore"
	"github.com/openctemio/sdk-go/pkg/outbox"
	"github.com/openctemio/sdk-go/pkg/sensorkit/workspace"
)

// stubOutbox is an outbox as the janitor sees it.
type stubOutbox struct {
	ok  bool
	why string
}

func (s *stubOutbox) Bytes() (int64, int64) { return 0, 0 }
func (s *stubOutbox) PurgeDead(context.Context, time.Duration, int) (int, int64) {
	return 0, 0
}
func (s *stubOutbox) DropTenant(string) (int, int, error) { return 0, 0, nil }
func (s *stubOutbox) AcceptsWork() (bool, string)         { return s.ok, s.why }

// stubWorkspaces reports a size and removes nothing.
type stubWorkspaces struct{ bytes int64 }

func (s *stubWorkspaces) SweepBounded(context.Context, func(string, string) bool, int) (int, error) {
	return 0, nil
}
func (s *stubWorkspaces) Bytes() int64             { return s.bytes }
func (s *stubWorkspaces) EraseTenant(string) error { return nil }

// kitStoreDirs are where a kit with outbox dir d keeps its store.
func kitStoreDirs(outboxDir string) (store, work string) {
	return resolveStorePaths(outboxDir)
}

// A job an earlier run held and never finished is reported to the platform
// as failed when the sensor starts, and what a crash left in the workspaces
// is swept.
func TestRun_RecoversInterruptedJobsAtStart(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, _ := baseOptions(t, f)
	storeDir, workDir := kitStoreDirs(opts.Outbox.Dir)

	// The earlier run: a journaled job in a step, and a workspace left behind.
	const cmdID = "0192a3b4-0000-7000-8000-0000000000aa"
	st, err := localstore.Open(localstore.Options{Dir: storeDir, CreateKey: true, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	j, err := st.Journal(localstore.SensorTenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(localstore.JobRecord{CommandID: cmdID}); err != nil {
		t.Fatal(err)
	}
	if err := j.StepStarted(cmdID, "scan", true); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := workspace.Open(workDir)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := m.Create("_sensor", "crashed-job", workspace.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	left := ws.Dir()
	f.OpenCommand(cmdID)

	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if k.ls == nil || k.ls.recovery != 1 {
		t.Fatalf("recovered %+v, want 1", k.ls)
	}
	if !strings.Contains(out.String(), "Recovery: 1 interrupted job(s)") {
		t.Errorf("start output does not say it:\n%s", out.String())
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Errorf("the crashed workspace was not swept: %v", err)
	}
	stop := runKit(t, k)
	waitFor(t, "the interrupted job to be reported failed", func() bool {
		s, e := f.CommandState(cmdID)
		return s == "failed" && strings.Contains(e, "step scan")
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	// Reported once: the next start finds nothing to recover.
	opts2, _, _ := baseOptions(t, f)
	opts2.Outbox.Dir = opts.Outbox.Dir
	opts2.StateDir = opts.StateDir
	k2, err := New(opts2)
	if err != nil {
		t.Fatal(err)
	}
	defer k2.closeClient()
	if k2.ls.recovery != 0 {
		t.Errorf("recovered %d again", k2.ls.recovery)
	}
}

// The janitor sweeps once at start and again after results are acknowledged;
// the heartbeat's local-store report describes the data. An older platform
// that does not list the feature is sent no member.
func TestRun_JanitorRunsAfterAckAndReports(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	cmdID := "0192a3b4-0000-7000-8000-000000000002"
	opts, out, errw := baseOptions(t, f)
	target := t.TempDir()
	f.QueueCommandPayload(cmdID, "scan", json.RawMessage(fmt.Sprintf(`{"scanner":"kit-tool","target":%q}`, target)))
	opts.Targets = []string{target}
	opts.ScanTargetPolicy = &core.ScanTargetPolicy{AllowedRoots: []string{target}}
	opts.AssetResolver = func(_, _ string) (ctis.AssetType, string) {
		return ctis.AssetTypeRepository, "github.com/openctemio/kit-test"
	}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "kit-tool", installed: true})
	stop := runKit(t, k)
	waitFor(t, "the command", func() bool {
		s, e := f.CommandState(cmdID)
		if s == "failed" {
			t.Fatalf("failed: %s\n%s\n%s", e, out.String(), errw.String())
		}
		return s == "completed"
	})
	waitFor(t, "a sweep after the start sweep (the acknowledgement)", func() bool {
		j := k.janitorRef.Load()
		return j != nil && j.Status().Sweeps >= 2
	})
	rep := k.localStoreReport()
	if rep == nil || rep.Level != "ok" || rep.Boot == 0 || rep.Sweeps < 2 || rep.StopClaiming {
		t.Errorf("report = %+v", rep)
	}
	if _, ok := rep.BytesByClass["outbox"]; !ok {
		t.Errorf("no outbox bytes in %+v", rep.BytesByClass)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for _, b := range f.Heartbeats() {
		if strings.Contains(string(b), "local_store") {
			t.Fatalf("a platform without the feature was sent local_store: %s", b)
		}
	}
	if k.janitorRef.Load() != nil {
		t.Error("the janitor still runs after Run returned")
	}
}

// The poller's claim gate follows the janitor: a full outbox and the high
// watermark both stop claiming, and it clears when they do.
func TestKit_AcceptsWorkFollowsOutboxAndWatermark(t *testing.T) {
	st, err := localstore.Open(localstore.Options{Dir: t.TempDir(), CreateKey: true, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ob := &stubOutbox{ok: true}
	wsb := &stubWorkspaces{}
	j, err := localstore.NewJanitor(localstore.JanitorConfig{Store: st, Outbox: ob, Workspaces: wsb, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	k := &Kit{ls: &localStore{store: st}}
	k.janitorRef.Store(j)
	sweep := func() {
		t.Helper()
		if _, err := j.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	sweep()
	if ok, why := k.acceptsWork(); !ok {
		t.Fatalf("idle store refuses work: %s", why)
	}
	// A full outbox: refused at once, before any sweep.
	ob.ok, ob.why = false, "unacknowledged results fill the outbox"
	if ok, why := k.acceptsWork(); ok || !strings.Contains(why, "outbox") {
		t.Fatalf("full outbox: %v %q", ok, why)
	}
	if rep := k.localStoreReport(); !rep.StopClaiming {
		t.Errorf("report does not say stop: %+v", rep)
	}
	ob.ok = true
	if ok, _ := k.acceptsWork(); !ok {
		t.Fatal("still refusing after the outbox cleared")
	}
	// The high watermark: workspaces over their budget.
	wsb.bytes = 1 << 40
	sweep()
	if ok, why := k.acceptsWork(); ok || !strings.Contains(why, "workspaces") {
		t.Fatalf("high watermark: %v %q", ok, why)
	}
	if rep := k.localStoreReport(); rep.Level != string(localstore.WatermarkHigh) || !rep.StopClaiming {
		t.Errorf("report = %+v", rep)
	}
	wsb.bytes = 0
	sweep()
	if ok, _ := k.acceptsWork(); !ok {
		t.Fatal("still refusing after the watermark cleared")
	}
}

// The store refuses a key file others can read, and the doctor checks name
// a key or a directory that is too open.
func TestCheckLocalStore_KeyFileAndDirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes mean nothing here")
	}
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	keyFile := filepath.Join(t.TempDir(), "store.key")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	enc, err := localstore.FormatKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, enc, 0o644); err != nil { // #nosec G306 -- the test needs a key that is too open
		t.Fatal(err)
	}
	if keyFileProblem(keyFile) == "" {
		t.Error("an open key file was called private")
	}
	t.Setenv(EnvStoreKeyFile, keyFile)
	if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "mode 0644") {
		t.Fatalf("a key file open to others must stop the start: %v", err)
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if msg := keyFileProblem(keyFile); msg != "" {
		t.Errorf("a private key file was called open: %s", msg)
	}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer k.closeClient()
	r := k.ConfigReport()
	if c, ok := findCheck(*r, CheckStoreKey); !ok || c.Code != "separate_key_file" {
		t.Errorf("key check = %+v (%v)", c, ok)
	}
	if c, ok := findCheck(*r, CheckStoreDir); !ok || c.Code != "private" {
		t.Errorf("dir check = %+v", c)
	}
	if c, ok := findCheck(*r, CheckStoreDisk); !ok || c.Status == core.CheckFail {
		t.Errorf("disk check = %+v", c)
	}

	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil { // #nosec G302 -- the test needs an open directory
		t.Fatal(err)
	}
	if dirPrivacyProblem(open) == "" {
		t.Error("an open directory was called private")
	}
	if err := os.Chmod(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if msg := dirPrivacyProblem(open); msg != "" {
		t.Errorf("a private directory was called open: %s", msg)
	}
}

// A tool must not read the store: its directory and key are protected.
func TestProtectedPaths_IncludeStore(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer k.closeClient()
	dir, _ := kitStoreDirs(opts.Outbox.Dir)
	if !slices.Contains(k.protectedPaths(), dir) {
		t.Errorf("store dir %s not protected: %v", dir, k.protectedPaths())
	}
}

// With no key file configured the store creates a 0600 key in its
// directory, and the report says the key sits on the data volume.
func TestOpenLocalStore_DefaultKeyIsPrivate(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer k.closeClient()
	dir, _ := kitStoreDirs(opts.Outbox.Dir)
	fi, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("master.key mode %04o", fi.Mode().Perm())
	}
	if c, _ := findCheck(*k.ConfigReport(), CheckStoreKey); c.Code != "on_data_volume" {
		t.Errorf("key check = %+v", c)
	}
}

// The outbox status command reads items sealed under the local store (it
// opens the store beside the outbox) instead of calling the outbox empty.
func TestOutboxCommand_ReadsStoreSealedItems(t *testing.T) {
	clearEnv(t)
	dir := filepath.Join(t.TempDir(), "outbox")
	storeDir, _ := resolveStorePaths(dir)
	st, err := localstore.Open(localstore.Options{Dir: storeDir, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.Open(outbox.Config{Dir: dir, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.Enqueue(outbox.Meta{Kind: outbox.KindReport}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = ob.Close()
	_ = st.Close()
	if _, err := os.Stat(outbox.DefaultKeyFile(dir)); err == nil {
		t.Fatal("a store-backed outbox wrote its own key")
	}

	var out, errw bytes.Buffer
	if code := OutboxCommand(OutboxPlan{Enabled: true, Config: clientOutbox(dir)}, false, &out, &errw); code != 0 {
		t.Fatalf("status: %d %s", code, errw.String())
	}
	if !strings.Contains(out.String(), "pending:      1") {
		t.Errorf("output %q", out.String())
	}

	// A running sensor holds the store.
	held, err := localstore.Open(localstore.Options{Dir: storeDir, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	errw.Reset()
	if code := OutboxCommand(OutboxPlan{Enabled: true, Config: clientOutbox(dir)}, false, &out, &errw); code != ExitError || !strings.Contains(errw.String(), "running sensor holds the store") {
		t.Errorf("locked: %d %q", code, errw.String())
	}
}

// Every job the kit runs is in the journal while it runs and gone once its
// result is queued: a crash mid-job is what the next start reports.
func TestRun_JournalsRunningJobs(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	const cmdID = "0192a3b4-0000-7000-8000-0000000000bb"
	f.QueueCommandPayload(cmdID, "journal_probe", json.RawMessage(`{}`))
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	inJournal := make(chan error, 1)
	k.UseCommandMiddleware(func(next core.CommandExecutor) core.CommandExecutor {
		return execFunc(func(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
			if cmd.Type != "journal_probe" {
				return next.Execute(ctx, cmd)
			}
			j, err := k.ls.store.Journal(localstore.SensorTenant)
			if err == nil {
				_, err = j.Get(cmd.ID)
			}
			inJournal <- err
			return &core.CommandExecutionResult{}, nil
		})
	}, "journal_probe")
	stop := runKit(t, k)
	select {
	case err := <-inJournal:
		if err != nil {
			t.Fatalf("the running job is not journaled: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command never ran")
	}
	waitFor(t, "the command to complete", func() bool {
		s, _ := f.CommandState(cmdID)
		return s == "completed"
	})
	j, err := k.ls.store.Journal(localstore.SensorTenant)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the journal record to go", func() bool {
		_, err := j.Get(cmdID)
		return err != nil
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// The status command never writes a store key: with the store directory
// present and no key, it reports without the store.
func TestOutboxCommand_DoesNotCreateStoreKey(t *testing.T) {
	clearEnv(t)
	dir := filepath.Join(t.TempDir(), "outbox")
	storeDir, _ := resolveStorePaths(dir)
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	if code := OutboxCommand(OutboxPlan{Enabled: true, Config: clientOutbox(dir)}, false, &out, &errw); code != 0 {
		t.Fatalf("status: %d %s", code, errw.String())
	}
	if _, err := os.Stat(filepath.Join(storeDir, "master.key")); !os.IsNotExist(err) {
		t.Fatalf("the status command created a store key: %v", err)
	}
	// A key file named by the setting that does not exist: not created
	// either.
	keyFile := filepath.Join(t.TempDir(), "store.key")
	t.Setenv(EnvStoreKeyFile, keyFile)
	_ = OutboxCommand(OutboxPlan{Enabled: true, Config: clientOutbox(dir)}, false, &out, &errw)
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("the status command created %s: %v", keyFile, err)
	}
}
