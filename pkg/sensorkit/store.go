package sensorkit

// The sensor's local store: the encrypted, crash-safe records (pkg/localstore)
// that the outbox, the job journal and the janitor share. The kit opens it
// with the outbox, recovers the jobs an earlier run left open, sweeps the
// workspaces a crash left, runs the janitor and stops claiming jobs while the
// storage is full.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/localstore"
	"github.com/openctemio/sdk-go/pkg/outbox"
	"github.com/openctemio/sdk-go/pkg/sensorkit/workspace"
)

// Settings of the local store.
const (
	EnvStoreDir       = "SENSOR_STORE_DIR"      // default: store/ next to the outbox directory
	EnvStoreKeyFile   = "SENSOR_STORE_KEY_FILE" // default <store dir>/master.key
	EnvWorkspaceDir   = "SENSOR_WORKSPACE_DIR"  // default: workspaces/ next to the outbox directory
	CheckStoreDir     = "storage.store_dir"
	CheckStoreKey     = "storage.store_key"
	CheckStoreDisk    = "storage.store_disk"
	CheckStoreKept    = "storage.store_persistent"
	storeRecoverLabel = "interrupted job(s) from an earlier run reported"
)

// interruptedReason is the error text of a job a crash cut short.
const interruptedReason = "the sensor stopped while this job ran (restart, crash or kill); it was not finished"

// localStore is the kit's handle on the store and what runs on it.
type localStore struct {
	store    *localstore.Store
	dir      string
	keyFile  string
	workDir  string
	ws       *workspace.Manager
	janitor  *localstore.Janitor
	policy   localstore.Policy
	mu       sync.Mutex
	recovery int // jobs reported at start
}

// resolveStorePaths decides the store and workspace directories: the
// settings, else beside the outbox directory (so they sit on the same data
// volume).
func resolveStorePaths(outboxDir string) (storeDir, workDir string) {
	base := filepath.Dir(outboxDir)
	storeDir = firstNonEmpty(os.Getenv(EnvStoreDir), filepath.Join(base, "store"))
	workDir = firstNonEmpty(os.Getenv(EnvWorkspaceDir), filepath.Join(base, "workspaces"))
	return storeDir, workDir
}

// openLocalStore opens the store for the outbox plan (nil when the outbox is
// off), hands it to the outbox config and returns it. The master key comes
// from SENSOR_STORE_KEY_FILE (a mounted secret) or is created 0600 in the
// store directory.
func (k *Kit) openLocalStore() error {
	p := &k.s.outbox
	if !p.Enabled || p.Config.Dir == "" {
		return nil
	}
	dir, workDir := resolveStorePaths(p.Config.Dir)
	if w := securePrivateDir(dir); w != "" {
		_, _ = fmt.Fprintf(k.errw, "Warning: store directory: %s\n", w)
	}
	keyFile := strings.TrimSpace(os.Getenv(EnvStoreKeyFile))
	ls := &localStore{dir: dir, keyFile: keyFile, workDir: workDir}
	st, err := localstore.Open(localstore.Options{
		Dir:       dir,
		KeyFile:   keyFile,
		CreateKey: true,
		OnTamper: func(ev localstore.TamperEvent) {
			_, _ = fmt.Fprintf(k.errw, "Warning: a local record failed authentication and was set aside (%s)\n", ev.Reason)
		},
	})
	if err != nil {
		if errors.Is(err, localstore.ErrLocked) {
			return fmt.Errorf("%w: another sensor process uses this store directory; give each sensor its own volume", err)
		}
		return fmt.Errorf("local store %s: %w", dir, err)
	}
	ls.store = st
	k.ls = ls
	p.Config.Store = st
	p.Config.OnDelivered = func(outbox.Meta) {
		if j := k.janitorRef.Load(); j != nil {
			j.NoteAcks()
		}
	}
	if k.s.verbose {
		_, _ = fmt.Fprintf(k.out, "  Local store: %s (boot %d)\n", dir, st.Stats().Boot)
	}
	k.checkLocalStore()
	return nil
}

// closeLocalStore closes the store (after the client and the janitor).
func (k *Kit) closeLocalStore() {
	if k.ls != nil && k.ls.store != nil {
		_ = k.ls.store.Close()
		k.ls.store = nil
	}
}

// recoverJobs reports, through the outbox, the jobs an earlier run held and
// never finished, and sweeps what such a run left in the workspaces. It runs
// once, at start, before any job is claimed.
func (k *Kit) recoverJobs() {
	ls := k.ls
	if ls == nil || ls.store == nil || k.client == nil {
		return
	}
	interrupted, err := ls.store.Recover(0)
	if err != nil {
		_, _ = fmt.Fprintf(k.errw, "Warning: reading the job journal: %v\n", err)
	}
	n := 0
	for _, it := range interrupted {
		reason := interruptedReason
		if it.Step != "" {
			reason += " (step " + it.Step + ")"
		}
		if rerr := k.client.ReportInterruptedCommand(it.Record.CommandID, it.Record.Tenant, reason); rerr != nil {
			_, _ = fmt.Fprintf(k.errw, "Warning: cannot report the interrupted job %s: %v\n", it.Record.CommandID, rerr)
			continue
		}
		n++
	}
	ls.recovery = n
	if n > 0 {
		_, _ = fmt.Fprintf(k.out, "  Recovery: %d %s\n", n, storeRecoverLabel)
	}
	if ws, werr := workspace.Open(ls.workDir); werr != nil {
		_, _ = fmt.Fprintf(k.errw, "Warning: job workspaces %s: %v\n", ls.workDir, werr)
	} else {
		ls.ws = ws
		// After the recovery no job of the earlier run is open: whatever the
		// workspaces hold is what a crash left.
		if _, serr := ws.Sweep(func(string, string) bool { return false }); serr != nil {
			_, _ = fmt.Fprintf(k.errw, "Warning: sweeping job workspaces: %v\n", serr)
		}
	}
}

// startJanitor starts the janitor (a sweep at start, after acknowledgement
// bursts and every 10 minutes) and returns the function that stops it and
// waits. Without a store it does nothing.
func (k *Kit) startJanitor(ctx context.Context) (stop func()) {
	ls := k.ls
	if ls == nil || ls.store == nil {
		return func() {}
	}
	cfg := localstore.JanitorConfig{Store: ls.store, Policy: ls.policy}
	if k.client != nil {
		if ob := k.client.Outbox(); ob != nil {
			cfg.Outbox = ob
		}
	}
	if ls.ws != nil {
		cfg.Workspaces = ls.ws
	}
	j, err := localstore.NewJanitor(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(k.errw, "Warning: local data cleanup is off: %v\n", err)
		return func() {}
	}
	ls.mu.Lock()
	ls.janitor = j
	ls.mu.Unlock()
	k.janitorRef.Store(j)
	jctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		j.Run(jctx)
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
			k.janitorRef.Store(nil)
		})
	}
}

// SetStorePolicy sets the retention and cap policy of the local data (the
// platform's policy once it sends one). Every field is clamped to a sane
// range and a zero field keeps its default, so a policy can tune cleanup but
// not switch it off. Safe while Run runs.
func (k *Kit) SetStorePolicy(p localstore.Policy) {
	if k.ls == nil {
		return
	}
	k.ls.mu.Lock()
	k.ls.policy = p
	j := k.ls.janitor
	k.ls.mu.Unlock()
	if j != nil {
		j.SetPolicy(p)
	}
}

// acceptsWork is the poller's claim gate: false while the janitor reports
// the storage high, the volume low or the outbox full of unacknowledged
// results. Without a janitor it follows the outbox alone.
func (k *Kit) acceptsWork() (bool, string) {
	if j := k.janitorRef.Load(); j != nil {
		return j.AcceptsWork()
	}
	if k.client != nil {
		if ob := k.client.Outbox(); ob != nil {
			return ob.AcceptsWork()
		}
	}
	return true, ""
}

// localStoreReport is the heartbeat's report of the local data (nil without
// a store).
func (k *Kit) localStoreReport() *core.LocalStoreReport {
	ls := k.ls
	if ls == nil || ls.store == nil {
		return nil
	}
	r := &core.LocalStoreReport{Level: string(localstore.WatermarkOK)}
	stats := ls.store.Stats()
	r.Boot, r.BootReset, r.Tampered = stats.Boot, stats.BootReset, stats.Tampered
	r.DiskLevel = string(ls.store.Disk().Level)
	if j := k.janitorRef.Load(); j != nil {
		st := j.Status()
		r.Level = string(st.Level)
		r.StopClaiming = st.StopClaiming
		r.Reason = st.Reason
		r.TotalBytes, r.QuotaBytes = st.Total, st.QuotaBytes
		r.BytesByClass = make(map[string]int64, len(st.Bytes))
		for c, b := range st.Bytes {
			r.BytesByClass[string(c)] = b
		}
		r.Sweeps = st.Sweeps
		r.LastSweepAt = st.Last.At
		for _, n := range st.Last.Removed {
			r.LastSweepRemoved += n
		}
	}
	if ok, why := k.acceptsWork(); !ok {
		r.StopClaiming, r.Reason = true, firstNonEmpty(r.Reason, why)
	}
	return r
}

// checkLocalStore reports the doctor checks of the store: the key file's
// mode, the directory's privacy and the volume's free space.
func (k *Kit) checkLocalStore() {
	ls := k.ls
	if ls == nil || ls.store == nil {
		return
	}
	// The store holds the keys of the sealed outbox items: if it is lost
	// while the outbox survives, those items cannot be read again.
	if !k.opts.Standalone {
		k.persistenceCheck(CheckStoreKept, EnvStoreDir, ls.dir,
			"Sealed results in the outbox cannot be read again when the container is recreated")
	}
	params := map[string]core.ConfigParam{"path": core.ParamPath(ls.dir)}
	if msg := dirPrivacyProblem(ls.dir); msg != "" {
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreDir, Status: core.CheckWarn, Code: "not_private", Params: params,
			Keys: []string{EnvStoreDir}, Summary: msg})
		_, _ = fmt.Fprintf(k.errw, "Warning: store directory: %s\n", msg)
	} else {
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreDir, Status: core.CheckPass, Code: "private", Params: params})
	}

	keyPath := firstNonEmpty(ls.keyFile, filepath.Join(ls.dir, "master.key"))
	kparams := map[string]core.ConfigParam{"path": core.ParamPath(keyPath)}
	switch msg := keyFileProblem(keyPath); {
	case msg != "":
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreKey, Status: core.CheckWarn, Code: "permissive", Params: kparams,
			Keys: []string{EnvStoreKeyFile}, Summary: msg})
		_, _ = fmt.Fprintf(k.errw, "Warning: store key: %s\n", msg)
	case ls.store.Stats().KeyOnDataVolume:
		// Integrity and tenant separation, not confidentiality against a
		// copy of the whole volume: say where the key lives.
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreKey, Status: core.CheckPass, Code: "on_data_volume", Params: kparams,
			Keys: []string{EnvStoreKeyFile}, Severity: core.SeverityInfo})
	default:
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreKey, Status: core.CheckPass, Code: "separate_key_file", Params: kparams})
	}

	d := ls.store.Disk()
	switch d.Level {
	case localstore.DiskLow:
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreDisk, Status: core.CheckWarn, Code: "low", Params: params, Summary: d.Reason})
		_, _ = fmt.Fprintf(k.errw, "Warning: the store volume is low on space: %s. The sensor claims no new jobs until it recovers.\n", d.Reason)
	case localstore.DiskCritical:
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreDisk, Status: core.CheckFail, Code: "critical", Params: params,
			Severity: core.SeverityWarning, Summary: d.Reason})
		_, _ = fmt.Fprintf(k.errw, "Warning: the store volume is nearly full: %s. Only acknowledgements and deletions proceed.\n", d.Reason)
	case localstore.DiskUnknown:
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreDisk, Status: core.CheckSkip, Code: "unknown", Params: params})
	default:
		k.ReportCheck(core.ConfigCheck{ID: CheckStoreDisk, Status: core.CheckPass, Code: "ok", Params: params})
	}
}

// dirPrivacyProblem says why dir is not private to the sensor's user ("" when
// it is, or where modes mean nothing).
func dirPrivacyProblem(dir string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Sprintf("cannot read %s: %v", dir, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("%s has mode %04o: group or others have access", dir, fi.Mode().Perm())
	}
	if uid, mine := ownedBySensorUser(fi); !mine {
		return fmt.Sprintf("%s is owned by uid %d, not by the sensor's user", dir, uid)
	}
	return ""
}

// keyFileProblem says why the key file at path is too open ("" when it is
// private, or does not exist yet).
func keyFileProblem(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("%s has mode %04o: it must be readable by the sensor's user only (0600)", path, fi.Mode().Perm())
	}
	return ""
}
