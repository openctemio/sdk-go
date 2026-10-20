package outbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func quietLog(t *testing.T) func(string, ...any) {
	return func(format string, args ...any) { t.Logf("[outbox] "+format, args...) }
}

func openTest(t *testing.T, dir string, mod func(*Config)) *Outbox {
	t.Helper()
	cfg := Config{Dir: dir, Logf: quietLog(t), BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	o, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

// recorder is a Deliverer that records payloads and returns scripted errors.
type recorder struct {
	mu   sync.Mutex
	got  []string
	errs func(d *Delivery) error
}

func (r *recorder) Deliver(_ context.Context, d *Delivery) (any, error) {
	if r.errs != nil {
		if err := r.errs(d); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	r.got = append(r.got, string(d.Payload))
	r.mu.Unlock()
	return "ok:" + string(d.Payload), nil
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

func runFor(t *testing.T, o *Outbox, d Deliverer) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = o.Run(ctx, d); close(done) }()
	return func() { cancel(); <-done }
}

func waitResult(t *testing.T, tk *Ticket) Result {
	t.Helper()
	select {
	case r := <-tk.Done():
		return r
	case <-time.After(5 * time.Second):
		t.Fatalf("no result for %s", tk.Meta.ID)
		return Result{}
	}
}

func TestEnqueueIsDurableAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	tk, err := o.Enqueue(Meta{Kind: KindReport, CommandID: "c1"}, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if tk.Meta.ReportID == "" || tk.Meta.ID == "" {
		t.Fatalf("ids not assigned: %+v", tk.Meta)
	}
	_ = o.Close()

	o2 := openTest(t, dir, nil)
	p := o2.Pending()
	if len(p) != 1 || p[0].ReportID != tk.Meta.ReportID || p[0].CommandID != "c1" {
		t.Fatalf("pending after reopen = %+v", p)
	}
	r := &recorder{}
	stop := runFor(t, o2, r)
	defer stop()
	waitFor(t, func() bool { return len(r.list()) == 1 })
	if r.list()[0] != `{"a":1}` {
		t.Fatalf("payload = %q", r.list()[0])
	}
	waitFor(t, func() bool { return o2.Stats().PendingCount == 0 })
	assertNoFiles(t, filepath.Join(dir, dirPending))
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func assertNoFiles(t *testing.T, dir string) {
	t.Helper()
	names, _ := os.ReadDir(dir)
	if len(names) != 0 {
		var n []string
		for _, e := range names {
			n = append(n, e.Name())
		}
		t.Fatalf("%s not empty: %v", dir, n)
	}
}

func TestFilesArePrivateAndSealed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	secret := "super-secret-finding-text"
	if _, err := o.Enqueue(Meta{Kind: KindReport}, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(fileMode)
		if fi.IsDir() {
			want = dirMode
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", p, fi.Mode().Perm(), want)
		}
		if !fi.IsDir() {
			data, _ := os.ReadFile(p)
			if strings.Contains(string(data), secret) {
				t.Errorf("%s holds the payload in clear text", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecondProcessCannotOpen(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	_, err := Open(Config{Dir: dir, Logf: quietLog(t)})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open err = %v, want ErrLocked", err)
	}
	_ = o.Close()
	o2, err := Open(Config{Dir: dir, Logf: quietLog(t)})
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	_ = o2.Close()
}

func TestDeliversOldestFirst(t *testing.T) {
	o := openTest(t, t.TempDir(), nil)
	for i := range 5 {
		if _, err := o.Enqueue(Meta{Kind: KindReport}, fmt.Appendf(nil, "%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	r := &recorder{}
	stop := runFor(t, o, r)
	defer stop()
	waitFor(t, func() bool { return len(r.list()) == 5 })
	if got := strings.Join(r.list(), ","); got != "0,1,2,3,4" {
		t.Fatalf("order = %s", got)
	}
}

func TestPermanentGoesToDeadLetterAndOthersFlow(t *testing.T) {
	dir := t.TempDir()
	var deadCB []DeadLetter
	var mu sync.Mutex
	o := openTest(t, dir, func(c *Config) {
		c.OnDeadLetter = func(d DeadLetter) { mu.Lock(); deadCB = append(deadCB, d); mu.Unlock() }
	})
	r := &recorder{errs: func(d *Delivery) error {
		if string(d.Payload) == "poison" {
			return Permanent(422, "schema-invalid: see problem", []byte(`{"type":"https://openctem.io/problems/ingest/schema-invalid","status":422}`), errors.New("http 422"))
		}
		return nil
	}}
	t1, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("a"))
	tp, _ := o.Enqueue(Meta{Kind: KindReport, CommandID: "cmd-1"}, []byte("poison"))
	t2, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("b"))
	stop := runFor(t, o, r)
	defer stop()
	if !waitResult(t, t1).Delivered || !waitResult(t, t2).Delivered {
		t.Fatal("healthy items not delivered")
	}
	res := waitResult(t, tp)
	if res.Dead == nil || res.Dead.Status != 422 {
		t.Fatalf("poison result = %+v", res)
	}
	st := o.Stats()
	if st.DeadLetterCount != 1 || st.PendingCount != 0 {
		t.Fatalf("stats = %+v", st)
	}
	reason, err := os.ReadFile(filepath.Join(dir, dirDead, tp.Meta.ID+reasonExt))
	if err != nil || !strings.Contains(string(reason), "schema-invalid") {
		t.Fatalf("reason file: %v %s", err, reason)
	}
	if dl, ok := o.DeadLetterForCommand("cmd-1"); !ok || dl.Meta.ID != tp.Meta.ID {
		t.Fatalf("DeadLetterForCommand = %+v %v", dl, ok)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(deadCB) == 1 })

	// Survives a restart as a dead letter, and can be requeued.
	stop()
	_ = o.Close()
	o2 := openTest(t, dir, nil)
	if d := o2.DeadLetters(); len(d) != 1 || d[0].Status != 422 {
		t.Fatalf("dead letters after reopen = %+v", d)
	}
	if err := o2.RequeueDead(tp.Meta.ID); err != nil {
		t.Fatal(err)
	}
	if o2.Stats().PendingCount != 1 {
		t.Fatal("requeued item not pending")
	}
}

func TestAuthPausesUntilResume(t *testing.T) {
	o := openTest(t, t.TempDir(), nil)
	var mu sync.Mutex
	rejected := true
	calls := 0
	r := &recorder{errs: func(*Delivery) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if rejected {
			return Unauthorized(errors.New("http 401"))
		}
		return nil
	}}
	tk, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("x"))
	stop := runFor(t, o, r)
	defer stop()
	waitFor(t, func() bool { return o.Stats().AuthPaused })
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if calls != 1 {
		t.Fatalf("calls while paused = %d, want 1", calls)
	}
	rejected = false
	mu.Unlock()
	if p := o.Pending(); len(p) != 1 {
		t.Fatal("item lost while paused")
	}
	o.Resume()
	if !waitResult(t, tk).Delivered {
		t.Fatal("not delivered after resume")
	}
	// The auth rejection was not counted as an attempt.
	if st := o.Stats(); st.Delivered != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestTransientBackoffCircuitAndWake(t *testing.T) {
	o := openTest(t, t.TempDir(), func(c *Config) {
		c.BackoffBase = time.Hour // only Wake can bring them back in this test
		c.BackoffMax = time.Hour
		c.CircuitThreshold = 2
	})
	var mu sync.Mutex
	down := true
	r := &recorder{errs: func(*Delivery) error {
		mu.Lock()
		defer mu.Unlock()
		if down {
			return errors.New("dial tcp: connection refused")
		}
		return nil
	}}
	var tks []*Ticket
	for i := range 3 {
		tk, _ := o.Enqueue(Meta{Kind: KindReport}, fmt.Appendf(nil, "%d", i))
		tks = append(tks, tk)
	}
	stop := runFor(t, o, r)
	defer stop()
	waitFor(t, func() bool { return o.Stats().CircuitOpen })
	if o.Stats().PendingCount != 3 {
		t.Fatal("items lost while down")
	}
	mu.Lock()
	down = false
	mu.Unlock()
	o.Wake()
	for _, tk := range tks {
		if !waitResult(t, tk).Delivered {
			t.Fatal("not drained after Wake")
		}
	}
	if got := strings.Join(r.list(), ","); got != "0,1,2" {
		t.Fatalf("drain order = %s", got)
	}
}

func TestRetryAfterIsHonouredAndNotOverriddenByWake(t *testing.T) {
	o := openTest(t, t.TempDir(), nil)
	var mu sync.Mutex
	first := time.Time{}
	var second time.Time
	r := &recorder{errs: func(*Delivery) error {
		mu.Lock()
		defer mu.Unlock()
		if first.IsZero() {
			first = time.Now()
			return RetryAfter(errors.New("http 429"), 300*time.Millisecond)
		}
		second = time.Now()
		return nil
	}}
	tk, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("x"))
	stop := runFor(t, o, r)
	defer stop()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return !first.IsZero() })
	o.Wake()
	waitResult(t, tk)
	mu.Lock()
	defer mu.Unlock()
	if gap := second.Sub(first); gap < 250*time.Millisecond {
		t.Fatalf("retried after %s, Retry-After was 300ms", gap)
	}
}

func TestCommandResultWaitsForItsReports(t *testing.T) {
	o := openTest(t, t.TempDir(), nil)
	var mu sync.Mutex
	fail := 2
	r := &recorder{errs: func(d *Delivery) error {
		mu.Lock()
		defer mu.Unlock()
		if d.Meta.Kind == KindReport && fail > 0 {
			fail--
			return errors.New("503")
		}
		return nil
	}}
	rep, _ := o.Enqueue(Meta{Kind: KindReport, CommandID: "c"}, []byte("report"))
	res, _ := o.Enqueue(Meta{Kind: KindCommandResult, CommandID: "c"}, []byte("result"))
	other, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("other"))
	stop := runFor(t, o, r)
	defer stop()
	for _, tk := range []*Ticket{rep, res, other} {
		waitResult(t, tk)
	}
	got := r.list()
	idx := map[string]int{}
	for i, g := range got {
		idx[g] = i
	}
	if idx["result"] < idx["report"] {
		t.Fatalf("command result sent before its report: %v", got)
	}
}

func TestTruncatedAndCorruptFilesAreQuarantined(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	a, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("aaaa"))
	b, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("bbbb"))
	c, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("cccc"))
	_ = o.Close()

	// a: item truncated (power loss on a lying disk).
	itemA := filepath.Join(dir, dirPending, a.Meta.ID+itemExt)
	data, _ := os.ReadFile(itemA)
	if err := os.WriteFile(itemA, data[:len(data)/2], fileMode); err != nil {
		t.Fatal(err)
	}
	// b: state file garbage (rebuilt from the item, delivered).
	if err := os.WriteFile(filepath.Join(dir, dirPending, b.Meta.ID+stateExt), []byte("garbage"), fileMode); err != nil {
		t.Fatal(err)
	}
	// c: item with a flipped byte.
	itemC := filepath.Join(dir, dirPending, c.Meta.ID+itemExt)
	data, _ = os.ReadFile(itemC)
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(itemC, data, fileMode); err != nil {
		t.Fatal(err)
	}
	// A stray file and an interrupted write.
	_ = os.WriteFile(filepath.Join(dir, dirPending, "junk.txt"), []byte("x"), fileMode)
	_ = os.WriteFile(filepath.Join(dir, dirTmp, "x.item.1.tmp"), []byte("x"), fileMode)

	o2 := openTest(t, dir, nil)
	p := o2.Pending()
	if len(p) != 2 { // a (truncated) quarantined at Open; b rebuilt; c (bit flip) is caught at delivery
		t.Fatalf("pending = %d (%+v)", len(p), p)
	}
	r := &recorder{}
	stop := runFor(t, o2, r)
	defer stop()
	waitFor(t, func() bool { return o2.Stats().PendingCount == 0 })
	if got := strings.Join(r.list(), ","); got != "bbbb" {
		t.Fatalf("delivered = %q", got)
	}
	if st := o2.Stats(); st.Corrupt < 3 {
		t.Fatalf("corrupt count = %d", st.Corrupt)
	}
	assertNoFiles(t, filepath.Join(dir, dirTmp))
	names, _ := os.ReadDir(filepath.Join(dir, dirCorrupt))
	if len(names) < 3 {
		t.Fatalf("quarantine holds %d files", len(names))
	}
}

// A full outbox never drops an unacknowledged result: Enqueue refuses the
// new item (ErrFull) with a warning, every queued item stays, AcceptsWork
// says stop claiming, and room made by a delivery is usable again.
func TestFullOutboxRefusesNewItemsAndKeepsQueued(t *testing.T) {
	var logs []string
	var evicted []Meta
	o := openTest(t, t.TempDir(), func(c *Config) {
		c.MaxBytes = 3000
		c.MaxDiskFraction = -1
		c.OnEvict = func(m []Meta, _ string) { evicted = append(evicted, m...) }
		c.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	})
	payload := []byte(strings.Repeat("x", 50))
	var queued []*Ticket
	var full error
	for i := range 40 {
		tk, err := o.Enqueue(Meta{Kind: KindReport}, append(payload, byte(i)))
		if err != nil {
			full = err
			break
		}
		queued = append(queued, tk)
	}
	if !errors.Is(full, ErrFull) {
		t.Fatalf("err = %v, want ErrFull", full)
	}
	st := o.Stats()
	if st.Evicted != 0 || len(evicted) != 0 || st.PendingCount != len(queued) || st.Refused != 1 {
		t.Fatalf("stats %+v, evicted %v", st, evicted)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "Nothing queued was dropped") {
		t.Fatalf("no warning: %q", logs)
	}
	if ok, why := o.AcceptsWork(); ok || why == "" {
		t.Fatal("a full outbox still accepts work")
	}
	// A delivery makes room.
	stop := runFor(t, o, &recorder{})
	waitResult(t, queued[0])
	stop()
	if _, err := o.Enqueue(Meta{Kind: KindReport}, append(payload, 'n')); err != nil {
		t.Fatalf("after a delivery: %v", err)
	}
}

func TestDeadLettersAreEvictedBeforePending(t *testing.T) {
	o := openTest(t, t.TempDir(), func(c *Config) { c.MaxBytes = 2500; c.MaxDiskFraction = -1 })
	r := &recorder{errs: func(d *Delivery) error { return Permanent(400, "bad", nil, nil) }}
	dead, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("dead"))
	stop := runFor(t, o, r)
	waitResult(t, dead)
	stop()
	var tks []*Ticket
	for range 6 {
		tk, _ := o.Enqueue(Meta{Kind: KindReport}, []byte(strings.Repeat("p", 20)))
		tks = append(tks, tk)
	}
	if o.Stats().DeadLetterCount != 0 {
		t.Fatal("dead letter kept while pending items were evicted")
	}
	_ = tks
}

// The age cap deletes old dead letters only: an unacknowledged item is kept
// however old it is.
func TestAgeCapDeletesDeadLettersOnly(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	dir := t.TempDir()
	mod := func(c *Config) { c.now = clock; c.MaxAge = time.Hour }
	o := openTest(t, dir, mod)
	dead, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("dead"))
	stop := runFor(t, o, &recorder{errs: func(*Delivery) error { return Permanent(400, "bad", nil, nil) }})
	waitResult(t, dead)
	stop()
	tk, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("old"))
	_ = o.Close()
	now = now.Add(2 * time.Hour)
	o2 := openTest(t, dir, mod)
	if st := o2.Stats(); st.PendingCount != 1 || st.DeadLetterCount != 0 || st.Evicted != 1 {
		t.Fatalf("stats = %+v (item %s)", st, tk.Meta.ID)
	}
}

func TestTooLargeItemIsRefused(t *testing.T) {
	o := openTest(t, t.TempDir(), func(c *Config) { c.MaxBytes = 100; c.MaxDiskFraction = -1 })
	big := make([]byte, 4096)
	for i := range big {
		big[i] = byte(i * 7919)
	}
	if _, err := o.Enqueue(Meta{Kind: KindReport}, big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestNewOutboxCreatesKey(t *testing.T) {
	dir := t.TempDir()
	_ = openTest(t, dir, nil)
	if _, err := os.Stat(filepath.Join(dir, keyName)); err != nil {
		t.Fatalf("key not created on an empty outbox: %v", err)
	}
}

// A missing key with sealed items left behind (a secret that failed to
// mount, a key file deleted by hand) must stop Open: creating a new key
// would make every one of those items unreadable.
func TestMissingKeyWithSealedItemsRefusesToOpen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyFile func(dir string) string
		dead    bool
	}{
		{"default key, pending item", func(string) string { return "" }, false},
		{"default key, dead letter", func(string) string { return "" }, true},
		{"external key file", func(string) string { return filepath.Join(t.TempDir(), "secret", "outbox.key") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgKey := tc.keyFile(dir)
			o := openTest(t, dir, func(c *Config) { c.KeyFile = cfgKey })
			tk, err := o.Enqueue(Meta{Kind: KindReport}, []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.dead {
				r := &recorder{errs: func(*Delivery) error { return Permanent(400, "refused", nil, nil) }}
				stop := runFor(t, o, r)
				waitFor(t, func() bool { return o.Stats().DeadLetterCount == 1 })
				stop()
			}
			_ = o.Close()
			keyFile := cfgKey
			if keyFile == "" {
				keyFile = DefaultKeyFile(dir)
			}
			if err := os.Remove(keyFile); err != nil {
				t.Fatal(err)
			}
			before := listTree(t, dir)

			_, err = Open(Config{Dir: dir, KeyFile: cfgKey, Logf: quietLog(t)})
			if !errors.Is(err, ErrKeyMissing) {
				t.Fatalf("Open err = %v, want ErrKeyMissing", err)
			}
			for _, want := range []string{keyFile, "1 sealed item", "Restore the key file"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
			if _, serr := os.Stat(keyFile); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("a key file was written: %v", serr)
			}
			if after := listTree(t, dir); after != before {
				t.Fatalf("outbox changed:\nbefore %s\nafter  %s", before, after)
			}
			if CheckKey(dir, keyFile) == nil {
				t.Fatal("CheckKey accepted the missing key")
			}
			if tk.Meta.ID == "" {
				t.Fatal("no item id")
			}
		})
	}
}

// Moving the sealed items aside, as the error says, lets the outbox start
// again with a new key.
func TestMissingKeyAfterItemsMovedAsideOpens(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	_, _ = o.Enqueue(Meta{Kind: KindReport}, []byte("x"))
	_ = o.Close()
	_ = os.Remove(DefaultKeyFile(dir))
	if err := os.Rename(filepath.Join(dir, dirPending), filepath.Join(t.TempDir(), "aside")); err != nil {
		t.Fatal(err)
	}
	o2 := openTest(t, dir, nil)
	if st := o2.Stats(); st.PendingCount != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func listTree(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Name() == lockName {
			return nil
		}
		fi, _ := d.Info()
		size := int64(0)
		if fi != nil && !d.IsDir() {
			size = fi.Size()
		}
		fmt.Fprintf(&b, "%s:%d ", strings.TrimPrefix(p, dir), size)
		return nil
	})
	return b.String()
}

func TestSaveProgressSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	tk, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("x"))
	r := &recorder{errs: func(d *Delivery) error {
		if err := d.SaveProgress([]byte(`{"acked":[0,1]}`)); err != nil {
			return err
		}
		return errors.New("connection reset")
	}}
	stop := runFor(t, o, r)
	waitFor(t, func() bool { return o.Stats().Attempts >= 1 })
	stop()
	_ = o.Close()
	o2 := openTest(t, dir, nil)
	var seen string
	r2 := &recorder{errs: func(d *Delivery) error { seen = string(d.State.Progress); return nil }}
	o2.Wake()
	stop2 := runFor(t, o2, r2)
	defer stop2()
	waitFor(t, func() bool { return o2.Stats().PendingCount == 0 })
	if seen != `{"acked":[0,1]}` {
		t.Fatalf("progress after restart = %q (item %s)", seen, tk.Meta.ID)
	}
}

func TestImportLegacyRetryQueue(t *testing.T) {
	legacy := t.TempDir()
	item := `{"id":"x","type":"findings","report":{"version":"1.0","findings":[{"title":"t"}]},"created_at":"2026-01-01T00:00:00Z"}`
	_ = os.WriteFile(filepath.Join(legacy, "a.json"), []byte(item), 0o600)
	_ = os.WriteFile(filepath.Join(legacy, "hb.json"), []byte(`{"type":"heartbeat","report":{"x":1}}`), 0o600)
	_ = os.WriteFile(filepath.Join(legacy, "notes.txt"), []byte("keep"), 0o600)
	o := openTest(t, t.TempDir(), nil)
	n, err := o.ImportLegacyRetryQueue(legacy)
	if err != nil || n != 1 {
		t.Fatalf("import = %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(legacy, "a.json")); !os.IsNotExist(err) {
		t.Fatal("imported file not removed")
	}
	if _, err := os.Stat(filepath.Join(legacy, "notes.txt")); err != nil {
		t.Fatal("unrelated file removed")
	}
	if p := o.Pending(); len(p) != 1 || p[0].Kind != KindReport {
		t.Fatalf("pending = %+v", p)
	}
}

func TestWaitReturnsWhenDrainedOrBackingOff(t *testing.T) {
	o := openTest(t, t.TempDir(), func(c *Config) { c.BackoffBase = time.Hour; c.BackoffMax = time.Hour })
	r := &recorder{errs: func(d *Delivery) error {
		if string(d.Payload) == "down" {
			return errors.New("connection refused")
		}
		return nil
	}}
	_, _ = o.Enqueue(Meta{Kind: KindReport}, []byte("ok"))
	_, _ = o.Enqueue(Meta{Kind: KindReport}, []byte("down"))
	stop := runFor(t, o, r)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if st := o.Stats(); st.Delivered != 1 || st.PendingCount != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

// Reports stop short of a reserve that only command results may use, so a
// full outbox still lets a running command report its end.
func TestFullOutboxKeepsRoomForCommandResults(t *testing.T) {
	o := openTest(t, t.TempDir(), func(c *Config) { c.MaxBytes = 30000; c.MaxDiskFraction = -1 })
	for i := 0; ; i++ {
		_, err := o.Enqueue(Meta{Kind: KindReport}, []byte(strings.Repeat("x", 50)+fmt.Sprint(i)))
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil || i > 1000 {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	if _, err := o.Enqueue(Meta{Kind: KindCommandResult, CommandID: "c"}, []byte("result")); err != nil {
		t.Fatalf("command result refused: %v", err)
	}
	if o.Stats().Evicted != 0 {
		t.Fatal("a pending item was evicted")
	}
}

// A command log batch is evicted before results under the byte cap, and
// losing one never marks its command result lost: logs are best effort.
func TestCommandLogsAreEvictedFirstAndNeverMarkResultsLost(t *testing.T) {
	o := openTest(t, t.TempDir(), func(c *Config) { c.MaxBytes = 3000; c.MaxDiskFraction = -1 })
	rep, err := o.Enqueue(Meta{Kind: KindReport, CommandID: "c"}, []byte("report"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := o.Enqueue(Meta{Kind: KindCommandResult, CommandID: "c"}, []byte("result"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if _, err := o.Enqueue(Meta{Kind: KindCommandLog, CommandID: "c"}, []byte(strings.Repeat("l", 50)+fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if o.Stats().Evicted == 0 {
		t.Fatal("nothing evicted")
	}
	kept := map[string]bool{}
	for _, m := range o.Pending() {
		kept[m.ID] = true
	}
	if !kept[rep.Meta.ID] || !kept[res.Meta.ID] {
		t.Fatal("a report or the command result was evicted before the logs")
	}
	var lost string
	r := &recorder{errs: func(d *Delivery) error {
		if d.Meta.Kind == KindCommandResult {
			lost = d.State.LostResults
		}
		return nil
	}}
	stop := runFor(t, o, r)
	defer stop()
	waitFor(t, func() bool { return o.Stats().PendingCount == 0 })
	if lost != "" {
		t.Fatalf("an evicted log batch marked the command result lost: %q", lost)
	}
	if _, ok := o.DeadLetterForCommand("c"); ok {
		t.Fatal("unexpected dead letter")
	}
}

// Wake spreads the start of a drain: the queue becomes ready, but nothing
// is delivered before one random instant within min(WakeSpread, items ×
// 100 ms), so a fleet back after an outage does not upload its whole
// backlog at once. The queue keeps its order.
func TestWakeSpreadsTheDrain(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	o := openTest(t, t.TempDir(), func(c *Config) { c.now = func() time.Time { return now } })
	for i := range 400 {
		if _, err := o.Enqueue(Meta{Kind: KindReport}, fmt.Appendf(nil, "%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	starts := map[time.Time]bool{}
	for range 20 {
		o.mu.Lock()
		for _, e := range o.entries {
			e.state.NextAttempt = now.Add(time.Hour) // backing off after failures
		}
		o.mu.Unlock()
		o.Wake()
		o.mu.Lock()
		at := o.drainAt
		e, wake := o.nextLocked(now)
		o.mu.Unlock()
		if at.Before(now) || at.After(now.Add(DefaultWakeSpread)) {
			t.Fatalf("drain starts %s after wake, want within %s", at.Sub(now), DefaultWakeSpread)
		}
		if at.After(now) && (e != nil || !wake.Equal(at)) {
			t.Fatalf("an item was handed out before the drain start (wake %v)", wake)
		}
		starts[at] = true
	}
	if len(starts) < 2 {
		t.Fatal("the drain start is not random")
	}
	// A small queue starts within items × 100 ms; WakeSpread < 0 drains at once.
	if d := wakeDelay(DefaultWakeSpread, 3); d > 300*time.Millisecond {
		t.Fatalf("3 items: delay %s", d)
	}
	if d := wakeDelay(-1, 1000); d != 0 {
		t.Fatalf("WakeSpread < 0: delay %s", d)
	}
}

// A restart with the outbox at its cap, or under a cap lowered below what is
// queued, keeps every unacknowledged result: nothing is evicted for space and
// new items are still refused until deliveries make room.
func TestUnackedResultsSurviveRestartAtOrOverCap(t *testing.T) {
	dir := t.TempDir()
	capOf := func(max int64) func(*Config) {
		return func(c *Config) { c.MaxBytes = max; c.MaxDiskFraction = -1 }
	}
	o := openTest(t, dir, capOf(3000))
	var ids []string
	for i := range 40 {
		tk, err := o.Enqueue(Meta{Kind: KindReport}, append([]byte(strings.Repeat("x", 50)), byte(i)))
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, tk.Meta.ID)
	}
	if len(ids) == 0 || len(ids) == 40 {
		t.Fatalf("queued %d items, want the cap to be reached", len(ids))
	}
	_ = o.Close()

	for _, max := range []int64{3000, 1000} { // same cap, then a cap below the queued bytes
		o2 := openTest(t, dir, capOf(max))
		if st := o2.Stats(); st.PendingCount != len(ids) || st.Evicted != 0 {
			t.Fatalf("cap %d: stats %+v, want %d pending and none evicted", max, st, len(ids))
		}
		if _, err := o2.Enqueue(Meta{Kind: KindReport}, []byte("more")); !errors.Is(err, ErrFull) {
			t.Fatalf("cap %d: enqueue err = %v, want ErrFull", max, err)
		}
		_ = o2.Close()
	}
}
