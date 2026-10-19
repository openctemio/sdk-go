package localstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func quiet(string, ...any) {}

func openT(t *testing.T, dir string, mod ...func(*Options)) *Store {
	t.Helper()
	o := Options{Dir: dir, Logf: quiet}
	for _, m := range mod {
		m(&o)
	}
	s, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func kvT(t *testing.T, s *Store, tenant, ns string) *KV {
	t.Helper()
	kv, err := s.KV(tenant, ns)
	if err != nil {
		t.Fatalf("KV: %v", err)
	}
	return kv
}

func TestRoundTripAndReopen(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	if s.Stats().Boot != 1 {
		t.Fatalf("boot = %d, want 1", s.Stats().Boot)
	}
	kv := kvT(t, s, SensorTenant, "policy")
	if err := kv.Put("scope", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := kv.Get("scope")
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if _, err := kv.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	_ = s.Close()

	s2 := openT(t, dir)
	if s2.Stats().Boot != 2 {
		t.Fatalf("boot after reopen = %d, want 2", s2.Stats().Boot)
	}
	got, err = kvT(t, s2, SensorTenant, "policy").Get("scope")
	if err != nil || string(got) != "hello" {
		t.Fatalf("after reopen Get = %q, %v", got, err)
	}
	// Nothing written in clear: the plaintext never appears on disk.
	assertNoPlaintext(t, dir, []byte("hello"))
}

func assertNoPlaintext(t *testing.T, dir string, needle []byte) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(p)
		if bytes.Contains(data, needle) {
			t.Errorf("%s contains the plaintext", p)
		}
		return nil
	})
}

func TestPermissions(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	if err := kvT(t, s, "t1", "ns").Put("a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, _ := d.Info()
		perm := fi.Mode().Perm()
		if d.IsDir() && perm != dirMode {
			t.Errorf("%s: dir mode %04o", p, perm)
		}
		if !d.IsDir() && perm&0o077 != 0 {
			t.Errorf("%s: file mode %04o", p, perm)
		}
		return nil
	})
}

func TestSecondOpenLocked(t *testing.T) {
	dir := t.TempDir()
	openT(t, dir)
	if _, err := Open(Options{Dir: dir, Logf: quiet}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v, want ErrLocked", err)
	}
}

func TestMissingMasterKeyRefused(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	_ = kvT(t, s, SensorTenant, "ns")
	_ = s.Close()
	if err := os.Remove(filepath.Join(dir, masterKeyName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir, Logf: quiet}); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("Open without key: %v, want ErrKeyMissing", err)
	}
}

func TestExplicitKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyDir := t.TempDir()
	kf := filepath.Join(keyDir, "store.key")
	if _, err := Open(Options{Dir: dir, KeyFile: kf, Logf: quiet}); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("missing explicit key: %v, want ErrKeyFile", err)
	}
	s := openT(t, dir, func(o *Options) { o.KeyFile = kf; o.CreateKey = true })
	if s.Stats().KeyOnDataVolume {
		t.Fatal("explicit key reported on the data volume")
	}
	if _, err := os.Stat(filepath.Join(dir, masterKeyName)); !os.IsNotExist(err) {
		t.Fatal("default key file created next to the data")
	}
	_ = s.Close()

	// A key others can read is refused.
	if err := os.Chmod(kf, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir, KeyFile: kf, Logf: quiet}); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("0644 key: %v, want ErrKeyFile", err)
	}
	// Group read only (a secret mounted with fsGroup) is accepted.
	if err := os.Chmod(kf, 0o440); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(Options{Dir: dir, KeyFile: kf, Logf: quiet})
	if err != nil {
		t.Fatalf("0440 key: %v", err)
	}
	_ = s2.Close()
	// A malformed key file is refused.
	if err := os.Chmod(kf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir, KeyFile: kf, Logf: quiet}); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("malformed key: %v, want ErrKeyFile", err)
	}
}

func TestWrongMasterKeyIsTamper(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	if err := kvT(t, s, "t1", "ns").Put("a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	key := bytes.Repeat([]byte{7}, keyLen)
	content, _ := FormatKey(key)
	if err := os.WriteFile(filepath.Join(dir, masterKeyName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	var events []TamperEvent
	s2 := openT(t, dir, func(o *Options) { o.OnTamper = func(e TamperEvent) { events = append(events, e) } })
	if _, err := s2.KV("t1", "ns"); !errors.Is(err, ErrTampered) {
		t.Fatalf("KV under the wrong master key: %v, want ErrTampered", err)
	}
	// The wrapped key is not replaced: the operator can still restore the
	// right master key.
	if _, err := os.Stat(filepath.Join(dir, dirKeys, "t1.key")); err != nil {
		t.Fatalf("wrapped key replaced or removed: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no tamper event")
	}
}

func TestTamperedRecordQuarantined(t *testing.T) {
	dir := t.TempDir()
	var events []TamperEvent
	s := openT(t, dir, func(o *Options) { o.OnTamper = func(e TamperEvent) { events = append(events, e) } })
	kv := kvT(t, s, SensorTenant, "ns")
	if err := kv.Put("a", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	p := kv.path("a")
	data, _ := os.ReadFile(p)
	data[len(data)-1] ^= 0x01
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get("a"); !errors.Is(err, ErrTampered) {
		t.Fatalf("Get tampered: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("tampered record not moved out")
	}
	if n, _ := os.ReadDir(filepath.Join(dir, dirCorrupt)); len(n) != 1 {
		t.Fatalf("quarantine holds %d files, want 1", len(n))
	}
	st := s.Stats()
	if st.Tampered != 1 || st.LastTamper == nil || st.LastTamper.Name != "a" || len(events) != 1 {
		t.Fatalf("stats %+v events %v", st, events)
	}
	// Truncated and empty files are tampering too, never a panic.
	for _, bad := range [][]byte{nil, []byte("OCLS"), data[:20]} {
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := kv.Get("a"); !errors.Is(err, ErrTampered) {
			t.Fatalf("Get %d bytes: %v", len(bad), err)
		}
	}
}

func TestRecordBoundToNameNamespaceAndTenant(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	a := kvT(t, s, "tenant-a", "ns")
	b := kvT(t, s, "tenant-b", "ns")
	a2 := kvT(t, s, "tenant-a", "other")
	if err := a.Put("x", []byte("secret-of-a")); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(a.path("x"))
	cases := map[string]string{
		"other name":      a.path("y"),
		"other namespace": a2.path("x"),
		"other tenant":    b.path("x"),
	}
	for label, dst := range cases {
		if err := os.WriteFile(dst, src, 0o600); err != nil {
			t.Fatal(err)
		}
		var kv *KV
		var name string
		switch label {
		case "other name":
			kv, name = a, "y"
		case "other namespace":
			kv, name = a2, "x"
		default:
			kv, name = b, "x"
		}
		if got, err := kv.Get(name); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: Get = %q, %v; want ErrTampered", label, got, err)
		}
	}
}

func TestEraseTenant(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	a := kvT(t, s, "tenant-a", "journal")
	b := kvT(t, s, "tenant-b", "journal")
	if err := a.Put("job1", []byte("result-of-a")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("job1", []byte("result-of-b")); err != nil {
		t.Fatal(err)
	}
	// A snapshot taken before the erasure (a backup, a volume copy).
	snap, _ := os.ReadFile(a.path("job1"))
	if err := s.EraseTenant("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, dirKeys, "tenant-a.key")); !os.IsNotExist(err) {
		t.Fatal("tenant key still on disk")
	}
	if _, err := os.Stat(filepath.Join(dir, dirKV, "tenant-a")); !os.IsNotExist(err) {
		t.Fatal("tenant records still on disk")
	}
	// The other tenant is untouched.
	if got, err := b.Get("job1"); err != nil || string(got) != "result-of-b" {
		t.Fatalf("tenant-b after erasing a: %q, %v", got, err)
	}
	// The snapshot can never be opened again, even put back in place.
	a = kvT(t, s, "tenant-a", "journal")
	if err := os.WriteFile(a.path("job1"), snap, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get("job1"); !errors.Is(err, ErrTampered) {
		t.Fatalf("restored snapshot after erasure: %v, want ErrTampered", err)
	}
	if s.Stats().Erased != 1 {
		t.Fatalf("erased = %d", s.Stats().Erased)
	}
	if !s.HasTenant("tenant-b") || s.HasTenant("never-seen") || s.HasTenant("../x") {
		t.Fatal("HasTenant")
	}
	if got := s.Tenants(); len(got) != 2 {
		t.Fatalf("tenants = %v", got)
	}
}

func TestMissingTenantKeyDropsOrphanData(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	if err := kvT(t, s, "t1", "ns").Put("a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := os.Remove(filepath.Join(dir, dirKeys, "t1.key")); err != nil {
		t.Fatal(err)
	}
	s2 := openT(t, dir)
	kv := kvT(t, s2, "t1", "ns")
	if _, err := kv.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan record: %v, want ErrNotFound", err)
	}
}

func TestExpiryFailsClosed(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	s := openT(t, dir, func(o *Options) { o.now = func() time.Time { return now } })
	kv := kvT(t, s, SensorTenant, "policy")
	if err := kv.Put("scope", []byte("cidrs"), WithExpiry(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := kv.Put("other", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.Get("scope"); err != nil || string(got) != "cidrs" {
		t.Fatalf("fresh: %q %v", got, err)
	}
	now = now.Add(time.Hour)
	got, err := kv.Get("scope")
	if !errors.Is(err, ErrExpired) || got != nil {
		t.Fatalf("expired: %q %v; want no data and ErrExpired", got, err)
	}
	info, err := kv.Stat("scope")
	if err != nil || info.ExpiresAt.IsZero() {
		t.Fatalf("Stat expired: %+v %v", info, err)
	}
	n, err := kv.SweepExpired()
	if err != nil || n != 1 {
		t.Fatalf("sweep = %d %v", n, err)
	}
	if names, _ := kv.List(); len(names) != 1 || names[0] != "other" {
		t.Fatalf("after sweep: %v", names)
	}
}

func TestDiskLevels(t *testing.T) {
	dir := t.TempDir()
	sp := space{freeBytes: 10 << 30, totalBytes: 20 << 30, freeFiles: 1e6, totalFiles: 2e6}
	s := openT(t, dir, func(o *Options) { o.space = func(string) (space, bool) { return sp, true } })
	kv := kvT(t, s, SensorTenant, "ns")
	if d := s.Disk(); d.Level != DiskOK {
		t.Fatalf("level %v", d)
	}
	sp.freeBytes = 512 << 20 // 512 MiB of 20 GiB: under 5 %
	if ok, why := s.AcceptsWork(); ok || why == "" {
		t.Fatalf("low disk accepts work: %v %q", ok, why)
	}
	if err := kv.Put("a", []byte("x")); err != nil {
		t.Fatalf("Put at low: %v", err)
	}
	sp.freeBytes = 10 << 20
	if d := s.Disk(); d.Level != DiskCritical {
		t.Fatalf("level %v", d)
	}
	if err := kv.Put("b", []byte("x")); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("Put at critical: %v", err)
	}
	if err := kv.Put("c", []byte("x"), Critical()); err != nil {
		t.Fatalf("critical Put at critical: %v", err)
	}
	if err := kv.Delete("a"); err != nil {
		t.Fatalf("Delete at critical: %v", err)
	}
	sp = space{freeBytes: 10 << 30, totalBytes: 20 << 30, freeFiles: 50, totalFiles: 2e6}
	if d := s.Disk(); d.Level != DiskCritical {
		t.Fatalf("inodes exhausted: %v", d)
	}
	s2dir := t.TempDir()
	s2 := openT(t, s2dir, func(o *Options) { o.space = func(string) (space, bool) { return space{}, false } })
	if ok, _ := s2.AcceptsWork(); !ok {
		t.Fatal("unknown disk refuses work")
	}
}

func TestAdoptTenantKey(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	key := bytes.Repeat([]byte{9}, keyLen)
	if err := s.AdoptTenantKey(SensorTenant, key); err != nil {
		t.Fatal(err)
	}
	if err := s.AdoptTenantKey(SensorTenant, key); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("a second adoption: %v, want ErrKeyExists", err)
	}
	z, err := s.Sealer(SensorTenant, "outbox")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := z.Seal("item-1", []byte("report"))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2 := openT(t, dir)
	z2, _ := s2.Sealer(SensorTenant, "outbox")
	if pt, err := z2.Open("item-1", blob); err != nil || string(pt) != "report" {
		t.Fatalf("Open after reopen: %q %v", pt, err)
	}
	if _, err := z2.Open("item-2", blob); !errors.Is(err, ErrTampered) {
		t.Fatalf("blob under another name: %v", err)
	}
	other, _ := s2.Sealer(SensorTenant, "content")
	if _, err := other.Open("item-1", blob); !errors.Is(err, ErrTampered) {
		t.Fatalf("blob under another purpose: %v", err)
	}
}

func TestInvalidNames(t *testing.T) {
	s := openT(t, t.TempDir())
	for _, n := range []string{"", ".", "..", "../x", "a/b", `a\b`, ".hidden", "a..b", string(make([]byte, 200))} {
		if _, err := s.KV(n, "ns"); !errors.Is(err, ErrInvalidName) {
			t.Errorf("tenant %q accepted", n)
		}
		if _, err := s.KV("t", n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("namespace %q accepted", n)
		}
	}
	kv := kvT(t, s, "t", "ns")
	if err := kv.Put("../../keys/t", []byte("x")); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("traversal name: %v", err)
	}
}

func TestTooLarge(t *testing.T) {
	s := openT(t, t.TempDir())
	kv := kvT(t, s, "t", "ns")
	if err := kv.Put("big", make([]byte, maxRecordBytes)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("big record: %v", err)
	}
}

func TestLeftoverTmpCleaned(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	_ = s.Close()
	junk := filepath.Join(dir, dirTmp, "deadbeef.tmp")
	if err := os.WriteFile(junk, []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	openT(t, dir)
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Fatal("leftover tmp file kept")
	}
}

func TestBootRecordTamperReported(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	_ = kvT(t, s, "t", "ns")
	_ = s.Close()
	if err := os.Remove(filepath.Join(dir, metaName)); err != nil {
		t.Fatal(err)
	}
	s2 := openT(t, dir)
	if st := s2.Stats(); st.Tampered != 1 || st.Boot != 1 {
		t.Fatalf("stats after boot record removal: %+v", st)
	}
}

func TestConcurrentUse(t *testing.T) {
	s := openT(t, t.TempDir())
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kv, err := s.KV(fmt.Sprintf("t%d", i%3), "ns")
			if err != nil {
				t.Error(err)
				return
			}
			for j := range 20 {
				name := fmt.Sprintf("r%d", j%5)
				if err := kv.Put(name, []byte(name)); err != nil {
					t.Error(err)
				}
				if got, err := kv.Get(name); err != nil || string(got) != name {
					t.Errorf("Get %s = %q %v", name, got, err)
				}
			}
		}()
	}
	wg.Wait()
	if st := s.Stats(); st.Tampered != 0 {
		t.Fatalf("tampered under concurrency: %+v", st)
	}
}
