package outbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

func openStore(t *testing.T, dir string) *localstore.Store {
	t.Helper()
	st, err := localstore.Open(localstore.Options{Dir: dir, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func itemFile(o *Outbox, id string) string { return filepath.Join(o.pendingDir, id+itemExt) }

func TestTenantKeysSealAndDeliver(t *testing.T) {
	dir, sdir := t.TempDir(), t.TempDir()
	st := openStore(t, sdir)
	o := openTest(t, dir, func(c *Config) { c.Store = st })
	ta, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a"}, []byte("findings-of-a"))
	tb, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-b"}, []byte("findings-of-b"))
	tn, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("findings-of-org-sensor"))
	for _, tk := range []*Ticket{ta, tb, tn} {
		data, _ := os.ReadFile(itemFile(o, tk.Meta.ID))
		if len(data) < 6 || data[4] != fileVersion2 {
			t.Fatalf("item %s not in format 2", tk.Meta.ID)
		}
		if bytes.Contains(data, []byte("findings-of")) {
			t.Fatal("payload visible on disk")
		}
	}
	_ = o.Close()

	// Reopen: every item is read back and delivered.
	o2 := openTest(t, dir, func(c *Config) { c.Store = st })
	r := &recorder{}
	stop := runFor(t, o2, r)
	waitFor(t, func() bool { return len(r.list()) == 3 })
	stop()
	got := r.list()
	sort.Strings(got)
	if got[0] != "findings-of-a" || got[1] != "findings-of-b" || got[2] != "findings-of-org-sensor" {
		t.Fatalf("delivered %v", got)
	}
	if ts := st.Tenants(); len(ts) != 3 {
		t.Fatalf("tenant keys %v", ts)
	}
}

// TestTenantItemSwapRefused: one organization's item copied over another's
// does not open (it is sealed under the other tenant's key and bound to
// its own id).
func TestTenantItemSwapRefused(t *testing.T) {
	dir := t.TempDir()
	st := openStore(t, t.TempDir())
	o := openTest(t, dir, func(c *Config) { c.Store = st })
	ta, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a"}, []byte("a"))
	tb, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-b"}, []byte("b"))
	_ = o.Close()
	data, _ := os.ReadFile(itemFile(o, ta.Meta.ID))
	if err := os.WriteFile(itemFile(o, tb.Meta.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(o.pendingDir, tb.Meta.ID+stateExt)) // force a rebuild from the item
	// Also try relabelling a's item as tenant b in the header.
	relabel := append([]byte(nil), data...)
	copy(relabel[8:], "tenant-b")
	if err := os.WriteFile(itemFile(o, ta.Meta.ID), relabel, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(o.pendingDir, ta.Meta.ID+stateExt))
	o2 := openTest(t, dir, func(c *Config) { c.Store = st })
	if s := o2.Stats(); s.PendingCount != 0 {
		t.Fatalf("swapped or relabelled items accepted: %+v", s)
	}
}

func TestDropTenantAndCryptoErase(t *testing.T) {
	dir := t.TempDir()
	st := openStore(t, t.TempDir())
	o := openTest(t, dir, func(c *Config) { c.Store = st })
	ta, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a"}, []byte("a"))
	_, _ = o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a"}, []byte("a2"))
	tb, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-b"}, []byte("b"))
	snapshot, _ := os.ReadFile(itemFile(o, ta.Meta.ID))
	n, err := o.DropTenant("tenant-a")
	if err != nil || n != 2 {
		t.Fatalf("dropped %d %v", n, err)
	}
	if res := waitResult(t, ta); !res.Evicted {
		t.Fatalf("ticket of a dropped item: %+v", res)
	}
	if err := st.EraseTenant("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if s := o.Stats(); s.PendingCount != 1 {
		t.Fatalf("pending after drop: %+v", s)
	}
	if _, err := os.Stat(itemFile(o, tb.Meta.ID)); err != nil {
		t.Fatal("other tenant's item removed")
	}
	// A copy of a's item restored from a snapshot can no longer be read.
	_ = o.Close()
	if err := os.WriteFile(itemFile(o, ta.Meta.ID), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	o2 := openTest(t, dir, func(c *Config) { c.Store = st })
	if s := o2.Stats(); s.PendingCount != 1 {
		t.Fatalf("erased tenant's item came back: %+v", s)
	}
}

// TestUpgradeFromVersion1: an outbox written without a store keeps
// delivering its items after the store is added; new items use format 2.
func TestUpgradeFromVersion1(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil)
	old, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("old"))
	_ = o.Close()
	st := openStore(t, t.TempDir())
	o2 := openTest(t, dir, func(c *Config) { c.Store = st })
	nw, _ := o2.Enqueue(Meta{Kind: KindReport}, []byte("new"))
	if d, _ := os.ReadFile(itemFile(o2, old.Meta.ID)); d[4] != fileVersion {
		t.Fatal("the old item was rewritten")
	}
	if d, _ := os.ReadFile(itemFile(o2, nw.Meta.ID)); d[4] != fileVersion2 {
		t.Fatal("the new item is not format 2")
	}
	r := &recorder{}
	stop := runFor(t, o2, r)
	waitFor(t, func() bool { return len(r.list()) == 2 })
	stop()
}

func TestStoreModeKeyRules(t *testing.T) {
	// Only format 2 items and no outbox key: opens.
	dir := t.TempDir()
	st := openStore(t, t.TempDir())
	o := openTest(t, dir, func(c *Config) { c.Store = st })
	_, _ = o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a"}, []byte("a"))
	_ = o.Close()
	_ = os.Remove(filepath.Join(dir, keyName))
	o2 := openTest(t, dir, func(c *Config) { c.Store = st })
	if s := o2.Stats(); s.PendingCount != 1 {
		t.Fatalf("format 2 item lost without the outbox key: %+v", s)
	}
	_ = o2.Close()

	// Format 1 items and no outbox key: refused, never a silent loss.
	dir2 := t.TempDir()
	o3 := openTest(t, dir2, nil)
	_, _ = o3.Enqueue(Meta{Kind: KindReport}, []byte("v1"))
	_ = o3.Close()
	_ = os.Remove(filepath.Join(dir2, keyName))
	if _, err := Open(Config{Dir: dir2, Store: st, Logf: quietLog(t)}); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("format 1 items without the key: %v", err)
	}
}

func FuzzTenantOpen(f *testing.F) {
	st, err := localstore.Open(localstore.Options{Dir: f.TempDir(), Logf: func(string, ...any) {}})
	if err != nil {
		f.Fatal(err)
	}
	z := tenantSealer{store: st}
	good, _ := z.seal(typeItem, "id", "tenant-a", []byte("x"))
	f.Add(good)
	f.Add([]byte("OCOB\x02I\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if pt, err := z.open(typeItem, "id", data); err == nil && !bytes.Equal(data, good) {
			t.Fatalf("forged file opened: %q", pt)
		}
	})
}
