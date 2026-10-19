package outbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

func janitorOver(t *testing.T, o *Outbox) (*localstore.Janitor, *localstore.Store) {
	t.Helper()
	st, err := localstore.Open(localstore.Options{Dir: t.TempDir(), Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	j, err := localstore.NewJanitor(localstore.JanitorConfig{Store: st, Outbox: o, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	return j, st
}

// A result the platform acknowledged is deleted at once, the janitor is
// told, and an unacknowledged one is never deleted by a sweep.
func TestAckedItemsGoUnackedStay(t *testing.T) {
	dir := t.TempDir()
	var acks atomic.Int64
	o := openTest(t, dir, func(c *Config) { c.OnDelivered = func(Meta) { acks.Add(1) } })
	jan, _ := janitorOver(t, o)
	r := &recorder{errs: func(d *Delivery) error {
		if string(d.Payload) == "stuck" {
			return errors.New("platform unreachable")
		}
		return nil
	}}
	ta, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("a"))
	tb, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("b"))
	tk, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("stuck"))
	stop := runFor(t, o, r)
	defer stop()
	if !waitResult(t, ta).Delivered || !waitResult(t, tb).Delivered {
		t.Fatal("not delivered")
	}
	waitFor(t, func() bool { return acks.Load() == 2 })
	if _, err := jan.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending := o.Pending()
	if len(pending) != 1 || pending[0].ID != tk.Meta.ID {
		t.Fatalf("pending after sweep: %+v", pending)
	}
	files, _ := filepath.Glob(filepath.Join(dir, dirPending, "*"+itemExt))
	if len(files) != 1 {
		t.Fatalf("item files on disk: %v", files)
	}
	if b := jan.Status().Bytes[localstore.ClassOutbox]; b <= 0 {
		t.Fatalf("outbox bytes not reported: %+v", jan.Status().Bytes)
	}
	// Even under a tiny quota the stuck item is kept: sweeping only stops
	// the claiming.
	jan.SetPolicy(localstore.Policy{StoreQuotaBytes: 1})
	_, _ = jan.Sweep(context.Background())
	if len(o.Pending()) != 1 {
		t.Fatal("an unacked item was evicted for space")
	}
}

func TestDeadLettersPurgedAfterTheirAge(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	o := openTest(t, dir, func(c *Config) { c.now = func() time.Time { return now } })
	jan, _ := janitorOver(t, o)
	r := &recorder{errs: func(*Delivery) error { return Permanent(422, "bad", nil, errors.New("422")) }}
	tp, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("poison"))
	stop := runFor(t, o, r)
	if waitResult(t, tp).Dead == nil {
		t.Fatal("not dead-lettered")
	}
	stop()
	now = now.Add(6 * 24 * time.Hour)
	if rep, _ := jan.Sweep(context.Background()); rep.Removed[localstore.ClassDeadLetter] != 0 {
		t.Fatalf("a young dead letter was purged: %+v", rep)
	}
	now = now.Add(2 * 24 * time.Hour)
	rep, _ := jan.Sweep(context.Background())
	if rep.Removed[localstore.ClassDeadLetter] != 1 || len(o.DeadLetters()) != 0 {
		t.Fatalf("report %+v", rep)
	}
	files, _ := os.ReadDir(filepath.Join(dir, dirDead))
	if len(files) != 0 {
		t.Fatalf("dead files left: %v", files)
	}
}

func TestDropTenantReportsInFlightItems(t *testing.T) {
	st := openStore(t, t.TempDir())
	o := openTest(t, t.TempDir(), func(c *Config) { c.Store = st })
	started, release := make(chan struct{}), make(chan struct{})
	d := DelivererFunc(func(_ context.Context, dl *Delivery) (any, error) {
		if dl.Meta.TenantID == "tenant-a" {
			close(started)
			<-release
		}
		return nil, nil
	})
	ta, _ := o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a"}, []byte("a"))
	stop := runFor(t, o, d)
	defer stop()
	<-started
	_, _ = o.Enqueue(Meta{Kind: KindReport, TenantID: "tenant-a", CommandID: "later"}, []byte("a2"))
	n, inflight, err := o.DropTenant("tenant-a")
	if err != nil || inflight != 1 || n != 1 {
		t.Fatalf("dropped %d, in flight %d, %v", n, inflight, err)
	}
	close(release)
	if !waitResult(t, ta).Delivered {
		t.Fatal("the in-flight item was not left to finish")
	}
}
