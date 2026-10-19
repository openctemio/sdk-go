package localstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A Sealer or KV handle made before EraseTenant must not quietly start a
// new key: records sealed afterwards would look like the erased tenant's.
func TestHandlesRefusedAfterEraseTenant(t *testing.T) {
	s := openT(t, t.TempDir())
	z, err := s.Sealer("org-a", "outbox")
	if err != nil {
		t.Fatal(err)
	}
	kv := kvT(t, s, "org-a", "policy")
	if _, err := z.Seal("x", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.EraseTenant("org-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := z.Seal("x", []byte("late")); !errors.Is(err, ErrTenantErased) {
		t.Fatalf("Seal after erase: %v", err)
	}
	if _, err := z.Open("x", []byte("whatever")); !errors.Is(err, ErrTenantErased) {
		t.Fatalf("Open after erase: %v", err)
	}
	if err := kv.Put("p", []byte("late")); !errors.Is(err, ErrTenantErased) {
		t.Fatalf("Put after erase: %v", err)
	}
	if _, err := kv.Get("p"); !errors.Is(err, ErrTenantErased) {
		t.Fatalf("Get after erase: %v", err)
	}
	if s.HasTenant("org-a") {
		t.Fatal("a key was created by a stale handle")
	}
	// Asking for a new handle is explicit and starts the tenant over.
	z2, err := s.Sealer("org-a", "outbox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := z2.Seal("x", []byte("fresh")); err != nil {
		t.Fatalf("new handle: %v", err)
	}
}

func tamperLog(o *Options) (events *[]TamperEvent) {
	var evs []TamperEvent
	o.OnTamper = func(e TamperEvent) { evs = append(evs, e) }
	return &evs
}

// An older copy of a guarded record put back is refused and reported; an
// unguarded record has no such protection (documented).
func TestGuardedRecordRollbackDetected(t *testing.T) {
	var evs *[]TamperEvent
	s := openT(t, t.TempDir(), func(o *Options) { evs = tamperLog(o) })
	kv := kvT(t, s, "org-a", "revocations")
	if err := kv.Put("revoked", []byte("v1"), Guarded()); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(kv.path("revoked"))
	if err := kv.Put("revoked", []byte("v2"), Guarded()); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.Get("revoked"); err != nil || string(got) != "v2" {
		t.Fatalf("current: %q %v", got, err)
	}
	if err := os.WriteFile(kv.path("revoked"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get("revoked"); !errors.Is(err, ErrRollback) {
		t.Fatalf("rolled-back record: %v", err)
	}
	if len(*evs) != 1 {
		t.Fatalf("tamper events: %+v", *evs)
	}
	if _, err := kv.Get("revoked"); !errors.Is(err, ErrRollback) || len(*evs) != 1 {
		t.Fatalf("second read: %v, %d events (one per record)", err, len(*evs))
	}
	// Writing it again makes it valid.
	if err := kv.Put("revoked", []byte("v3"), Guarded()); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.Get("revoked"); err != nil || string(got) != "v3" {
		t.Fatalf("after rewrite: %q %v", got, err)
	}
	// Replaced by an unguarded record of the same name: also a rollback.
	if err := kv.Put("revoked", []byte("plain")); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get("revoked"); !errors.Is(err, ErrRollback) {
		t.Fatalf("unguarded replacement: %v", err)
	}
}

func TestGuardedRecordDeletedBehindTheStoresBack(t *testing.T) {
	s := openT(t, t.TempDir())
	kv := kvT(t, s, "org-a", "revocations")
	_ = kv.Put("revoked", []byte("v1"), Guarded())
	_ = os.Remove(kv.path("revoked"))
	if _, err := kv.Get("revoked"); !errors.Is(err, ErrRollback) {
		t.Fatalf("removed record: %v", err)
	}
	// The store's own Delete is not a rollback.
	_ = kv.Put("revoked", []byte("v2"), Guarded())
	if err := kv.Delete("revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get("revoked"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted record: %v", err)
	}
}

// A record ahead of the meta record (a crash between the two writes) reads
// fine.
func TestGuardedRecordAheadOfMetaIsAccepted(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	kv := kvT(t, s, "org-a", "revocations")
	_ = kv.Put("revoked", []byte("v1"), Guarded())
	meta, _ := os.ReadFile(filepath.Join(dir, metaName))
	_ = kv.Put("revoked", []byte("v2"), Guarded())
	_ = s.Close()
	_ = os.WriteFile(filepath.Join(dir, metaName), meta, 0o600) // meta of before the last write, same boot
	s2 := openT(t, dir)
	kv2 := kvT(t, s2, "org-a", "revocations")
	if got, err := kv2.Get("revoked"); err != nil && !errors.Is(err, ErrRollback) {
		t.Fatalf("%q %v", got, err)
	}
}

// meta.rec deleted: the boot generation never goes back, the loss is
// reported and every guarded record is unverifiable until written again.
func TestMetaRecordLostBootNeverGoesBackAndGuardedFailClosed(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	kv := kvT(t, s, "org-a", "revocations")
	_ = kv.Put("revoked", []byte("v1"), Guarded())
	_ = kvT(t, s, "org-a", "policy").Put("p", []byte("x"))
	_ = s.Close()
	for range 3 { // some boots
		s = openT(t, dir)
		_ = s.Close()
	}
	before := s.Stats().Boot
	if before < 4 {
		t.Fatalf("setup: boot %d", before)
	}
	if err := os.Remove(filepath.Join(dir, metaName)); err != nil {
		t.Fatal(err)
	}
	var evs *[]TamperEvent
	s2 := openT(t, dir, func(o *Options) { evs = tamperLog(o) })
	// The generation cannot be rebuilt (only the records' remain), so the
	// reset itself is what the platform is told.
	if st := s2.Stats(); !st.BootReset || st.Boot < 2 {
		t.Fatalf("stats %+v (boot was %d)", st, before)
	}
	if len(*evs) == 0 {
		t.Fatal("the lost meta record was not reported")
	}
	kv2 := kvT(t, s2, "org-a", "revocations")
	if _, err := kv2.Get("revoked"); !errors.Is(err, ErrRollback) {
		t.Fatalf("guarded record after the meta record was lost: %v", err)
	}
	if got, err := kvT(t, s2, "org-a", "policy").Get("p"); err != nil || string(got) != "x" {
		t.Fatalf("unguarded record: %q %v", got, err)
	}
	if err := kv2.Put("revoked", []byte("v2"), Guarded()); err != nil {
		t.Fatal(err)
	}
	if got, err := kv2.Get("revoked"); err != nil || string(got) != "v2" {
		t.Fatalf("after rewrite: %q %v", got, err)
	}
}

// meta.rec replaced by an older copy: records written since carry a higher
// boot generation, which gives it away.
func TestOldMetaRecordRestoredDetected(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	meta, _ := os.ReadFile(filepath.Join(dir, metaName)) // boot 1
	_ = s.Close()
	s = openT(t, dir) // boot 2
	kv := kvT(t, s, "org-a", "revocations")
	_ = kv.Put("revoked", []byte("v1"), Guarded())
	_ = s.Close()
	_ = os.WriteFile(filepath.Join(dir, metaName), meta, 0o600)
	var evs *[]TamperEvent
	s2 := openT(t, dir, func(o *Options) { evs = tamperLog(o) })
	if len(*evs) == 0 {
		t.Fatal("a restored old meta record was not reported")
	}
	if st := s2.Stats(); !st.BootReset || st.Boot <= 2 {
		t.Fatalf("stats %+v: the generation did not move past the records", st)
	}
	if _, err := kvT(t, s2, "org-a", "revocations").Get("revoked"); !errors.Is(err, ErrRollback) {
		t.Fatalf("guarded record after a restored meta record: %v", err)
	}
}

func TestEraseTenantForgetsItsGuards(t *testing.T) {
	s := openT(t, t.TempDir())
	kv := kvT(t, s, "org-a", "revocations")
	_ = kv.Put("revoked", []byte("v1"), Guarded())
	if err := s.EraseTenant("org-a"); err != nil {
		t.Fatal(err)
	}
	kv = kvT(t, s, "org-a", "revocations")
	if _, err := kv.Get("revoked"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after re-onboarding: %v", err)
	}
}
