package localstore

import (
	"errors"
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
