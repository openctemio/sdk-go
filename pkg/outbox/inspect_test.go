package outbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectReadsALockedOutboxWithoutChangingIt(t *testing.T) {
	dir := t.TempDir()
	o := openTest(t, dir, nil) // holds the lock, as a running sensor does
	// The poison item goes first: it is attempted before the failing ones
	// can open the circuit.
	dead, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("poison"))
	a, _ := o.Enqueue(Meta{Kind: KindReport}, []byte("a"))
	_, _ = o.Enqueue(Meta{Kind: KindReport}, []byte("b"))
	r := &recorder{errs: func(d *Delivery) error {
		if string(d.Payload) == "poison" {
			return Permanent(422, "schema-invalid", nil, nil)
		}
		return errorString("down")
	}}
	stop := runFor(t, o, r)
	waitResult(t, dead)
	stop()
	_ = os.WriteFile(filepath.Join(dir, dirPending, "stray"), []byte("x"), fileMode)

	before, _ := os.ReadDir(filepath.Join(dir, dirPending))
	in, err := Inspect(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if in.PendingCount != 2 || in.PendingBytes == 0 || in.Unreadable != 0 {
		t.Fatalf("inspection = %+v", in)
	}
	if !in.OldestPending.Equal(a.Meta.CreatedAt) {
		t.Fatalf("oldest = %v, want %v", in.OldestPending, a.Meta.CreatedAt)
	}
	if len(in.DeadLetters) != 1 || in.DeadLetters[0].Status != 422 {
		t.Fatalf("dead letters = %+v", in.DeadLetters)
	}
	after, _ := os.ReadDir(filepath.Join(dir, dirPending))
	if len(after) != len(before) {
		t.Fatal("Inspect changed the directory")
	}

	// Without the key: counts and sizes, no ages.
	in, err = Inspect(dir, filepath.Join(t.TempDir(), "missing.key"))
	if err != nil || in.PendingCount != 2 || in.Unreadable != 2 {
		t.Fatalf("keyless inspection = %+v, %v", in, err)
	}
	if _, err := Inspect(t.TempDir(), ""); err == nil {
		t.Fatal("a non-outbox directory was accepted")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
