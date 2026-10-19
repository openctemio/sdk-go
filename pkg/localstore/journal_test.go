package localstore

import (
	"errors"
	"testing"
	"time"
)

func TestJournalStepsAndFinish(t *testing.T) {
	s := openT(t, t.TempDir())
	j, err := s.Journal("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(JobRecord{CommandID: "cmd-1", LeaseEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(JobRecord{CommandID: "cmd-1", LeaseEpoch: 1}); err == nil {
		t.Fatal("same command and epoch journaled twice")
	}
	if err := j.StepStarted("cmd-1", "discover", true); err != nil {
		t.Fatal(err)
	}
	if err := j.StepDone("cmd-1", "discover"); err != nil {
		t.Fatal(err)
	}
	if err := j.StepStarted("cmd-1", "validate", false); err != nil {
		t.Fatal(err)
	}
	// Within the same run, a non-repeatable step that started cannot start again.
	if err := j.StepStarted("cmd-1", "validate", false); !errors.Is(err, ErrStepRefused) {
		t.Fatalf("second start: %v", err)
	}
	if err := j.StepDone("cmd-1", "validate"); err != nil {
		t.Fatal(err)
	}
	if err := j.Finish("cmd-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Get("cmd-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finished job still journaled: %v", err)
	}
}

// TestRecoverNeverRerunsDestructiveStep: a crash during a non-repeatable
// step is reported as interrupted after restart, and the platform handing
// the same command back cannot make that step run a second time.
func TestRecoverNeverRerunsDestructiveStep(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir)
	j, _ := s.Journal("tenant-a")
	if err := j.Begin(JobRecord{CommandID: "cmd-1", LeaseEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	if err := j.StepStarted("cmd-1", "scan", true); err != nil {
		t.Fatal(err)
	}
	if err := j.StepDone("cmd-1", "scan"); err != nil {
		t.Fatal(err)
	}
	if err := j.StepStarted("cmd-1", "exploit-check", false); err != nil {
		t.Fatal(err)
	}
	other, _ := s.Journal("tenant-b")
	if err := other.Begin(JobRecord{CommandID: "cmd-2"}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close() // the crash

	s2 := openT(t, dir)
	its, err := s2.Recover(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(its) != 2 {
		t.Fatalf("interruptions = %+v, want 2", its)
	}
	var mine *Interruption
	for i := range its {
		if its[i].Record.CommandID == "cmd-1" {
			mine = &its[i]
		}
	}
	if mine == nil || mine.Step != "exploit-check" || mine.Record.Tenant != "tenant-a" || !mine.Record.Interrupted {
		t.Fatalf("interruption %+v", mine)
	}
	// A second recovery in the same boot reports nothing new.
	if again, _ := s2.Recover(0); len(again) != 0 {
		t.Fatalf("reported twice: %+v", again)
	}
	// The platform requeues the command to this sensor with a new epoch.
	j2, _ := s2.Journal("tenant-a")
	if err := j2.Begin(JobRecord{CommandID: "cmd-1", LeaseEpoch: 2}); err != nil {
		t.Fatal(err)
	}
	if err := j2.StepStarted("cmd-1", "scan", true); err != nil {
		t.Fatalf("repeatable step refused: %v", err)
	}
	if err := j2.StepStarted("cmd-1", "exploit-check", false); !errors.Is(err, ErrStepRefused) {
		t.Fatalf("non-repeatable step after an interrupted run: %v, want ErrStepRefused", err)
	}
	// A step marked repeatable now cannot launder the earlier one either.
	if err := j2.StepStarted("cmd-1", "exploit-check", true); !errors.Is(err, ErrStepRefused) {
		t.Fatalf("re-marked repeatable: %v, want ErrStepRefused", err)
	}
}

func TestRecoverDropsOldTombstones(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	clock := func(o *Options) { o.now = func() time.Time { return now } }
	s := openT(t, dir, clock)
	j, _ := s.Journal(SensorTenant)
	_ = j.Begin(JobRecord{CommandID: "cmd-1"})
	_ = s.Close()
	s2 := openT(t, dir, clock)
	if its, _ := s2.Recover(time.Hour); len(its) != 1 {
		t.Fatalf("interruptions %v", its)
	}
	now = now.Add(2 * time.Hour)
	if _, err := s2.Recover(time.Hour); err != nil {
		t.Fatal(err)
	}
	j2, _ := s2.Journal(SensorTenant)
	if _, err := j2.Get("cmd-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old tombstone kept: %v", err)
	}
}

func TestJournalErasedWithTenant(t *testing.T) {
	s := openT(t, t.TempDir())
	j, _ := s.Journal("tenant-a")
	_ = j.Begin(JobRecord{CommandID: "cmd-1"})
	if err := s.EraseTenant("tenant-a"); err != nil {
		t.Fatal(err)
	}
	j, _ = s.Journal("tenant-a")
	if _, err := j.Get("cmd-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("journal survived erasure: %v", err)
	}
}

func TestJournalWritesOnCriticalDisk(t *testing.T) {
	sp := space{freeBytes: 1 << 20, totalBytes: 1 << 30}
	s := openT(t, t.TempDir(), func(o *Options) { o.space = func(string) (space, bool) { return sp, true } })
	j, _ := s.Journal(SensorTenant)
	if err := j.Begin(JobRecord{CommandID: "cmd-1"}); err != nil {
		t.Fatalf("journal write on a critical disk: %v", err)
	}
}
