package executor

import "testing"

func TestRlimitEnvelope(t *testing.T) {
	d := DefaultLimits()
	l := rlimitEnvelope(d, Limits{}, &Envelope{MemoryMax: 512 << 20, Pids: 256})
	if l.MemoryBytes != 1<<30 || l.Processes != 256 {
		t.Fatalf("light: %+v", l)
	}
	l = rlimitEnvelope(d, Limits{}, &Envelope{MemoryMax: 3 << 30, Pids: 4096})
	if l.MemoryBytes != 6<<30 || l.Processes != d.Processes {
		t.Fatalf("heavy: %+v (never above the defaults)", l)
	}
	explicit := Limits{MemoryBytes: 100 << 20, Processes: 10}
	l = rlimitEnvelope(Limits{MemoryBytes: 100 << 20, Processes: 10}, explicit, &Envelope{MemoryMax: 4 << 30, Pids: 64})
	if l.MemoryBytes != 100<<20 || l.Processes != 10 {
		t.Fatalf("explicit limits not kept: %+v", l)
	}
	if got := rlimitEnvelope(d, Limits{}, nil); got != d {
		t.Fatalf("nil envelope changed limits: %+v", got)
	}
}
