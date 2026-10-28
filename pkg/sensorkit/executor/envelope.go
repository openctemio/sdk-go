package executor

// Envelope is the resource envelope of one task (research/318 §6.2): where
// the sensor's cgroup is delegated (EnableEnvelopes), the task runs in a
// cgroup v2 of its own with these limits; elsewhere its memory and process
// bounds become rlimits of the launcher (EnvelopeRlimit).
type Envelope struct {
	// CPU is the CPU ceiling in cores (cpu.max); 0 sets none.
	CPU float64
	// MemoryMax is the hard memory limit (memory.max); 0 sets none.
	MemoryMax uint64
	// Pids bounds the task's processes and threads (pids.max).
	Pids uint64
}

// Envelope kinds (Status.Envelope).
const (
	EnvelopeCgroup = "cgroup"
	EnvelopeRlimit = "rlimit"
)

// minRlimitMemory is the smallest data limit an rlimit envelope sets: the
// data rlimit counts every private writable mapping, which a runtime with
// its own allocator reserves generously.
const minRlimitMemory = 1 << 30

// rlimitEnvelope narrows limits by the envelope where cgroups are not
// used: twice the memory limit (at least minRlimitMemory) as the data
// limit, and the process bound. A limit the caller set explicitly is kept.
func rlimitEnvelope(l, explicit Limits, e *Envelope) Limits {
	if e == nil {
		return l
	}
	if explicit.MemoryBytes == 0 && e.MemoryMax > 0 {
		l.MemoryBytes = min(l.MemoryBytes, max(2*e.MemoryMax, minRlimitMemory))
	}
	if explicit.Processes == 0 && e.Pids > 0 {
		l.Processes = min(l.Processes, e.Pids)
	}
	return l
}
