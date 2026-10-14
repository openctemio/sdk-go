package core

// cpuMeter is the CPU time of a job's tool processes: each tracked process
// with the processes it started, read from the operating system when the
// progress is read (procTable). A process that exited keeps the CPU time it
// was last seen with; the total never goes down. Where process CPU time
// cannot be read it stays 0.
type cpuMeter struct {
	roots map[int]cpuRoot
	ended int64 // ms of tracked processes that exited
	last  int64 // the last total read
}

// cpuRoot is one tracked process: its start time (to tell it from a later
// process with the same pid) and the CPU ms of its tree when last read.
type cpuRoot struct {
	start uint64
	ms    int64
}

// maxTrackedProcesses bounds the processes one job tracks.
const maxTrackedProcesses = 64

func (m *cpuMeter) track(pid int) {
	if m.roots == nil {
		m.roots = map[int]cpuRoot{}
	}
	if _, ok := m.roots[pid]; ok || len(m.roots) >= maxTrackedProcesses {
		return
	}
	start, _ := procStart(pid)
	m.roots[pid] = cpuRoot{start: start}
}

// read is the job's CPU ms now.
func (m *cpuMeter) read() int64 {
	if len(m.roots) == 0 {
		return m.last
	}
	procs := procTable()
	if procs == nil {
		return m.last
	}
	var children map[int][]int
	total := m.ended
	for pid, r := range m.roots {
		p, alive := procs[pid]
		if !alive || (r.start != 0 && p.start != r.start) {
			m.ended += r.ms
			total += r.ms
			delete(m.roots, pid)
			continue
		}
		if children == nil {
			children = make(map[int][]int, len(procs))
			for cpid, cp := range procs {
				children[cp.ppid] = append(children[cp.ppid], cpid)
			}
		}
		r.ms = max(r.ms, treeCPU(pid, procs, children))
		m.roots[pid] = r
		total += r.ms
	}
	m.last = max(m.last, total)
	return m.last
}

// procInfo is one process as procTable reads it.
type procInfo struct {
	ppid  int
	start uint64
	cpuMs int64 // its own CPU time and that of the children it waited for
}

// treeCPU sums the CPU ms of pid and its live descendants.
func treeCPU(pid int, procs map[int]procInfo, children map[int][]int) int64 {
	var total int64
	stack := []int{pid}
	seen := map[int]bool{}
	for len(stack) > 0 {
		n := len(stack) - 1
		cur := stack[n]
		stack = stack[:n]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		total += procs[cur].cpuMs
		stack = append(stack, children[cur]...)
	}
	return total
}
