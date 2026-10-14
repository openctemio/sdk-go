//go:build linux

package core

import (
	"bytes"
	"os"
	"strconv"
)

// clockTicksMs is the length of one clock tick (USER_HZ, 100 on Linux) in
// milliseconds.
const clockTicksMs = 10

// procTable reads every process's parent, start time and CPU time from
// /proc; nil when /proc cannot be read.
func procTable() map[int]procInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make(map[int]procInfo, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if p, ok := readProcStat(pid); ok {
			out[pid] = p
		}
	}
	return out
}

// procStart is a process's start time (clock ticks since boot).
func procStart(pid int) (uint64, bool) {
	p, ok := readProcStat(pid)
	return p.start, ok
}

// readProcStat reads /proc/<pid>/stat: ppid (field 4), utime, stime, cutime,
// cstime (14-17) and starttime (22). The command name (field 2) may hold
// spaces and parentheses, so fields are counted after its last ')'.
func readProcStat(pid int) (procInfo, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procInfo{}, false
	}
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 {
		return procInfo{}, false
	}
	f := bytes.Fields(raw[i+1:])
	if len(f) < 20 {
		return procInfo{}, false
	}
	num := func(b []byte) int64 {
		n, _ := strconv.ParseInt(string(b), 10, 64)
		return max(n, 0)
	}
	ppid, _ := strconv.Atoi(string(f[1]))
	start, _ := strconv.ParseUint(string(f[19]), 10, 64)
	ticks := num(f[11]) + num(f[12]) + num(f[13]) + num(f[14])
	return procInfo{ppid: ppid, start: start, cpuMs: ticks * clockTicksMs}, true
}
