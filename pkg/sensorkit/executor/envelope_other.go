//go:build !linux

package executor

import (
	"os/exec"
	"sync"
)

var (
	envMu    sync.Mutex
	envTried bool
)

// EnvelopeProbeArg makes a program that calls RunLauncherIfRequested exit
// at once (cgroup probe; Linux only).
const EnvelopeProbeArg = "__openctem-envelope-probe"

// EnableEnvelopes reports the rlimit envelope: cgroups are Linux only.
func EnableEnvelopes() (mode, missing string) {
	return EnvelopeRlimit, "cgroup envelopes are available on Linux only"
}

type cgroupEnvelopes struct{}

type taskCgroup struct{}

func currentEnvelopes() (*cgroupEnvelopes, string) {
	return nil, "cgroup envelopes are available on Linux only"
}

func (*cgroupEnvelopes) create(string, Envelope) (*taskCgroup, error) { return nil, nil }
func (*taskCgroup) configure(*exec.Cmd)                               {}
func (*taskCgroup) started()                                          {}
func (*taskCgroup) oomKilled() bool                                   { return false }
func (*taskCgroup) close()                                            {}
