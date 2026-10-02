//go:build linux

package sensorkit

import (
	"os"
	"strconv"
)

// writeSelfOOMScoreAdj sets the sensor's own oom_score_adj. A value below
// the current minimum needs CAP_SYS_RESOURCE (EACCES without it).
func writeSelfOOMScoreAdj(adj int) error {
	return os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(adj)), 0)
}
