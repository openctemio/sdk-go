package sensorkit

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// errOOMUnsupported is the protection on a system without oom_score_adj.
var errOOMUnsupported = errors.New("only Linux has an OOM score")

// protectFromOOM writes SensorOOMScoreAdj to the sensor's own oom_score_adj
// with write and prints the outcome: a banner line to out, or one warning
// line to errw. A refusal never stops the sensor; it runs unprotected.
func protectFromOOM(out, errw io.Writer, write func(int) error) {
	err := write(SensorOOMScoreAdj)
	switch {
	case err == nil:
		_, _ = fmt.Fprintf(out, "  OOM protection: on (oom_score_adj %d; scanners are not protected)\n", SensorOOMScoreAdj)
	case errors.Is(err, errOOMUnsupported):
		_, _ = fmt.Fprintf(errw, "Warning: %s=true is ignored: %v; the sensor runs unprotected\n", EnvProtectFromOOM, err)
	case errors.Is(err, fs.ErrPermission):
		_, _ = fmt.Fprintf(errw, "Warning: %s=true: lowering oom_score_adj to %d needs CAP_SYS_RESOURCE "+
			"(docker run --cap-add SYS_RESOURCE, or run as root under systemd); the sensor runs unprotected\n",
			EnvProtectFromOOM, SensorOOMScoreAdj)
	default:
		_, _ = fmt.Fprintf(errw, "Warning: %s=true: cannot set oom_score_adj to %d: %v; the sensor runs unprotected\n",
			EnvProtectFromOOM, SensorOOMScoreAdj, err)
	}
}
