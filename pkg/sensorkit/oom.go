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
// line to errw. A refusal never stops the sensor; it runs unprotected. It
// returns the outcome's check code (protected, unsupported, no_permission,
// failed) and a one-line summary for the config report.
func protectFromOOM(out, errw io.Writer, write func(int) error) (code, summary string) {
	err := write(SensorOOMScoreAdj)
	switch {
	case err == nil:
		_, _ = fmt.Fprintf(out, "  OOM protection: on (oom_score_adj %d; scanners are not protected)\n", SensorOOMScoreAdj)
		return "protected", ""
	case errors.Is(err, errOOMUnsupported):
		_, _ = fmt.Fprintf(errw, "Warning: %s=true is ignored: %v; the sensor runs unprotected\n", EnvProtectFromOOM, err)
		return "unsupported", "OOM protection is only available on Linux"
	case errors.Is(err, fs.ErrPermission):
		_, _ = fmt.Fprintf(errw, "Warning: %s=true: lowering oom_score_adj to %d needs CAP_SYS_RESOURCE "+
			"(docker run --cap-add SYS_RESOURCE, or run as root under systemd); the sensor runs unprotected\n",
			EnvProtectFromOOM, SensorOOMScoreAdj)
		return "no_permission", "lowering oom_score_adj needs CAP_SYS_RESOURCE"
	default:
		_, _ = fmt.Fprintf(errw, "Warning: %s=true: cannot set oom_score_adj to %d: %v; the sensor runs unprotected\n",
			EnvProtectFromOOM, SensorOOMScoreAdj, err)
		return "failed", fmt.Sprintf("cannot set oom_score_adj: %v", err)
	}
}
