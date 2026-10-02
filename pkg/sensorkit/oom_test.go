package sensorkit

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

func TestResolveProtectFromOOM(t *testing.T) {
	for _, c := range []struct {
		explicit bool
		env      string
		want     bool
		usage    bool
	}{
		{false, "", false, false},
		{false, "true", true, false},
		{false, " TRUE ", true, false},
		{false, "false", false, false},
		{true, "false", true, false},
		{false, "maybe", false, true},
	} {
		t.Setenv(EnvProtectFromOOM, c.env)
		got, err := ResolveProtectFromOOM(c.explicit)
		if c.usage {
			if ExitCode(err) != ExitUsage {
				t.Errorf("%v/%q: want a usage error, got %v", c.explicit, c.env, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%v/%q: got (%v, %v), want %v", c.explicit, c.env, got, err, c.want)
		}
	}
}

// The protection prints its outcome; a refusal is one warning line and
// never an error.
func TestProtectFromOOM_Outcome(t *testing.T) {
	eacces := &fs.PathError{Op: "open", Path: "/proc/self/oom_score_adj", Err: syscall.EACCES}
	for _, c := range []struct {
		name    string
		err     error
		banner  string
		warning string
	}{
		{"applied", nil, "OOM protection: on (oom_score_adj -500", ""},
		{"no CAP_SYS_RESOURCE", eacces, "", "needs CAP_SYS_RESOURCE (docker run --cap-add SYS_RESOURCE"},
		{"EPERM", syscall.EPERM, "", "needs CAP_SYS_RESOURCE"},
		{"not Linux", errOOMUnsupported, "", "is ignored: only Linux"},
		{"other", errors.New("read-only file system"), "", "cannot set oom_score_adj to -500: read-only file system"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out, errw bytes.Buffer
			var wrote int
			protectFromOOM(&out, &errw, func(adj int) error { wrote = adj; return c.err })
			if wrote != SensorOOMScoreAdj {
				t.Errorf("wrote %d, want %d", wrote, SensorOOMScoreAdj)
			}
			if c.banner != "" {
				if !strings.Contains(out.String(), c.banner) || errw.Len() != 0 {
					t.Errorf("out = %q, errw = %q; want the banner %q", out.String(), errw.String(), c.banner)
				}
				return
			}
			if out.Len() != 0 || strings.Count(errw.String(), "\n") != 1 || !strings.Contains(errw.String(), c.warning) {
				t.Errorf("out = %q, errw = %q; want one warning line with %q", out.String(), errw.String(), c.warning)
			}
		})
	}
}
