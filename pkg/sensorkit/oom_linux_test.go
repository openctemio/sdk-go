//go:build linux

package sensorkit

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
)

func readSelfOOMScoreAdj(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		t.Skip("no /proc/self/oom_score_adj")
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The real write: with CAP_SYS_RESOURCE the sensor's score is
// SensorOOMScoreAdj; without it, the one warning names the capability and
// the score is unchanged.
func TestProtectFromOOM_Linux(t *testing.T) {
	orig := readSelfOOMScoreAdj(t)
	if orig <= SensorOOMScoreAdj {
		t.Skipf("the test already runs with oom_score_adj %d", orig)
	}
	t.Cleanup(func() {
		// Raising back is unprivileged.
		_ = os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(orig)), 0)
	})
	var out, errw bytes.Buffer
	protectFromOOM(&out, &errw, writeSelfOOMScoreAdj)
	got := readSelfOOMScoreAdj(t)
	if errw.Len() > 0 {
		if !strings.Contains(errw.String(), "needs CAP_SYS_RESOURCE") || got != orig || out.Len() != 0 {
			t.Fatalf("refused: warning %q, banner %q, score %d (was %d)", errw.String(), out.String(), got, orig)
		}
		t.Skip("no CAP_SYS_RESOURCE: the refusal path was checked")
	}
	if got != SensorOOMScoreAdj || !strings.Contains(out.String(), "OOM protection: on") {
		t.Fatalf("score %d, banner %q", got, out.String())
	}
}
