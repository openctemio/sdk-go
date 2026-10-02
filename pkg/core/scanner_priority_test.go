//go:build linux

package core

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// selfNice is the test process's nice value (getpriority returns 20 - nice).
func selfNice(t *testing.T) int {
	t.Helper()
	v, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	return 20 - v
}

func selfOOMScoreAdj(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		t.Skip("no /proc/self/oom_score_adj")
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// The scanner's process group gets the lower CPU priority and the higher
// OOM score; a process it forks after starting inherits both.
func TestApplyScannerPriority_ScannerAndItsChildren(t *testing.T) {
	SetScannerPriority(&ScannerPriority{Nice: 10, IOLevel: 7, OOMScoreAdj: 500})
	t.Cleanup(func() { SetScannerPriority(nil) })
	if selfOOMScoreAdj(t) > 500 {
		t.Skip("the test runs with an oom_score_adj above 500")
	}
	wantNice := min(selfNice(t)+10, 19)

	// $$ is the scanner (the group leader); cat and cut are its children.
	script := `sleep 0.3; echo "leader $(cut -d' ' -f19 /proc/$$/stat) $(cat /proc/$$/oom_score_adj)"; ` +
		`echo "child $(cut -d' ' -f19 /proc/self/stat) $(cat /proc/self/oom_score_adj)"`
	for name, run := range map[string]func() (string, error){
		"ExecuteScanner": func() (string, error) {
			r, err := ExecuteScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", script}})
			if err != nil {
				return "", err
			}
			return string(r.Stdout), nil
		},
		"StreamScanner": func() (string, error) {
			r, err := StreamScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", script}}, func(string, bool) {})
			if err != nil {
				return "", err
			}
			return string(r.Stdout), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := run()
			if err != nil {
				t.Fatal(err)
			}
			for _, who := range []string{"leader", "child"} {
				want := who + " " + strconv.Itoa(wantNice) + " 500"
				if !strings.Contains(out, want) {
					t.Errorf("%s: want %q in output, got %q", who, want, out)
				}
			}
		})
	}
}

// Without a priority set (the SDK default outside sensorkit) scanners run
// at the sensor's own priority.
func TestApplyScannerPriority_OffByDefault(t *testing.T) {
	SetScannerPriority(nil)
	r, err := ExecuteScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "cut -d' ' -f19 /proc/$$/stat"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(r.Stdout)); got != strconv.Itoa(selfNice(t)) {
		t.Fatalf("scanner nice = %s, want the sensor's %d", got, selfNice(t))
	}
}

func TestSetScannerPriority_Clamps(t *testing.T) {
	SetScannerPriority(&ScannerPriority{Nice: 40, IOLevel: 9, OOMScoreAdj: 5000})
	t.Cleanup(func() { SetScannerPriority(nil) })
	got := CurrentScannerPriority()
	if got == nil || got.Nice != 19 || got.IOLevel != 7 || got.OOMScoreAdj != 1000 {
		t.Fatalf("got %+v", got)
	}
	SetScannerPriority(&ScannerPriority{Nice: -5, IOLevel: -1, OOMScoreAdj: -10})
	if got := CurrentScannerPriority(); got.Nice != 0 || got.IOLevel != -1 || got.OOMScoreAdj != 0 {
		t.Fatalf("got %+v", got)
	}
}
