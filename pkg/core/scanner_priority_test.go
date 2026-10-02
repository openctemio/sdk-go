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

func TestScannerOOMScoreAdj(t *testing.T) {
	low := &ScannerPriority{OOMScoreAdj: 500}
	for _, c := range []struct {
		name   string
		p      *ScannerPriority
		sensor int
		want   int
		ok     bool
	}{
		{"priority, unprotected sensor", low, 0, 500, true},
		{"priority, protected sensor", low, -500, 500, true},
		{"no priority, unprotected sensor", nil, 0, 0, false},
		{"no priority, sensor above 0", nil, 300, 0, false},
		{"no priority, protected sensor", nil, -500, 0, true},
		{"priority without an OOM score, protected sensor", &ScannerPriority{Nice: 10}, -1000, 0, true},
	} {
		if got, ok := scannerOOMScoreAdj(c.p, c.sensor); got != c.want || ok != c.ok {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

// A sensor protected from the OOM killer (a negative oom_score_adj) never
// hands its protection to a scanner, with or without a scanner priority. It
// needs CAP_SYS_RESOURCE to lower the test process's own score.
func TestApplyScannerPriority_ScannerDropsSensorProtection(t *testing.T) {
	orig := selfOOMScoreAdj(t)
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-100"), 0); err != nil {
		t.Skipf("cannot lower the test's own oom_score_adj (needs CAP_SYS_RESOURCE): %v", err)
	}
	t.Cleanup(func() {
		// Raising back is unprivileged.
		_ = os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(orig)), 0)
	})

	// $$ is the scanner; cat is a child it forks after the write.
	script := `sleep 0.3; echo "leader $(cat /proc/$$/oom_score_adj)"; echo "child $(cat /proc/self/oom_score_adj)"`
	for name, c := range map[string]struct {
		p    *ScannerPriority
		want string
	}{
		"normal priority": {nil, "0"},
		"low priority":    {&ScannerPriority{Nice: 10, IOLevel: 7, OOMScoreAdj: 500}, "500"},
	} {
		t.Run(name, func(t *testing.T) {
			SetScannerPriority(c.p)
			t.Cleanup(func() { SetScannerPriority(nil) })
			r, err := ExecuteScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", script}})
			if err != nil {
				t.Fatal(err)
			}
			out := string(r.Stdout)
			for _, who := range []string{"leader", "child"} {
				if want := who + " " + c.want; !strings.Contains(out, want) {
					t.Errorf("want %q in output, got %q", want, out)
				}
			}
		})
	}
}
