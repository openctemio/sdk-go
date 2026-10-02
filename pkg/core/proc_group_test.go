//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// alive reports whether pid is a live (non-zombie) process.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// state is the field after "(comm)".
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] != 'Z'
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("process %d (the scanner's child) outlived the scanner", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func childPID(t *testing.T, file string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(file)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatal("the wrapper never wrote its child's pid")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A canceled scan kills the whole process group: a wrapper script's
// background child dies with it (api RFC-030 E2E finding F4).
func TestExecuteScanner_CancelKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ExecuteScanner(ctx, &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "sleep 60 & echo $! > " + pidFile + "; wait"}})
	}()
	pid := childPID(t, pidFile)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ExecuteScanner did not return after cancel")
	}
	waitGone(t, pid)
}

// A scanner that exits leaving a background child: the child is reaped.
func TestExecuteScanner_ReapsLeftoverChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	if _, err := ExecuteScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "sleep 60 >/dev/null 2>&1 & echo $! > " + pidFile}}); err != nil {
		t.Fatal(err)
	}
	waitGone(t, childPID(t, pidFile))
}

// The same for StreamScanner and BaseScanner.Scan's path.
func TestStreamScanner_CancelKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = StreamScanner(ctx, &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "sleep 60 & echo $! > " + pidFile + "; wait"}}, func(string, bool) {})
	}()
	pid := childPID(t, pidFile)
	cancel()
	<-done
	waitGone(t, pid)
}
