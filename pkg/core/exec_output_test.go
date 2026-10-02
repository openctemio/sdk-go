package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A line longer than bufio.Scanner's 64 KiB token limit must not stop
// StreamScanner from reading: the scanner would block on a full pipe until
// its timeout and the rest of its output would be lost.
func TestStreamScanner_LongLine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// 200 KiB line, then a short line.
	res, err := StreamScanner(ctx, &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "head -c 204800 /dev/zero | tr '\\0' a; echo; echo done"}}, func(string, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("StreamScanner stalled until the deadline")
	}
	if got, want := len(res.Stdout), 204800+1+5; got != want {
		t.Fatalf("stdout length = %d, want %d", got, want)
	}
}

// A scanner that writes more than the bound is stopped (not read to the end,
// not silently truncated into a smaller "clean" result) and the run fails.
func TestExecuteScanner_OutputBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	// `yes` never stops on its own: only the bound can end it.
	res, err := ExecuteScanner(ctx, &ExecConfig{Binary: "yes", Args: []string{"finding"}, MaxOutputBytes: 1 << 20})
	if !errors.Is(err, ErrScannerOutputTooLarge) {
		t.Fatalf("err = %v, want ErrScannerOutputTooLarge", err)
	}
	if time.Since(start) > 10*time.Second || ctx.Err() != nil {
		t.Fatal("the scanner was not stopped at the bound")
	}
	if res == nil || int64(len(res.Stdout)) != 1<<20 {
		t.Fatalf("stdout kept = %d bytes, want %d", len(res.Stdout), 1<<20)
	}
}

func TestStreamScanner_OutputBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := StreamScanner(ctx, &ExecConfig{Binary: "yes", MaxOutputBytes: 1 << 16}, func(string, bool) {})
	if !errors.Is(err, ErrScannerOutputTooLarge) {
		t.Fatalf("err = %v, want ErrScannerOutputTooLarge", err)
	}
}

func TestBaseScanner_OutputBound(t *testing.T) {
	s := NewBaseScanner(&BaseScannerConfig{Name: "yes", Binary: "yes", Timeout: 20 * time.Second, MaxOutputBytes: 1 << 16, WorkDir: t.TempDir()})
	start := time.Now()
	_, err := s.Scan(context.Background(), "", nil)
	if !errors.Is(err, ErrScannerOutputTooLarge) {
		t.Fatalf("err = %v, want ErrScannerOutputTooLarge", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the scanner was not stopped at the bound")
	}
}

// Output under the bound is kept whole, lines and all, with the last line's
// missing newline handled.
func TestStreamScanner_Lines(t *testing.T) {
	var got []string
	res, err := StreamScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "printf 'a\\r\\nb\\nc'"}}, func(line string, isErr bool) {
		if !isErr {
			got = append(got, line)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "a|b|c" {
		t.Fatalf("lines = %q", got)
	}
	if string(res.Stdout) != "a\r\nb\nc" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

// Stderr past its bound is cut and noted, and the run is not failed for it.
func TestExecuteScanner_StderrBound(t *testing.T) {
	res, err := ExecuteScanner(context.Background(), &ExecConfig{Binary: "/bin/sh", Args: []string{"-c", "head -c 6000000 /dev/zero >&2; echo ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "ok\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if len(res.Stderr) != maxScannerStderr+len(stderrTruncatedNote) || !strings.HasSuffix(string(res.Stderr), stderrTruncatedNote) {
		t.Fatalf("stderr = %d bytes, want %d with the truncation note", len(res.Stderr), maxScannerStderr+len(stderrTruncatedNote))
	}
}
