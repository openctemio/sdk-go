package core

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fakeBinary(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary")
	}
	bin := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil { //nolint:gosec // test fake binary must be executable
		t.Fatal(err)
	}
	return bin
}

func TestVersionOutput(t *testing.T) {
	tests := []struct {
		name, script, want string
		installed          bool
	}{
		{"stdout", `printf '1.179.0\n'`, "1.179.0\n", true},
		{"stdout wins over stderr", `printf 'Version: 0.75.0\n'; printf 'warn\n' >&2`, "Version: 0.75.0\n", true},
		{"stderr when stdout empty, colors stripped", `printf '[\033[34mINF\033[0m] Current Version: v2.6.6\n' >&2`, "[INF] Current Version: v2.6.6\n", true},
		{"non-zero exit is not installed", `echo boom >&2; exit 3`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installed, out, err := VersionOutput(context.Background(), fakeBinary(t, tt.script), "-version")
			if err != nil {
				t.Fatal(err)
			}
			if installed != tt.installed || out != tt.want {
				t.Fatalf("VersionOutput = %v, %q; want %v, %q", installed, out, tt.installed, tt.want)
			}
		})
	}
}

func TestVersionOutputMissingBinary(t *testing.T) {
	installed, out, err := VersionOutput(context.Background(), filepath.Join(t.TempDir(), "absent"))
	if installed || out != "" || err != nil {
		t.Fatalf("VersionOutput(missing) = %v, %q, %v", installed, out, err)
	}
}

// CheckBinaryInstalled keeps its contract (one line) and now also sees a
// version that is printed only to stderr.
func TestCheckBinaryInstalledFirstLine(t *testing.T) {
	bin := fakeBinary(t, `printf '\n[\033[34mINF\033[0m] Nuclei Engine Version: v3.11.1\n[INF] PDCP Directory: /x\n' >&2`)
	installed, line, err := CheckBinaryInstalled(context.Background(), bin, "-version")
	if err != nil || !installed {
		t.Fatalf("CheckBinaryInstalled = %v, %v", installed, err)
	}
	if line != "[INF] Nuclei Engine Version: v3.11.1" {
		t.Fatalf("line = %q", line)
	}
}

func TestVersionAfterLabel(t *testing.T) {
	out := "[INF] Nuclei Config Directory: /x\n[INF] Nuclei Engine Version: v3.11.1 (latest)\n"
	if got := VersionAfterLabel(out, "Engine Version:"); got != "v3.11.1" {
		t.Fatalf("got %q", got)
	}
	if got := VersionAfterLabel(out, "Current Version:"); got != "" {
		t.Fatalf("absent label: got %q", got)
	}
	if got := VersionAfterLabel("Version:\n", "Version:"); got != "" {
		t.Fatalf("empty value: got %q", got)
	}
}

func TestStripANSI(t *testing.T) {
	if got := StripANSI("[\x1b[34mINF\x1b[0m] x \x1b[1;31mred\x1b[0m"); got != "[INF] x red" {
		t.Fatalf("got %q", got)
	}
}
