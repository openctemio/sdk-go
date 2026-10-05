package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var out, errw bytes.Buffer
	if code := run(nil, &out, &errw); code != 2 || !strings.Contains(errw.String(), "usage") {
		t.Fatalf("no arguments: %d %q", code, errw.String())
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	out.Reset()
	example := filepath.Join("..", "..", "examples", "python-adapter", "tool.yaml")
	if code := run([]string{"tool", example}, &out, &errw); code != 0 || !strings.Contains(out.String(), "PASS") {
		t.Fatalf("example: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"tool", "missing/tool.yaml"}, &out, &errw); code != 1 || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("missing manifest: %d\n%s", code, out.String())
	}
}
