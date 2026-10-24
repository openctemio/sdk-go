package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"tool", "version"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, errb.String())
		}
		got := out.String()
		if !strings.HasPrefix(got, "openctem ") || strings.TrimSpace(got) == "openctem" {
			t.Fatalf("%v: output %q", args, got)
		}
	}
}

func TestUsageListsVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "version") {
		t.Fatalf("usage %q lacks version", errb.String())
	}
}
