package core

import (
	"regexp"
	"strings"
	"testing"
)

// The absent-policy warning says what it means in plain words, once, with
// the fix, and cites no internal document.
func TestAbsentWarningsPlain(t *testing.T) {
	w := absentWarnings(false)
	if len(w) != 1 {
		t.Fatalf("want one warning, got %d: %v", len(w), w)
	}
	if !strings.Contains(w[0], "paired before local policies were required") || !strings.Contains(w[0], DefaultLocalPolicyPath) {
		t.Fatalf("warning: %s", w[0])
	}
	if regexp.MustCompile(`RFC|research/|\(Q\d`).MatchString(w[0]) {
		t.Fatalf("internal reference in warning: %s", w[0])
	}
	if strings.Count(w[0], DefaultLocalPolicyPath) != 1 {
		t.Fatalf("advice repeated: %s", w[0])
	}
}
