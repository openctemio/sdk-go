package core

import (
	"regexp"
	"testing"
)

func TestProcessInstanceID_StableAndRandomShape(t *testing.T) {
	a, b := ProcessInstanceID(), ProcessInstanceID()
	if a == "" || a != b {
		t.Fatalf("the instance id must be set and stable within a process: %q %q", a, b)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a) {
		t.Fatalf("instance id %q: want 32 lowercase hex characters", a)
	}
}
