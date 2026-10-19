package core

import "testing"

// JobGuard is part of the Stable API and has always been comparable; sensors
// may compare guards or use them as map keys.
func TestJobGuardStaysComparable(t *testing.T) {
	var a, b JobGuard
	if a != b {
		t.Fatal("zero guards differ")
	}
}
