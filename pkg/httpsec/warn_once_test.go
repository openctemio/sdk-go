package httpsec

import "testing"

func TestFirstWarning(t *testing.T) {
	const u = "http://api.warn-once.test:8080"
	if !FirstWarning(u) {
		t.Fatal("first call must allow the warning")
	}
	for range 3 {
		if FirstWarning(u) {
			t.Fatal("the warning must be printed once per process per base URL")
		}
	}
	if !FirstWarning(u + "/other") {
		t.Fatal("another base URL gets its own warning")
	}
}
