package executor

import "testing"

func TestStatusUnconfined(t *testing.T) {
	for _, tc := range []struct {
		st      Status
		want    string
		refuses bool
	}{
		{Status{Mode: ModeAuto, Sandboxed: true}, "", false},
		{Status{Mode: ModeRequired, Sandboxed: true}, "", false},
		{Status{Mode: ModeAuto}, UnconfinedRefused, true},
		{Status{Mode: ModeOff}, UnconfinedAcknowledged, false},
		{Status{}, "", false},
	} {
		if got := tc.st.Unconfined(); got != tc.want || tc.st.RefusesActiveTools() != tc.refuses {
			t.Errorf("%+v: %q %t, want %q %t", tc.st, got, tc.st.RefusesActiveTools(), tc.want, tc.refuses)
		}
	}
	// The default backend (nothing installed: tests, one-shot runs) is off,
	// so it refuses nothing.
	if Current().Status().RefusesActiveTools() {
		t.Fatal("the default backend refuses active tools")
	}
}
