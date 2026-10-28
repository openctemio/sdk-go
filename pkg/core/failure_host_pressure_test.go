package core

import "testing"

type startErr struct{ attempts int }

func (e startErr) Error() string { return "start failed" }
func (e startErr) FailureClass() (string, string) {
	return string(FailureHostPressure), ReasonNoHandshake
}
func (e startErr) FailureStart() (int, string) { return e.attempts, "elevated" }

func TestHostPressureFailure(t *testing.T) {
	f := ClassifyFailure(FailureInput{Err: startErr{attempts: 2}, Tool: "subfinder"})
	if f.Class != FailureHostPressure || f.Evidence.Reason != ReasonNoHandshake || f.Evidence.Attempts != 2 || f.Evidence.Pressure != "elevated" {
		t.Fatalf("failure %+v", f)
	}
	if f.ErrorCode() != "TOOL_EXIT" {
		t.Fatalf("error code %q: an older platform must read it as before", f.ErrorCode())
	}
	b := (&Failure{Class: FailureHostPressure, Evidence: FailureEvidence{Attempts: -3, Pressure: "<script>"}}).Bounded()
	if b.Class != FailureHostPressure || b.Evidence.Attempts != 0 || b.Evidence.Pressure != "" {
		t.Fatalf("bounded %+v", b)
	}
}
