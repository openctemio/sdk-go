package toolhost

import (
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// A forwarder that does not stop (a handler blocked on a connection) never
// holds the task: the wait is bounded and the outcome says so.
func TestStuckForwarderDoesNotHoldTheTask(t *testing.T) {
	old := forwarderStopGrace
	forwarderStopGrace = 200 * time.Millisecond
	t.Cleanup(func() { forwarderStopGrace = old })
	e := &taskEgress{fw: egress.New(egress.Scope{}, egress.Limits{}), dir: t.TempDir(), cancel: func() {}}
	e.wg.Add(1) // a handler that never returns
	done := make(chan []LogLine, 1)
	go func() { done <- e.finish(&Outcome{}, nil) }()
	select {
	case lines := <-done:
		found := false
		for _, l := range lines {
			if l.Fields["egress"] == "stop_timeout" {
				found = true
			}
		}
		if !found {
			t.Fatalf("no stop-timeout line in %+v", lines)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("finish waited for a forwarder that never stops")
	}
}
