package v2

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The held segments travel as segments.held, next to received and expected.
func TestStatusHeldSegmentsWireShape(t *testing.T) {
	in := Status{ReportID: "r1", State: StateReceiving, Segments: SegmentCounts{Received: 2}, HeldSegments: []int{0, 2}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"segments":{"received":2,"held":[0,2]}`) {
		t.Fatalf("wire: %s", b)
	}
	var out Status
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ReportID != "r1" || out.Segments.Received != 2 || !reflect.DeepEqual(out.HeldSegments, []int{0, 2}) {
		t.Fatalf("round trip: %+v", out)
	}
}
