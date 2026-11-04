package toolhost

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

func refusal(host string, port int, proto, reason string) egress.Record {
	return egress.Record{Host: host, Port: port, Protocol: proto, Verdict: egress.Refused, Reason: reason}
}

func TestEgressLogFoldsRepeatedRefusals(t *testing.T) {
	root := refusal(".", 0, "dns", "egress: destination refused: . is not a target")
	other := refusal("a.example", 443, "connect", "egress: port 443 not allowed")

	t.Run("root query four times", func(t *testing.T) {
		got := egressLog([]egress.Record{root, root, root, root})
		if len(got) != 1 {
			t.Fatalf("lines: %+v", got)
		}
		want := "egress refused . (dns): egress: destination refused: . is not a target (x4)"
		if got[0].Msg != want || got[0].Fields["count"] != 4 || got[0].Fields["host"] != "." {
			t.Fatalf("line: %+v", got[0])
		}
	})
	t.Run("single refusal has no count", func(t *testing.T) {
		got := egressLog([]egress.Record{other})
		if len(got) != 1 || strings.Contains(got[0].Msg, "(x") {
			t.Fatalf("line: %+v", got)
		}
		if _, ok := got[0].Fields["count"]; ok {
			t.Fatalf("count on a single refusal: %+v", got[0].Fields)
		}
		if got[0].Msg != "egress refused a.example:443 (connect): egress: port 443 not allowed" {
			t.Fatalf("msg %q", got[0].Msg)
		}
	})
	t.Run("different port, protocol or reason stays apart; allowed ignored", func(t *testing.T) {
		recs := []egress.Record{root, other, root,
			refusal("a.example", 80, "connect", other.Reason),
			refusal("a.example", 443, "http", other.Reason),
			refusal("a.example", 443, "connect", "other reason"),
			{Host: "ok.example", Protocol: "connect", Verdict: egress.Allowed}}
		got := egressLog(recs)
		if len(got) != 5 {
			t.Fatalf("lines: %+v", got)
		}
		if got[0].Fields["count"] != 2 {
			t.Fatalf("first: %+v", got[0])
		}
	})
	t.Run("cap counts distinct destinations", func(t *testing.T) {
		var recs []egress.Record
		for i := 0; i < maxEgressLogLines+5; i++ {
			h := fmt.Sprintf("h%d.example", i)
			recs = append(recs, refusal(h, 0, "dns", "r"), refusal(h, 0, "dns", "r"))
		}
		got := egressLog(recs)
		if len(got) != maxEgressLogLines+1 {
			t.Fatalf("lines %d", len(got))
		}
		if got[0].Fields["count"] != 2 {
			t.Fatalf("first: %+v", got[0])
		}
		if got[len(got)-1].Msg != "egress refused 5 more destinations" {
			t.Fatalf("tail %q", got[len(got)-1].Msg)
		}
	})
	t.Run("many repeats of few destinations have no tail", func(t *testing.T) {
		var recs []egress.Record
		for i := 0; i < 100; i++ {
			recs = append(recs, root)
		}
		if got := egressLog(recs); len(got) != 1 {
			t.Fatalf("lines %d", len(got))
		}
	})
	t.Run("none", func(t *testing.T) {
		if got := egressLog(nil); len(got) != 0 {
			t.Fatalf("%+v", got)
		}
	})
}
