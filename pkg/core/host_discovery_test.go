package core

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/openctemio/contract/capability"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// probeReport builds a port probe's CTIS 2.0 report: per host, an asset and
// one service asset per open port linked by an exposes relationship.
type probeHost struct {
	typ   ctis.AssetType
	value string
	ports []int
}

func probeReport(hosts ...probeHost) *ctis.Report {
	r := &ctis.Report{}
	for i, h := range hosts {
		id := "h" + strconv.Itoa(i)
		r.Assets = append(r.Assets, ctis.Asset{ID: id, Type: h.typ, Value: h.value})
		for _, p := range h.ports {
			sid := id + "-" + strconv.Itoa(p)
			r.Assets = append(r.Assets, ctis.Asset{ID: sid, Type: ctis.AssetTypeService,
				Value:     h.value + ":" + strconv.Itoa(p) + "/tcp",
				Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: p, Transport: ctis.TransportTCP, State: ctis.PortOpen}}})
			r.Relationships = append(r.Relationships, ctis.Relationship{Type: ctis.RelExposes, FromRef: id, ToRef: sid})
		}
	}
	return r
}

func reportMap(t *testing.T, r *ctis.Report) map[string]any {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A host discovery report keeps each answering address of the job, with
// the lowest probe port that answered, and nothing else (no service assets,
// no relationships).
func TestLiveHostsReport(t *testing.T) {
	r := probeReport(
		probeHost{ctis.AssetTypeIPAddress, "198.51.100.7", []int{443, 22}},
		probeHost{ctis.AssetTypeIPAddress, "198.51.100.9", []int{80}},
		probeHost{ctis.AssetTypeIPAddress, "203.0.113.5", []int{80}}, // not a target
		probeHost{ctis.AssetTypeHost, "app.example.com", []int{80}},
		probeHost{ctis.AssetTypeIPAddress, "198.51.100.8", nil}, // no answer
	)
	LiveHostsReport(r, []string{"198.51.100.0/29", "198.51.100.9", "::ffff:198.51.100.0/120"})
	if len(r.Assets) != 2 || r.Assets[0].Value != "198.51.100.7" || r.Assets[0].Properties[PropLiveBy] != "tcp:22" ||
		r.Assets[1].Value != "198.51.100.9" || r.Assets[1].Properties[PropLiveBy] != "tcp:80" {
		t.Fatalf("assets = %+v", r.Assets)
	}
	if len(r.Relationships) != 0 {
		t.Fatalf("relationships kept: %+v", r.Relationships)
	}
	// The report passes the capability's output contract.
	c, ok := capability.Lookup(CapabilityHostDiscovery + "@1")
	if !ok {
		t.Fatal("discover.hosts@1 is not in the taxonomy")
	}
	if v, err := c.Check(reportMap(t, r), capability.CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("contract: %v %v", v, err)
	}
	LiveHostsReport(nil, nil)
	all := probeReport(probeHost{ctis.AssetTypeIPAddress, "203.0.113.5", []int{80}})
	if LiveHostsReport(all, nil); len(all.Assets) != 1 {
		t.Fatal("without targets every answering address is kept")
	}
	// A closed port is not an answer.
	closed := probeReport(probeHost{ctis.AssetTypeIPAddress, "203.0.113.6", []int{80}})
	closed.Assets[1].Technical.Service.State = ctis.PortClosed
	if LiveHostsReport(closed, nil); len(closed.Assets) != 0 {
		t.Fatal("an address with only a closed port is live")
	}
}
