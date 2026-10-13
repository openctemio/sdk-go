package core

import (
	"testing"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

func portsAsset(typ ctis.AssetType, value string, ports ...int) ctis.Asset {
	a := ctis.Asset{Type: typ, Value: value}
	if len(ports) > 0 {
		pi := make([]ctis.PortInfo, len(ports))
		for i, p := range ports {
			pi[i] = ctis.PortInfo{Port: p}
		}
		a.Technical = &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: pi}}
	}
	return a
}

// A host discovery report keeps each answering address of the job, with
// the probe that answered, and nothing else.
func TestLiveHostsReport(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{
		portsAsset(ctis.AssetTypeIPAddress, "198.51.100.7", 443, 22),
		portsAsset(ctis.AssetTypeIPAddress, "198.51.100.9", 80),
		portsAsset(ctis.AssetTypeIPAddress, "203.0.113.5", 80), // not a target
		portsAsset(ctis.AssetTypeHost, "app.example.com", 80),
		portsAsset(ctis.AssetTypeIPAddress, "198.51.100.8"), // no answer
	}}
	LiveHostsReport(r, []string{"198.51.100.0/29", "198.51.100.9", "::ffff:198.51.100.0/120"})
	if len(r.Assets) != 2 || r.Assets[0].Value != "198.51.100.7" || r.Assets[0].Properties[PropLiveBy] != "tcp:443" ||
		r.Assets[1].Value != "198.51.100.9" || r.Assets[1].Properties[PropLiveBy] != "tcp:80" {
		t.Fatalf("assets = %+v", r.Assets)
	}
	// The report passes the capability's output contract.
	c, ok := capability.Lookup(CapabilityHostDiscovery + "@1")
	if !ok {
		t.Fatal("discover.hosts@1 is not in the taxonomy")
	}
	if v, err := c.Check(r, capability.CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("contract: %v %v", v, err)
	}
	LiveHostsReport(nil, nil)
	all := &ctis.Report{Assets: []ctis.Asset{portsAsset(ctis.AssetTypeIPAddress, "203.0.113.5", 80)}}
	if LiveHostsReport(all, nil); len(all.Assets) != 1 {
		t.Fatal("without targets every answering address is kept")
	}
}
