package sensorkit

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

// A host resolver with search domains is noted, as information only.
func TestDNSSearchCheckIsInformational(t *testing.T) {
	k := &Kit{doc: newDoctor(settingsreg.New(), nil)}
	k.checkDNSSearch()
	c, ok := findCheck(*k.ConfigReport(), CheckDNSSearch)
	if len(egress.SearchDomains("")) == 0 {
		if ok {
			t.Fatalf("no search domains, but a check: %+v", c)
		}
		t.Skip("this host's resolver has no search domains")
	}
	if !ok || c.Status != core.CheckPass || c.Severity != core.SeverityInfo || c.Code != "search_domains" {
		t.Fatalf("check %+v (present %v), want pass/info/search_domains", c, ok)
	}
}
