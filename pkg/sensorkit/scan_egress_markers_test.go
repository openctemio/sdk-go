package sensorkit

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func egressKit(mode string, shared bool) *Kit {
	k := &Kit{handlers: map[string]core.CommandExecutor{}}
	k.s.shared = shared
	k.s.scanEgress = ScanEgress{Mode: mode}
	k.bcfg = core.BaseSensorConfig{}
	k.sensor = core.NewBaseSensor(&k.bcfg, nil)
	return k
}

func reported(k *Kit) []string {
	return k.Tools().CapabilityReport(context.Background()).Capabilities
}

// SENSOR_SCAN_EGRESS=direct-only is a host-set Direct path: the kit says so
// (the sensor reports egress.host-direct@1), never for a shared sensor and
// never for one that takes pools.
func TestEgressHostDirect(t *testing.T) {
	for _, c := range []struct {
		mode   string
		shared bool
		want   bool
	}{
		{ScanEgressDirectOnly, false, true},
		{ScanEgressPlatform, false, false},
		{ScanEgressDirectOnly, true, false},
	} {
		if got := egressKit(c.mode, c.shared).EgressHostDirect(); got != c.want {
			t.Errorf("%s shared=%v: %v", c.mode, c.shared, got)
		}
	}
}

// A proxy test is served only by a sensor that accepts platform pools.
func TestServeProxyTestOnlyWhereAPoolIsAccepted(t *testing.T) {
	ok := egressKit(ScanEgressPlatform, false)
	if !ok.ServeProxyTest() || !slices.Contains(reported(ok), core.CapabilityProxyTest) || ok.handlers[core.CommandTypeProxyTest] == nil {
		t.Fatalf("a pool-accepting sensor must serve the test: %v", reported(ok))
	}
	for name, k := range map[string]*Kit{
		"direct-only": egressKit(ScanEgressDirectOnly, false),
		"shared":      egressKit(ScanEgressPlatform, true),
	} {
		if k.ServeProxyTest() || slices.Contains(reported(k), core.CapabilityProxyTest) || k.handlers[core.CommandTypeProxyTest] != nil {
			t.Errorf("%s must not serve proxy tests", name)
		}
	}
}

func TestPrepareEgressBeforeRunFails(t *testing.T) {
	if _, err := egressKit(ScanEgressPlatform, false).PrepareEgress(context.Background(), "c1", nil); err == nil {
		t.Fatal("no executor yet")
	}
}
