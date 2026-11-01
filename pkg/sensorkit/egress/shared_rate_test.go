package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/openctemio/ctis/edgeprotect"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// An edge block one task met cools the target down for the tenant's other
// tasks on the sensor: their connections toward it are refused before the
// path is chosen (no proxy endpoint, and no direct dial, is tried), the
// target is a blocked coverage gap that names the edge, and a task of
// another tenant is not affected.
func TestEdgeBlockCoolsTheTargetDownAcrossTasks(t *testing.T) {
	shared := adapt.NewSensorRate()
	scope := Scope{Names: map[string][]netip.Addr{"app.example": {netip.MustParseAddr("192.0.2.10")}}}
	var dials atomic.Int32
	newTask := func(tenant string) *Forwarder {
		f := New(scope, Limits{Rate: 1000})
		f.TargetRate().Share(shared, tenant)
		f.Dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			c, s := net.Pipe()
			t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
			return c, nil
		}
		return f
	}
	first, second, other := newTask("t1"), newTask("t1"), newTask("t2")
	ctx := context.Background()
	if _, _, err := first.dial(ctx, "connect", "app.example", 443); err != nil {
		t.Fatal(err)
	}
	first.TargetRate().ReportResponse("app.example", 403, "",
		edgeprotect.Verdict{Vendor: edgeprotect.Cloudflare, State: edgeprotect.Blocked, Signal: "cloudflare.block-page"})

	dials.Store(0)
	_, rec, err := second.dial(ctx, "connect", "app.example", 443)
	if !errors.Is(err, adapt.ErrHostUnavailable) {
		t.Fatalf("second task's connection during the cooldown: %v, want ErrHostUnavailable", err)
	}
	if rec != nil || dials.Load() != 0 {
		t.Fatalf("the cooled-down target was dialed %d time(s)", dials.Load())
	}
	gaps, _ := second.TargetRate().Gaps()
	if len(gaps) != 1 || gaps[0].Host != "app.example" || gaps[0].Reason != adapt.GapBlocked || gaps[0].Edge != "blocked" {
		t.Fatalf("second task's gaps %+v, want app.example blocked by the edge", gaps)
	}
	if _, _, err := other.dial(ctx, "connect", "app.example", 443); err != nil || dials.Load() != 1 {
		t.Fatalf("another tenant's task: err %v, dials %d; the cooldown must not reach it", err, dials.Load())
	}
}
