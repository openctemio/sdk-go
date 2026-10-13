package conformance

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// The SDK's own probe passes the reach suite.
func TestReachSuite_SDKProbe(t *testing.T) {
	RunReachSuite(t, SDKReachProber)
}

// The suite catches a probe that dials what the guard did not admit, and
// one that reports an unroutable target as reached.
func TestReachSuite_CatchesBrokenProbes(t *testing.T) {
	// Dials every literal target directly, guard or not.
	ignoresGuard := func(ctx context.Context, _ reach.Guard, dial reach.DialFunc, targets []string) (reach.ProbeResult, error) {
		for _, tg := range targets {
			if a, err := netip.ParseAddr(strings.Trim(tg, "[]")); err == nil {
				if c, err := dial(ctx, "tcp", netip.AddrPortFrom(a, 443).String()); err == nil {
					_ = c.Close()
				}
			}
		}
		return reach.ProbeResult{}, nil
	}
	// Probes correctly but reports everything as reached.
	liesReached := func(ctx context.Context, g reach.Guard, dial reach.DialFunc, targets []string) (reach.ProbeResult, error) {
		res, err := SDKReachProber(ctx, g, dial, targets)
		res.Classes = map[reach.Class]int{reach.Reached: res.Targets}
		res.Reached, res.Unreached, res.UnreachedList = res.Targets, 0, nil
		return res, err
	}
	for name, tc := range map[string]struct {
		probe ReachProber
		want  string
	}{
		"ignores the guard": {ignoresGuard, "OnlyAdmitted: SECURITY: dialed 198.51.100.1"},
		"reports reached":   {liesReached, "Unroutable: an unroutable target must be reported unreached"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &suiteRecorder{}
			RunReachSuite(r, tc.probe)
			if !strings.Contains(strings.Join(r.errs, "\n"), tc.want) {
				t.Fatalf("want a failure %q, got:\n%s", tc.want, strings.Join(r.errs, "\n"))
			}
		})
	}
}
