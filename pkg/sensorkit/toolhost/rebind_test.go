package toolhost

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// builtinPolicy is a Policy without AdmittedAddrs (a sensor's own policy
// wrapper): its target check is the built-in deny list.
type builtinPolicy struct{}

func (builtinPolicy) AllowsTool(string) bool { return true }
func (builtinPolicy) CheckTarget(ctx context.Context, target string) error {
	return (*core.LocalPolicy)(nil).CheckTarget(ctx, target)
}
func (builtinPolicy) CapTimeout(d time.Duration) time.Duration { return d }
func (builtinPolicy) KillSwitchEngaged() bool                  { return false }

// noLoopbackAllowance pins the production loopback posture for a test
// (CI sets OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK=1 for its local fakes).
func noLoopbackAllowance(t *testing.T) {
	t.Helper()
	prev := httpsec.AllowLoopback
	httpsec.AllowLoopback = false
	t.Cleanup(func() { httpsec.AllowLoopback = prev })
}

func stubLookup(t *testing.T, fn func(context.Context, string, string) ([]netip.Addr, error)) {
	t.Helper()
	prev := lookupNetIP
	lookupNetIP = fn
	t.Cleanup(func() { lookupNetIP = prev })
}

// A name that passed admission public and resolves to a private or
// metadata address when the task's forwarder scope is built is not pinned
// there: the forwarder has no address to dial for it (DNS rebinding).
func TestTaskScopeRebindToInternalIsNotPinned(t *testing.T) {
	noLoopbackAllowance(t)
	t.Setenv(core.EnvSensorAllowPrivateTargets, "")
	for _, later := range []string{"10.0.0.5", "169.254.169.254", "127.0.0.1", "100.64.1.1"} {
		var calls atomic.Int32
		stubLookup(t, func(context.Context, string, string) ([]netip.Addr, error) {
			calls.Add(1)
			return []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr(later)}, nil
		})
		h := &Host{Policy: builtinPolicy{}}
		s := h.taskScope(context.Background(), tool.Manifest{Permissions: tool.Permissions{Network: tool.NetTargets}},
			tool.Task{Targets: []tool.Target{{Ref: "t0", Value: "https://rebind.example.com/"}}})
		got := s.Names["rebind.example.com"]
		if calls.Load() == 0 {
			t.Fatal("the scope did not look the name up")
		}
		if slices.Contains(got, netip.MustParseAddr(later)) {
			t.Errorf("re-bound to %s: pinned %v", later, got)
		}
		if !slices.Contains(got, netip.MustParseAddr("203.0.113.7")) {
			t.Errorf("the public address was dropped: %v", got)
		}
	}
}
