package toolhost

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/internal/absname"
)

// sharedPolicy is the admission policy of a shared sensor (Host.Shared):
// the sensor's policy (the built-in deny list when it has none), then the
// job's zone rule for every address the target names: a private address
// only inside the job's zone ranges, no other non-public address at all.
type sharedPolicy struct{ inner Policy }

func (p sharedPolicy) AllowsTool(name string) bool {
	return p.inner == nil || p.inner.AllowsTool(name)
}

func (p sharedPolicy) CapTimeout(d time.Duration) time.Duration {
	if p.inner == nil {
		return d
	}
	return p.inner.CapTimeout(d)
}

func (p sharedPolicy) KillSwitchEngaged() bool {
	return p.inner != nil && p.inner.KillSwitchEngaged()
}

func (p sharedPolicy) CheckTarget(ctx context.Context, target string) error {
	var err error
	if p.inner != nil {
		err = p.inner.CheckTarget(ctx, target)
	} else {
		err = (*core.LocalPolicy)(nil).CheckTarget(ctx, target)
	}
	if err != nil {
		return err
	}
	t := strings.TrimSpace(target)
	if pfx, perr := netip.ParsePrefix(t); perr == nil {
		return core.CheckSharedPrefix(ctx, pfx)
	}
	host := targetHost(t)
	if host == "" {
		return nil // a path or an image reference: no network address
	}
	if a, aerr := netip.ParseAddr(host); aerr == nil {
		return core.CheckSharedAddr(ctx, a)
	}
	addrs, lerr := lookupNetIP(ctx, "ip", absname.Of(host))
	if lerr != nil || len(addrs) == 0 {
		// The policy passed a name that does not resolve now: nothing to
		// reach, and the forwarder pins no address for it.
		return nil
	}
	for _, a := range addrs {
		if err := core.CheckSharedAddr(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

// targetHost is the host a network target names: a URL's host, a
// host:port's host, a bare host or address ("" for a path).
func targetHost(t string) string {
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, ".") {
		return ""
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(t, "[]")
}

// sharedAddrs keeps the addresses that pass the job's zone rule.
func sharedAddrs(ctx context.Context, addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if core.CheckSharedAddr(ctx, a) == nil {
			out = append(out, a)
		}
	}
	return out
}
