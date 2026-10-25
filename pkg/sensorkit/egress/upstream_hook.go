package egress

import (
	"context"
	"net"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// The upstream hook: Forwarder.Dial may send a connection through an
// upstream proxy (package egress/upstream). The forwarder has already
// checked the destination against the scope, pinned its address and
// applied the per-target rate; the hook only chooses the path.

type targetHostKey struct{}

// WithTargetHost returns ctx carrying the destination host of the
// connection being dialed (the name or address the tool asked for, before
// it was resolved to the address Dial receives).
func WithTargetHost(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, targetHostKey{}, normName(host))
}

// TargetHost is the destination host the forwarder put on the context of
// a Dial call (lower case, no trailing dot), or "" when there is none.
func TargetHost(ctx context.Context) string {
	h, _ := ctx.Value(targetHostKey{}).(string)
	return h
}

// EndpointConn is a connection an upstream proxy endpoint carries: the
// forwarder records the endpoint id (Record.Endpoint).
type EndpointConn interface {
	net.Conn
	UpstreamEndpoint() string
}

// Upstream error classes (one per connection attempt through an endpoint).
const (
	ClassProxyDown         = "proxy_down"
	ClassProxyAuth         = "proxy_auth"
	ClassTargetUnreachable = "target_unreachable"
	ClassTargetRefused     = "target_refused"
)

// UpstreamError is the error of a Dial that went to an upstream proxy.
type UpstreamError struct {
	// Class is one of the Class constants.
	Class string
	// Endpoint is the id of the last endpoint tried ("" when none was
	// usable).
	Endpoint string
	// Final means the upstream has decided for the whole connection: the
	// forwarder does not try the destination's other addresses.
	Final bool
	// TargetClass is what a ClassTargetUnreachable answer says about the
	// target, as a reach class (the proxy reached no service there:
	// reach.NoRoute or reach.Timeout; it was refused: reach.PortClosed).
	// Unknown for the other classes.
	TargetClass reach.Class
	Err         error
}

func (e *UpstreamError) Error() string { return e.Class + ": " + e.Err.Error() }
func (e *UpstreamError) Unwrap() error { return e.Err }

// ProxyFault reports whether the failure was the proxy's (it is down or
// refused our credentials), not the target's.
func (e *UpstreamError) ProxyFault() bool {
	return e.Class == ClassProxyDown || e.Class == ClassProxyAuth
}

// PathFault reports whether the connection never reached the target
// because of the path: the proxy is down or refused our credentials
// (ProxyFault), or its own rules refused the destination
// (ClassTargetRefused, e.g. a CONNECT proxy that allows only port 443).
// It says nothing about the target: the target's rate and reachability do
// not move, and the target's coverage has a gap.
func (e *UpstreamError) PathFault() bool {
	return e.ProxyFault() || e.Class == ClassTargetRefused
}
