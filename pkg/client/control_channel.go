package client

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// The control channel (api RFC-035 §5.1): heartbeats go on their own HTTP
// client, with their own connection pool and a short timeout, and are not
// retried with their stale report. A result upload, a slow segment or a
// stuck connection of the data plane never holds a heartbeat back, and a
// heartbeat that fails is followed by the next one (core.HeartbeatRetryDelay)
// rather than by up to three retries of 30 seconds each.

// DefaultControlTimeout bounds one control request (a heartbeat) when
// Config.ControlTimeout is not set. The platform marks a sensor stale after
// 90 seconds without one; a heartbeat that has not been answered in 15 is
// better replaced by the next.
const DefaultControlTimeout = 15 * time.Second

// controlRetries is how often a failed control request is sent again: once,
// for a connection the platform closed while it sat idle in the pool (a
// POST is not replayed by net/http).
const controlRetries = 1

type controlKey struct{}

// withControl marks ctx's requests as control traffic: they use the
// control client.
func withControl(ctx context.Context) context.Context {
	return context.WithValue(ctx, controlKey{}, true)
}

// httpFor is the HTTP client for a request made under ctx.
func (c *Client) httpFor(ctx context.Context) *http.Client {
	if on, _ := ctx.Value(controlKey{}).(bool); on {
		return c.controlHTTP()
	}
	return c.httpClient
}

// controlHTTP is the control client: the API client's transport cloned (the
// same TLS settings and dial guard, see httpsec.NewAPIClient) with a
// connection pool of its own, the platform path's proxy (httpsec.APIProxy,
// api RFC-034) and the control timeout. It is built on first use, from the
// API client and the proxy setting as configured then. This is the one place
// the control transport is built.
func (c *Client) controlHTTP() *http.Client {
	c.ctlOnce.Do(func() {
		base := c.httpClient
		timeout := c.controlTimeout
		if timeout <= 0 {
			timeout = DefaultControlTimeout
		}
		if base.Timeout > 0 && base.Timeout < timeout {
			timeout = base.Timeout
		}
		hc := &http.Client{
			Transport:     base.Transport,
			CheckRedirect: base.CheckRedirect,
			Jar:           base.Jar,
			Timeout:       timeout,
		}
		inner, signer := base.Transport, (*sensorsig.Transport)(nil)
		// Protocol v3 sits above the v2 transport: the control client gets
		// its own pool underneath the same v3 binding.
		v3rt, _ := inner.(*v3RoundTripper)
		if v3rt != nil {
			inner = v3rt.next
		}
		if st, ok := inner.(*sensorsig.Transport); ok {
			inner, signer = st.Base, st
		}
		if tr, ok := inner.(*http.Transport); ok {
			ctl := tr.Clone()
			// The platform path's proxy (api RFC-034: SENSOR_CONTROL_PROXY,
			// else HTTP(S)_PROXY), as the API client's transport has it.
			ctl.Proxy = httpsec.APIProxy().Func()
			hc.Transport = ctl
			if signer != nil {
				// A key-bound client signs its heartbeats too.
				hc.Transport = &sensorsig.Transport{Signer: signer.Signer, Base: ctl, MaxBody: signer.MaxBody}
			}
		}
		if v3rt != nil && hc.Transport != base.Transport {
			hc.Transport = v3rt.withNext(hc.Transport)
		}
		c.ctl = hc
	})
	return c.ctl
}
