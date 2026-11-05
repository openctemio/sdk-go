package egress

// The job's web scope (pkg/webscope) at the forwarder. A task with a web
// scope has every connection guarded, whatever its port: TLS is
// terminated with the forwarder's own authority (as for a path limit),
// every HTTP/1.x request is checked with webscope.Scope.Allows before it
// goes upstream, and anything that is not HTTP/1.x is refused. A redirect
// is a new request and is checked again, so a tool that follows one to a
// denied path is refused there. The check sees the request as the server
// would (percent-decoding, dot segments, case of a deny path), so it holds
// for a tool that keeps to no scope of its own: on a confined sandbox the
// forwarder is the tool's only way out.
//
// A web scope with a request cap (MaxRequestsPerHost) also bounds how many
// requests the task sends to one host name: every request the guard lets
// through counts, on any connection, port or scheme, and the ones past the
// cap are refused like a request outside the scope. The count lives in the
// task's forwarder, so nothing the task does (a new connection, a redirect,
// another port) resets it.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

// ErrRequestCap is the refusal of a request past the web scope's request
// cap. It wraps webscope.ErrOutOfScope: a tool reads it as any refusal.
var ErrRequestCap = fmt.Errorf("%w: request cap reached", webscope.ErrOutOfScope)

// maxCountedHosts bounds the host names one task's request cap tracks: a
// request to a further name is refused (over-refusing is the safe side; a
// web scope names at most a few dozen hosts).
const maxCountedHosts = 4096

// checkWeb checks a request that names name against the task's web scope
// (nil without one).
func (g *guard) checkWeb(req *http.Request, name string) error {
	ws := g.f.scope.Web
	if ws == nil {
		return nil
	}
	scheme := "http"
	if g.tls {
		scheme = "https"
	}
	host := name
	if strings.Contains(host, ":") { // an IPv6 address
		host = "[" + host + "]"
	}
	u := &url.URL{Scheme: scheme, Host: host, Path: req.URL.Path, RawPath: req.URL.RawPath}
	return ws.Allows(req.Method, u, g.f.scope.WebTargets)
}

// spendWebRequest counts one request to name against the web scope's
// request cap, or refuses it when the cap is spent. A task without a cap
// spends nothing.
func (f *Forwarder) spendWebRequest(name string) error {
	ws := f.scope.Web
	if ws == nil || ws.MaxRequestsPerHost <= 0 {
		return nil
	}
	f.webMu.Lock()
	defer f.webMu.Unlock()
	if f.webRequests == nil {
		f.webRequests = map[string]int{}
	}
	n, known := f.webRequests[name]
	if !known && len(f.webRequests) >= maxCountedHosts {
		return fmt.Errorf("%w: more than %d hosts", ErrRequestCap, maxCountedHosts)
	}
	if n >= ws.MaxRequestsPerHost {
		return fmt.Errorf("%w: %d requests to %s", ErrRequestCap, ws.MaxRequestsPerHost, clipString(shown(name), 128))
	}
	f.webRequests[name] = n + 1
	return nil
}

// WebRequests is how many requests the task sent to host under its web
// scope's request cap (0 without a cap).
func (f *Forwarder) WebRequests(host string) int {
	f.webMu.Lock()
	defer f.webMu.Unlock()
	return f.webRequests[normName(strings.Trim(host, "[]"))]
}
