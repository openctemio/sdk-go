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

import (
	"net/http"
	"net/url"
	"strings"
)

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
