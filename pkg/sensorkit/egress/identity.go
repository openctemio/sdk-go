package egress

// The job's identification at the forwarder. A tool that cannot put the
// job's identification headers, User-Agent or query parameter on its own
// requests still runs when its sandbox confines the network: the forwarder
// is its only way out, it guards every connection (Scope.Identity) and sets
// the identification on every HTTP request before it goes upstream. A
// connection that is not HTTP/1.x is refused there, so nothing reaches a
// target without the identification.

import (
	"net/http"
)

// Identity is what the forwarder puts on every request.
type Identity struct {
	// Headers replace a header of the same name the tool sent (names are
	// case-insensitive).
	Headers map[string]string
	// QueryName and QueryValue, when QueryName is set, replace a query
	// parameter of that name on the request's URL.
	QueryName, QueryValue string
	// UserAgent returns the User-Agent of a request to host ("" leaves the
	// tool's); nil leaves it too.
	UserAgent func(host string) string
}

// apply sets the identification on a request to host. A nil Identity does
// nothing.
func (id *Identity) apply(req *http.Request, host string) {
	if id == nil {
		return
	}
	for k, v := range id.Headers {
		req.Header.Del(k)
		req.Header.Set(k, v)
	}
	if id.UserAgent != nil {
		if ua := id.UserAgent(host); ua != "" {
			req.Header.Set("User-Agent", ua)
		}
	}
	if id.QueryName != "" && req.URL != nil {
		q := req.URL.Query()
		if len(q[id.QueryName]) != 1 || q.Get(id.QueryName) != id.QueryValue {
			q.Set(id.QueryName, id.QueryValue)
			req.URL.RawQuery = q.Encode()
		}
	}
}
