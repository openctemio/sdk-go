package client

import (
	"net/http"
	"strings"
)

// v1Only serves fn as a platform from before protocol v2: every /api/v2/
// request is a plain 404 (what chi answers for an unknown route), so the
// client negotiates protocol v1 and fn sees only v1 requests.
func v1Only(fn func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v2/") {
			http.NotFound(w, r)
			return
		}
		fn(w, r)
	})
}
