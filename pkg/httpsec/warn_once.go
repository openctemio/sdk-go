package httpsec

import "sync"

// warnedBaseURLs remembers the base URLs whose CheckAPIBaseURL warning was
// already printed by this process.
var warnedBaseURLs sync.Map

// FirstWarning reports whether the CheckAPIBaseURL warning for baseURL should
// be printed now: true the first time it is asked for a given base URL in this
// process, false afterwards. pkg/client and pkg/platform share it, so a sensor
// that builds several clients for one platform prints the plain-http warning
// once, not once per client or per request.
func FirstWarning(baseURL string) bool {
	_, loaded := warnedBaseURLs.LoadOrStore(baseURL, struct{}{})
	return !loaded
}
