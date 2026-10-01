package platform

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// apiURL validates baseURL and returns baseURL + path, where path is
// built from pathFormat with every id path-escaped. IDs (job IDs, command
// IDs) come from the server; without escaping, an id like "x/../../admin"
// or "x?y" would rewrite the request path or query.
//
// Base URL rules (httpsec.CheckAPIBaseURL): non-http(s) schemes, missing
// hosts and embedded credentials are rejected; plain http to a
// non-loopback host is allowed but warned about once on stderr.
func apiURL(baseURL, pathFormat string, ids ...string) (string, error) {
	warning, err := httpsec.CheckAPIBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	// Printed once per process per base URL, shared with pkg/client.
	if warning != "" && httpsec.FirstWarning(baseURL) {
		fmt.Fprintf(os.Stderr, "[platform] WARNING: %s\n", warning)
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		if id == "" {
			return "", fmt.Errorf("empty path segment in %q", pathFormat)
		}
		args[i] = url.PathEscape(id)
	}
	return strings.TrimRight(baseURL, "/") + fmt.Sprintf(pathFormat, args...), nil
}

// newAPIHTTPClient returns the HTTP client used for every request that
// carries the sensor's API key or bootstrap token: SSRF-guarded dialer and
// no redirect following (the API never redirects; following one would
// forward the credential).
func newAPIHTTPClient(timeout time.Duration) *http.Client {
	return httpsec.NewAPIClient(timeout)
}
