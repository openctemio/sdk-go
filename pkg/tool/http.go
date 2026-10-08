package tool

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// HTTPSpec is how a tool's requests to its targets look (tool.yaml http;
// api RFC-060 §4.4): a tool may set these freely. What a request may reach
// is not among them: the scope, the sandbox and the forwarder decide that.
type HTTPSpec struct {
	// UserAgent replaces the default "openctem-<tool>/<version>".
	UserAgent string `json:"user_agent,omitempty"`
	// Headers are added to every request that does not set them.
	Headers map[string]string `json:"headers,omitempty"`
	// Timeout bounds one request (1s to 10m; default 5m).
	Timeout Duration `json:"timeout,omitempty"`
	// TLS adjusts TLS toward the targets.
	TLS *TLSSpec `json:"tls,omitempty"`
}

// TLSSpec adjusts TLS toward a tool's targets.
type TLSSpec struct {
	// InsecureSkipVerify accepts any certificate (scanning a target with a
	// self-signed or expired one). Refused for a vendor-network tool:
	// credentials travel to vendor hosts.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// MinVersion is "1.0", "1.1", "1.2" or "1.3" (default: Go's).
	MinVersion string `json:"min_version,omitempty"`
}

// Bounds of an HTTPSpec.
const (
	maxHTTPHeaders     = 32
	maxHTTPHeaderValue = 1024
	maxUserAgent       = 256
)

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)

// refusedHeaders are headers a descriptor may not set: credentials (they
// come from the credential broker, never from tool.yaml) and the ones the
// HTTP client and the forwarder own.
var refusedHeaders = []string{"authorization", "cookie", "proxy-authorization", "proxy-connection", "host",
	"content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "keep-alive"}

// TLSMinVersion maps MinVersion to crypto/tls (0: Go's default).
func (t *TLSSpec) TLSMinVersion() uint16 {
	if t == nil {
		return 0
	}
	switch t.MinVersion {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	}
	return 0
}

// validate checks the spec of a manifest whose network is network; add
// reports a problem at a JSON pointer.
func (h *HTTPSpec) validate(network Network, add func(ptr, format string, args ...any)) {
	if h == nil {
		return
	}
	if h.UserAgent != "" && (len(h.UserAgent) > maxUserAgent || !printableASCII(h.UserAgent)) {
		add("/http/user_agent", "must be at most %d printable ASCII characters", maxUserAgent)
	}
	if len(h.Headers) > maxHTTPHeaders {
		add("/http/headers", "at most %d headers", maxHTTPHeaders)
	}
	for _, name := range slices.Sorted(mapKeys(h.Headers)) {
		ptr := "/http/headers/" + name
		switch {
		case !headerNameRE.MatchString(name):
			add(ptr, "not a header name")
		case slices.Contains(refusedHeaders, strings.ToLower(name)) || strings.HasPrefix(strings.ToLower(name), "proxy-"):
			add(ptr, "may not be set in tool.yaml (credentials come from the credential broker; the client owns framing headers)")
		case len(h.Headers[name]) > maxHTTPHeaderValue || !printableASCII(h.Headers[name]):
			add(ptr, "the value must be at most %d printable ASCII characters", maxHTTPHeaderValue)
		}
	}
	if t := time.Duration(h.Timeout); t != 0 && (t < time.Second || t > 10*time.Minute) {
		add("/http/timeout", "must be between 1s and 10m")
	}
	if h.TLS != nil {
		if h.TLS.MinVersion != "" && h.TLS.TLSMinVersion() == 0 {
			add("/http/tls/min_version", "must be 1.0, 1.1, 1.2 or 1.3")
		}
		if h.TLS.InsecureSkipVerify && network == NetVendor {
			add("/http/tls/insecure_skip_verify", "not for a vendor-network tool: its credentials travel to the vendor hosts")
		}
	}
}

func printableASCII(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// String summarizes the spec for a log line (header names only).
func (h *HTTPSpec) String() string {
	if h == nil {
		return ""
	}
	var parts []string
	if h.UserAgent != "" {
		parts = append(parts, "user_agent="+h.UserAgent)
	}
	if len(h.Headers) > 0 {
		parts = append(parts, "headers="+strings.Join(slices.Sorted(mapKeys(h.Headers)), ","))
	}
	if h.Timeout != 0 {
		parts = append(parts, "timeout="+time.Duration(h.Timeout).String())
	}
	if h.TLS != nil && h.TLS.InsecureSkipVerify {
		parts = append(parts, "tls_verify=off")
	}
	if h.TLS != nil && h.TLS.MinVersion != "" {
		parts = append(parts, "tls_min="+h.TLS.MinVersion)
	}
	return fmt.Sprint(strings.Join(parts, " "))
}
