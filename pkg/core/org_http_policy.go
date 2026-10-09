package core

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// OrgHTTPPolicy is what the organization decides about its tools' requests
// (api RFC-060 §4.1, the tenant layer). The platform sends it with each scan
// job. It can only narrow: the sensor-local policy decides first, and a tool
// that skips TLS verification is refused when either layer forbids it.
type OrgHTTPPolicy struct {
	// UserAgent replaces the tools' User-Agent unless the local policy forces
	// one ("" none).
	UserAgent string `json:"user_agent,omitempty"`
	// AllowInsecureTLS false refuses tools whose tool.yaml skips TLS
	// verification; nil leaves it to the local policy.
	AllowInsecureTLS *bool `json:"allow_insecure_tls,omitempty"`
	// Headers are sent on every request of the job's tools: the
	// identification a bug-bounty program requires of its researchers
	// (api RFC-065), for example "X-Bug-Bounty: <handle>". They replace a
	// tool.yaml header of the same name. Credentials and the headers the
	// HTTP client and the forwarder own are refused.
	Headers map[string]string `json:"headers,omitempty"`
}

// Bounds of the policy's headers.
const (
	maxOrgHTTPHeaders     = 10
	maxOrgHTTPHeaderValue = 200
)

var orgHeaderNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)

// orgRefusedHeaders may not come from the platform: credentials (they come
// from the credential broker) and the headers the HTTP client and the
// forwarder own.
var orgRefusedHeaders = map[string]bool{"authorization": true, "cookie": true, "proxy-authorization": true,
	"proxy-connection": true, "host": true, "content-length": true, "transfer-encoding": true,
	"connection": true, "upgrade": true, "te": true, "trailer": true, "keep-alive": true}

func printableASCIIOnly(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
}

// Validate accepts a User-Agent of printable ASCII up to 256 bytes and at
// most 10 headers: token names, printable ASCII values up to 200 bytes, no
// credential or connection header.
func (p *OrgHTTPPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if p.UserAgent != "" && (len(p.UserAgent) > 256 || !printableASCIIOnly(p.UserAgent)) {
		return errors.New("http_policy.user_agent must be at most 256 printable ASCII characters")
	}
	if len(p.Headers) > maxOrgHTTPHeaders {
		return fmt.Errorf("http_policy.headers: at most %d headers", maxOrgHTTPHeaders)
	}
	for name, value := range p.Headers {
		switch {
		case !orgHeaderNameRE.MatchString(name):
			return fmt.Errorf("http_policy.headers: %q is not a header name", name)
		case orgRefusedHeaders[strings.ToLower(name)] || strings.HasPrefix(strings.ToLower(name), "proxy-"):
			return fmt.Errorf("http_policy.headers: %s may not be set by the platform", name)
		case len(value) > maxOrgHTTPHeaderValue || !printableASCIIOnly(value):
			return fmt.Errorf("http_policy.headers: %s must be at most %d printable ASCII characters", name, maxOrgHTTPHeaderValue)
		}
	}
	return nil
}
