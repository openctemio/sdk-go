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
	// LockedHeaders are the names (case-insensitive) in Headers that the
	// platform enforces or a program sets: the sensor-local layer cannot
	// change them. UserAgentLocked does the same for UserAgent.
	LockedHeaders   []string `json:"locked_headers,omitempty"`
	UserAgentLocked bool     `json:"user_agent_locked,omitempty"`
	// Query is one query parameter appended to the URL of every request the
	// job's tools send to their targets (nil none). A tool that cannot carry
	// it (features.http_query) reports it "not applied".
	Query *HTTPQuery `json:"query,omitempty"`
}

// HTTPQuery is a query parameter the organization adds to its scan
// requests, so its logs show the scan: a name and a URL-safe value.
type HTTPQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

var queryPartRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// Validate accepts a name and a value of 1 to 64 of [A-Za-z0-9._~-], which
// need no percent-encoding anywhere in a URL.
func (q *HTTPQuery) Validate() error {
	if q == nil {
		return nil
	}
	if !queryPartRE.MatchString(q.Name) || !queryPartRE.MatchString(q.Value) {
		return errors.New("http_policy.query: the name and the value must each be 1 to 64 of letters, digits and . _ ~ -")
	}
	return nil
}

// Bounds of the policy's headers.
const (
	// MaxIdentityHeaders is the most headers a task's merged identification
	// may carry: the job's (at most maxOrgHTTPHeaders) plus the sensor
	// owner's local http.headers (at most MaxLocalHTTPHeaders).
	MaxIdentityHeaders    = 16
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
func (p *OrgHTTPPolicy) Validate() error { return p.validate(maxOrgHTTPHeaders) }

// ValidateMerged is Validate for an identification after the sensor-local
// layer is merged in: up to MaxIdentityHeaders headers.
func (p *OrgHTTPPolicy) ValidateMerged() error { return p.validate(MaxIdentityHeaders) }

func (p *OrgHTTPPolicy) validate(maxHeaders int) error {
	if p == nil {
		return nil
	}
	if p.UserAgent != "" && (len(p.UserAgent) > 256 || !printableASCIIOnly(p.UserAgent)) {
		return errors.New("http_policy.user_agent must be at most 256 printable ASCII characters")
	}
	if len(p.Headers) > maxHeaders {
		return fmt.Errorf("http_policy.headers: at most %d headers", maxHeaders)
	}
	for name, value := range p.Headers {
		if err := CheckIdentityHeader(name, value); err != nil {
			return fmt.Errorf("http_policy.headers: %w", err)
		}
	}
	for _, n := range p.LockedHeaders {
		if !orgHeaderNameRE.MatchString(n) {
			return fmt.Errorf("http_policy.locked_headers: %q is not a header name", n)
		}
	}
	if len(p.LockedHeaders) > maxHeaders {
		return fmt.Errorf("http_policy.locked_headers: at most %d names", maxHeaders)
	}
	return p.Query.Validate()
}

// CheckIdentityHeader is the rule every identification header obeys,
// whichever layer sets it (platform, organization, program, sensor owner):
// an RFC 7230 token name of 1 to 64 characters; a printable ASCII value of
// at most 200 bytes (no CR, LF or other control character); and never a
// credential, hop-by-hop or connection header (Authorization, Cookie,
// Host, Content-Length, Transfer-Encoding, Connection, Proxy-*, ...).
func CheckIdentityHeader(name, value string) error {
	switch {
	case !orgHeaderNameRE.MatchString(name):
		return fmt.Errorf("%q is not a header name (1 to 64 letters, digits or !#$%%&'*+-.^_|~)", name)
	case orgRefusedHeaders[strings.ToLower(name)] || strings.HasPrefix(strings.ToLower(name), "proxy-"):
		return fmt.Errorf("%s cannot be set: connection, proxy and credential headers are refused", name)
	case len(value) > maxOrgHTTPHeaderValue || !printableASCIIOnly(value):
		return fmt.Errorf("%s: the value must be at most %d printable ASCII characters", name, maxOrgHTTPHeaderValue)
	}
	return nil
}
