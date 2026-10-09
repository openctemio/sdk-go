package core

import (
	"errors"
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
}

// Validate accepts a User-Agent of printable ASCII up to 256 bytes.
func (p *OrgHTTPPolicy) Validate() error {
	if p == nil || p.UserAgent == "" {
		return nil
	}
	if len(p.UserAgent) > 256 || strings.IndexFunc(p.UserAgent, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
		return errors.New("http_policy.user_agent must be at most 256 printable ASCII characters")
	}
	return nil
}
