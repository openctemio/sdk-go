package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scanner content (api RFC-031): the data a tool scans with, apart from its
// binary: trivy's vulnerability database, the nuclei templates, the semgrep
// rules. A sensor reports what it has on its heartbeat, per tool
// (ToolInfo.Content), and the platform can ask it to refresh that content
// (the refresh_content command) under the tenant's content policy.

// Content names. A name is one kind of content a tool uses; a sensor may
// report others.
const (
	ContentTrivyDB         = "trivy-db"
	ContentTrivyJavaDB     = "trivy-java-db"
	ContentNucleiTemplates = "nuclei-templates"
	ContentSemgrepRules    = "semgrep-rules"
)

// CommandTypeRefreshContent is the command that asks a sensor to refresh its
// scanner content now (RefreshContentRequest is its payload). A sensor that
// reports managed content accepts it.
const CommandTypeRefreshContent = "refresh_content"

// ContentInfo is one piece of scanner content a sensor has.
type ContentInfo struct {
	// Name is the content's name (ContentTrivyDB, ContentNucleiTemplates, ...).
	Name string `json:"name"`
	// Version identifies the content: a release tag for templates, the
	// build time for a database, a digest prefix for a rules bundle. Empty
	// when the sensor has none.
	Version string `json:"version,omitempty"`
	// UpdatedAt is when the content was published (the database's build
	// time, the templates' release date); the platform measures staleness
	// from it. nil when unknown.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// FetchedAt is when this sensor installed it.
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
	// CheckedAt is when the sensor last confirmed with its source that this
	// is still the newest version (or the pinned one). Content that is old
	// because its publisher has released nothing newer is not stale: see
	// Stale.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Source is where it came from: a registry repository, a URL, "image"
	// for content baked into the sensor image, or the tool's own fetch.
	Source string `json:"source,omitempty"`
	// Digest is the content's digest ("sha256:..."): the OCI manifest digest
	// of a database, the archive digest of a template release.
	Digest string `json:"digest,omitempty"`
	// Managed is true when the sensor controls the content (it refreshes,
	// verifies and swaps it, and scans use exactly this version); false
	// when the tool fetches its content by itself.
	Managed bool `json:"managed"`
	// Error is the last refresh failure, if the last refresh failed (the
	// sensor keeps scanning with the version above). Short, no secrets.
	Error string `json:"error,omitempty"`
}

// Age returns how old the content is at now (from UpdatedAt, else
// FetchedAt); ok is false when neither is known.
func (c ContentInfo) Age(now time.Time) (age time.Duration, ok bool) {
	switch {
	case c.UpdatedAt != nil:
		return now.Sub(*c.UpdatedAt), true
	case c.FetchedAt != nil:
		return now.Sub(*c.FetchedAt), true
	default:
		return 0, false
	}
}

// Stale reports whether the content is stale at now under maxAge: older
// than maxAge (Age) AND not confirmed current (CheckedAt) within maxAge.
// A template set whose newest release is three weeks old is not stale while
// the sensor keeps confirming that nothing newer exists; a database whose
// refresh keeps failing is. maxAge <= 0 never makes content stale; content
// of unknown age is not stale.
func (c ContentInfo) Stale(now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	age, ok := c.Age(now)
	if !ok || age <= maxAge {
		return false
	}
	return c.CheckedAt == nil || now.Sub(*c.CheckedAt) > maxAge
}

// ContentPolicy is a tenant's policy for scanner content, sent to sensors on
// refresh_content commands. Sources (registries, mirrors, local
// directories) are NOT part of it: they are the sensor host's configuration,
// so the platform cannot point a sensor at content from elsewhere.
type ContentPolicy struct {
	// RefreshIntervalHours is how often the sensor checks for new content;
	// 0 leaves the sensor's own setting.
	RefreshIntervalHours int `json:"refresh_interval_hours,omitempty"`
	// Content is the per-content policy, keyed by content name.
	Content map[string]ContentPin `json:"content,omitempty"`
}

// ContentPin is the policy for one kind of content.
type ContentPin struct {
	// MaxAgeHours: content older than this is stale. The sensor refreshes
	// it on its next check and the platform reports the sensor degraded
	// while it stays stale. 0: no limit.
	MaxAgeHours int `json:"max_age_hours,omitempty"`
	// Version pins the content: an OCI digest ("sha256:...") for a
	// database, a release tag ("v10.4.9") for templates. Empty: the
	// newest the source has.
	Version string `json:"version,omitempty"`
	// Rulesets (semgrep-rules only) are the registry rulesets the sensor
	// fetches, verifies and pins ("p/default"). Empty: semgrep fetches its
	// rules itself on every scan (--config auto).
	Rulesets []string `json:"rulesets,omitempty"`
}

// MaxAge returns MaxAgeHours as a duration (0 when unset).
func (p ContentPin) MaxAge() time.Duration {
	if p.MaxAgeHours <= 0 {
		return 0
	}
	return time.Duration(p.MaxAgeHours) * time.Hour
}

// RefreshContentRequest is the payload of a refresh_content command.
type RefreshContentRequest struct {
	// Content names the content to refresh; empty refreshes all managed
	// content.
	Content []string `json:"content,omitempty"`
	// Force refreshes even content that is still fresh.
	Force bool `json:"force,omitempty"`
	// Policy, when present, replaces the policy the sensor applies (it
	// keeps it for its scheduled refreshes).
	Policy *ContentPolicy `json:"policy,omitempty"`
}

// Limits on a refresh_content payload (it comes from the network).
const (
	maxRefreshContentNames = 32
	maxContentNameLen      = 64
	maxContentVersionLen   = 128
	maxContentRulesets     = 32
	maxContentRulesetLen   = 128
	maxPolicyHours         = 24 * 365
)

// ErrInvalidRefreshContent is returned for a malformed refresh_content payload.
var ErrInvalidRefreshContent = errors.New("invalid refresh_content payload")

// ParseRefreshContentRequest decodes and checks a refresh_content payload.
// An empty payload is a valid request (refresh all content that needs it).
func ParseRefreshContentRequest(payload json.RawMessage) (*RefreshContentRequest, error) {
	req := &RefreshContentRequest{}
	if len(strings.TrimSpace(string(payload))) == 0 || string(payload) == "null" {
		return req, nil
	}
	if err := json.Unmarshal(payload, req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRefreshContent, err)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	return req, nil
}

func (r *RefreshContentRequest) validate() error {
	if len(r.Content) > maxRefreshContentNames {
		return fmt.Errorf("%w: more than %d content names", ErrInvalidRefreshContent, maxRefreshContentNames)
	}
	for _, n := range r.Content {
		if !validContentName(n) {
			return fmt.Errorf("%w: content name %q", ErrInvalidRefreshContent, n)
		}
	}
	if r.Policy == nil {
		return nil
	}
	if h := r.Policy.RefreshIntervalHours; h < 0 || h > maxPolicyHours {
		return fmt.Errorf("%w: refresh_interval_hours %d", ErrInvalidRefreshContent, h)
	}
	if len(r.Policy.Content) > maxRefreshContentNames {
		return fmt.Errorf("%w: more than %d content policies", ErrInvalidRefreshContent, maxRefreshContentNames)
	}
	for name, pin := range r.Policy.Content {
		if !validContentName(name) {
			return fmt.Errorf("%w: content name %q", ErrInvalidRefreshContent, name)
		}
		if pin.MaxAgeHours < 0 || pin.MaxAgeHours > maxPolicyHours {
			return fmt.Errorf("%w: %s max_age_hours %d", ErrInvalidRefreshContent, name, pin.MaxAgeHours)
		}
		if len(pin.Version) > maxContentVersionLen || !printableToken(pin.Version) {
			return fmt.Errorf("%w: %s version", ErrInvalidRefreshContent, name)
		}
		if len(pin.Rulesets) > maxContentRulesets {
			return fmt.Errorf("%w: %s has more than %d rulesets", ErrInvalidRefreshContent, name, maxContentRulesets)
		}
		for _, rs := range pin.Rulesets {
			if rs == "" || len(rs) > maxContentRulesetLen || !printableToken(rs) {
				return fmt.Errorf("%w: %s ruleset %q", ErrInvalidRefreshContent, name, rs)
			}
		}
	}
	return nil
}

// validContentName: lower-case letters, digits and '-', 1..64 characters.
func validContentName(s string) bool {
	if s == "" || len(s) > maxContentNameLen {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// printableToken: no whitespace, control characters or a leading '-' (the
// value may end up as a command-line argument).
func printableToken(s string) bool {
	if strings.HasPrefix(s, "-") {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}
