package tool

import (
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/contract/identity"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// Task is one unit of work. Its targets were admitted by the runtime and its
// configuration validated against the manifest's schema before the tool
// sees it.
type Task struct {
	ID       string    `json:"id"`
	Attempt  int       `json:"attempt,omitempty"`
	Deadline time.Time `json:"deadline,omitzero"`
	Targets  []Target  `json:"targets,omitempty"`
	// Config is the effective configuration (defaults applied).
	Config json.RawMessage `json:"config,omitempty"`
	// Inputs are files placed in the task's directory (parsers).
	Inputs []Input `json:"inputs,omitempty"`
	// Repo is the repository of a runner-mode (CI) task.
	Repo *Repo `json:"repo,omitempty"`
	// Scope is the job's scope, read-only, for tools that expand targets.
	// Expanded targets are emitted as assets, never scanned in the same
	// task.
	Scope Scope `json:"scope,omitzero"`
	// Local is configuration the sensor itself supplies for a tool compiled
	// into it (operator settings, managed content paths): never from the
	// platform, never for an adapter shipped on its own.
	Local json.RawMessage `json:"local,omitempty"`
	// Retest, when not empty, makes the task a retest: the items to check
	// again, each on one of Targets (see Retester).
	Retest []RetestItem `json:"retest,omitempty"`
	// Capability is the capability the task runs ("scan.ports@1"), one the
	// tool implements. The runtime checks the output against its contract.
	Capability string `json:"capability,omitempty"`
	// Params are the capability's standard params as the workflow set
	// them. The runtime maps them onto the tool's config keys
	// (Manifest.ApplyParams) before the tool starts; the tool reads only
	// Config and never receives Params.
	Params map[string]json.RawMessage `json:"params,omitempty"`
	// MaxTier is the highest tier the job allows (the ceiling of the
	// platform grant). A tool whose MinimumTier is higher is refused.
	MaxTier Tier `json:"max_tier,omitempty"`
	// WebScope, when set, is the hosts, paths and methods a web tool may
	// request (webscope.Scope). Context.HTTP refuses every request outside
	// it; a tool that makes its own requests declares features.web_scope
	// and keeps to it.
	WebScope *webscope.Scope `json:"web_scope,omitempty"`
	// Limits are the port, protocol and path limits of the targets (from
	// the job's verified signed statement; scopelimit). The tool host
	// enforces them outside the tool: the task's egress forwarder refuses
	// a connection to a limited host on another port and an HTTP request
	// outside its path prefixes. A task with limits runs only on a sandbox
	// that confines its network.
	Limits []scopelimit.Limit `json:"limits,omitempty"`
	// HTTP is the effective http settings of the task: the manifest's,
	// with what the sensor's local policy decides (a forced User-Agent).
	// Set by the runtime, never taken from a job; ctx.HTTP() applies it.
	HTTP *HTTPSpec `json:"http,omitempty"`
	// Identity is the identification every request of the task must carry:
	// the organization's User-Agent (after the sensor-local policy, which
	// wins) and headers from the job. Set by the runtime, never taken from
	// a job; ctx.HTTP() sets it on every request over what the tool set
	// itself, and an exec tool receives it through {{http.user_agent}} and
	// {{http.headers:-flag}}. nil when the job carries none, or when the
	// task sends no HTTP to its targets (Manifest.SendsHTTPToTargets).
	Identity *Identity `json:"identity,omitempty"`
	// OrgHTTP is the organization's HTTP policy from the job. The tool host
	// merges it into HTTP (after the local policy) and clears it; a tool
	// never acts on it.
	OrgHTTP *core.OrgHTTPPolicy `json:"-"`
	// Egress is the job's proxy pool (core.EgressDialer). The tool host
	// makes it the task forwarder's Dial hook in the sensor's process; a
	// tool never sees it, nor the pool's credentials.
	Egress core.EgressDialer `json:"-"`
	// Content are the task's content packs per slot the manifest
	// declares, resolved by the sensor to read-only paths (ContentPaths).
	Content []TaskContent `json:"content,omitempty"`
}

// Target is one thing to work on.
type Target struct {
	// Ref is an opaque reference the runtime uses to file records on the
	// target. It never enters a CTIS document (the runtime names the
	// target's asset by its position).
	Ref string `json:"ref"`
	// Type is a CTIS 2.0 asset type ("web_origin", "domain_name",
	// "service", "repository").
	Type string `json:"type,omitempty"`
	// Value is the target itself in its type's canonical form
	// ("https://a.example:8443", "10.0.4.7", "10.0.4.7:22/tcp", "/src").
	Value string `json:"value"`
	// Attrs are typed hints from the platform (port, scheme, tech, ...).
	Attrs map[string]string `json:"attrs,omitempty"`
}

// URL returns the target as a URL with path appended ("" when the target
// is not a URL or a host).
func (t Target) URL(path string) string {
	v := serviceHostPort(strings.TrimSpace(t.Value))
	if !strings.Contains(v, "://") {
		if v == "" || strings.ContainsAny(v, "/ ") {
			return ""
		}
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return ""
	}
	if path != "" {
		u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	}
	return u.String()
}

// Host returns the target's host name or IP address ("" for a path).
func (t Target) Host() string {
	v := serviceHostPort(strings.TrimSpace(t.Value))
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return h
	}
	if strings.ContainsAny(v, "/ ") {
		return ""
	}
	return strings.Trim(v, "[]")
}

// Port returns the target's port: explicit, from Attrs["port"], or the
// scheme's default (0 when unknown).
func (t Target) Port() int {
	v := serviceHostPort(strings.TrimSpace(t.Value))
	var scheme string
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return 0
		}
		scheme, v = u.Scheme, u.Host
	}
	if _, p, err := net.SplitHostPort(v); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	if n, err := strconv.Atoi(t.Attrs["port"]); err == nil && n > 0 && n < 65536 {
		return n
	}
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// serviceHostPort returns the host:port of a CTIS service value
// ("10.0.4.7:22/tcp"), and any other value unchanged.
func serviceHostPort(v string) string {
	if strings.Contains(v, "://") {
		return v
	}
	i := strings.LastIndex(v, "/")
	if i <= 0 {
		return v
	}
	switch strings.ToLower(v[i+1:]) {
	case "tcp", "udp", "sctp":
		if _, _, err := net.SplitHostPort(v[:i]); err == nil {
			return v[:i]
		}
	}
	return v
}

// Transport returns the transport of a CTIS service value ("tcp", "udp",
// "sctp"; "" for any other value).
func (t Target) Transport() string {
	v := strings.TrimSpace(t.Value)
	if hp := serviceHostPort(v); hp != v {
		return strings.ToLower(v[len(hp)+1:])
	}
	return ""
}

// Input is a file given to the task (a parser's input).
type Input struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	// Path is relative to the task's directory.
	Path   string `json:"path"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// Repo is a CI task's repository.
type Repo struct {
	URL           string `json:"url,omitempty"`
	Branch        string `json:"branch,omitempty"`
	Commit        string `json:"commit,omitempty"`
	DefaultBranch bool   `json:"default_branch,omitempty"`
	PullRequest   int    `json:"pull_request,omitempty"`
}

// Scope is a job's scope.
type Scope struct {
	Includes []string `json:"includes,omitempty"`
	Excludes []string `json:"excludes,omitempty"`
}

// Status is how a task ended.
type Status string

// Task outcomes.
const (
	// StatusOK: every target done.
	StatusOK Status = "ok"
	// StatusPartial: some targets failed, or output was capped or
	// quarantined.
	StatusPartial Status = "partial"
	// StatusFailed: the task failed.
	StatusFailed Status = "failed"
	// StatusCanceled: the task was canceled.
	StatusCanceled Status = "canceled"
)

// TargetState is the outcome of one target.
type TargetState string

// Target outcomes.
const (
	StateDone    TargetState = "done"
	StateFailed  TargetState = "failed"
	StateSkipped TargetState = "skipped"
)

// Identity is the identification every request of a task carries
// (Task.Identity).
type Identity struct {
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	// Query is the query parameter every request carries (nil none); a tool
	// without features.http_query is not given it (AppliedIdentity says so).
	Query *core.HTTPQuery `json:"query,omitempty"`
	// UserAgents is the rotation list in force (nil none): a request to a
	// host carries UserAgentFor(host), the same value for every request of
	// the run to that host. UserAgent is then the value of the task's
	// first target host, for a tool that takes one User-Agent per process.
	UserAgents   []string `json:"user_agents,omitempty"`
	UserAgentKey string   `json:"user_agent_key,omitempty"`
	// Required: every request to a target must carry Headers and Query;
	// the tool host refused the task where they could not be carried.
	Required bool `json:"required,omitempty"`
}

// Empty reports whether the identification sets nothing.
func (i *Identity) Empty() bool {
	return i == nil || (i.UserAgent == "" && len(i.Headers) == 0 && i.Query == nil && len(i.UserAgents) == 0)
}

// UserAgentFor is the User-Agent of a request to host: the rotation list's
// value for (UserAgentKey, host) (contract identity.SelectUserAgent), else
// UserAgent.
func (i *Identity) UserAgentFor(host string) string {
	if i == nil {
		return ""
	}
	if len(i.UserAgents) > 0 {
		return identity.SelectUserAgent(i.UserAgentKey, host, i.UserAgents)
	}
	return i.UserAgent
}

// NeedsHeaders reports whether the identification sets a User-Agent or a
// header (a query parameter alone needs no features.http_identity).
func (i *Identity) NeedsHeaders() bool { return i != nil && (i.UserAgent != "" || len(i.Headers) > 0) }

// HeaderLines is the identification as "Name: value" lines: the User-Agent
// first, then the headers in name order. A tool that maps the
// identification onto its own header flags (features.http_identity) passes
// one line per flag and drops any header of the same name it was
// configured with, so the identification wins.
func (i *Identity) HeaderLines() []string {
	if i.Empty() {
		return nil
	}
	var out []string
	if i.UserAgent != "" {
		out = append(out, "User-Agent: "+i.UserAgent)
	}
	names := make([]string, 0, len(i.Headers))
	for k := range i.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		out = append(out, k+": "+i.Headers[k])
	}
	return out
}

// Overrides reports whether a configured "Name: value" header line names
// a header the identification sets (case-insensitive): such a line must be
// dropped in favor of the identification.
func (i *Identity) Overrides(line string) bool {
	if i.Empty() {
		return false
	}
	name, _, _ := strings.Cut(line, ":")
	name = strings.TrimSpace(name)
	if i.UserAgent != "" && strings.EqualFold(name, "User-Agent") {
		return true
	}
	for k := range i.Headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// Validate checks the identification as the organization's policy is
// checked (core.OrgHTTPPolicy.Validate): a User-Agent of printable ASCII
// up to 256 bytes, at most 10 headers with token names, printable ASCII
// values up to 200 bytes (no CR, LF, NUL or other control character), and
// no credential, hop-by-hop or connection header (Host, Authorization,
// Cookie, Content-Length, Transfer-Encoding, Connection, Proxy-*, ...).
// The tool host refuses a task whose identification fails it; nothing is
// stripped.
func (i *Identity) Validate() error {
	if i == nil {
		return nil
	}
	return (&core.OrgHTTPPolicy{UserAgent: i.UserAgent, Headers: i.Headers, Query: i.Query, UserAgents: i.UserAgents,
		UserAgentKey: i.UserAgentKey}).ValidateMerged()
}
