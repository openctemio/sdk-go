package tool

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
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
}

// Target is one thing to work on.
type Target struct {
	// Ref is an opaque reference that links records to the platform's
	// asset.
	Ref string `json:"ref"`
	// Type is a CTIS asset type ("http_service", "domain", "repository").
	Type string `json:"type,omitempty"`
	// Value is the target itself ("https://a.example:8443", "10.0.4.7",
	// "/src").
	Value string `json:"value"`
	// Attrs are typed hints from the platform (port, scheme, tech, ...).
	Attrs map[string]string `json:"attrs,omitempty"`
}

// URL returns the target as a URL with path appended ("" when the target
// is not a URL or a host).
func (t Target) URL(path string) string {
	v := strings.TrimSpace(t.Value)
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
	v := strings.TrimSpace(t.Value)
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
	v := strings.TrimSpace(t.Value)
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
