// Package webscope is the web scope of a job: which hosts, paths and
// methods a web tool (a crawler, a DAST scanner) may request. The platform
// puts it in the job; the SDK refuses every request outside it, whatever the
// tool does (tool.Context.HTTP), and the sensor maps it onto the flags of a
// tool that makes its own requests.
//
// A job without a web scope is unrestricted by this package (the target
// hosts and the egress guard still apply).
package webscope

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
)

// Bounds of a web scope.
const (
	maxEntries   = 64
	maxEntrySize = 512
)

// ErrOutOfScope is the error of a request outside the web scope.
var ErrOutOfScope = errors.New("outside the job's web scope")

// methods are the HTTP methods a scope may allow.
var methods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

// defaultMethods are the methods of a scope that names none: the ones that
// change nothing on a well-behaved server.
var defaultMethods = []string{"GET", "HEAD", "OPTIONS"}

// Scope is a job's web scope.
type Scope struct {
	// Hosts are the hosts a request may go to: a host name or address
	// ("app.example.com"), or "*.example.com" for the domain and every
	// name under it. Empty: the job's target hosts.
	Hosts []string `json:"hosts,omitempty"`
	// PathPrefixes are the paths a request may go to ("/app", "/api/v2/").
	// A prefix matches itself and the paths under it, at a segment
	// boundary. Empty: every path.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	// DenyPaths are paths a request never goes to ("/logout", "/admin"),
	// whatever PathPrefixes allows. A deny path matches every path that
	// starts with it, ignoring case: over-blocking is the safe side.
	DenyPaths []string `json:"deny_paths,omitempty"`
	// Methods are the HTTP methods a request may use. Empty: GET, HEAD
	// and OPTIONS.
	Methods []string `json:"methods,omitempty"`
}

// Validate checks the scope's bounds and syntax. A job whose scope is
// invalid is refused, never run unrestricted.
func (s *Scope) Validate() error {
	if s == nil {
		return nil
	}
	for name, list := range map[string][]string{"hosts": s.Hosts, "path_prefixes": s.PathPrefixes,
		"deny_paths": s.DenyPaths, "methods": s.Methods} {
		if len(list) > maxEntries {
			return fmt.Errorf("web scope: %d %s, at most %d", len(list), name, maxEntries)
		}
		for _, v := range list {
			if v == "" || len(v) > maxEntrySize || strings.ContainsFunc(v, isControl) {
				return fmt.Errorf("web scope: invalid %s entry", name)
			}
		}
	}
	for _, h := range s.Hosts {
		if strings.ContainsAny(h, "/?#@ ") || strings.Count(h, "*") > 1 ||
			(strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
			return fmt.Errorf("web scope: invalid host %q", h)
		}
	}
	for _, p := range slices.Concat(s.PathPrefixes, s.DenyPaths) {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") || hasDotSegment(p) {
			return fmt.Errorf("web scope: invalid path %q", p)
		}
	}
	for _, m := range s.Methods {
		if !slices.Contains(methods, m) {
			return fmt.Errorf("web scope: method %q is not one of %v", m, methods)
		}
	}
	return nil
}

// Allows reports whether a request may go to u with method; the error
// names why not. targets are the job's target hosts, the hosts of a scope
// that names none.
func (s *Scope) Allows(method string, u *url.URL, targets []string) error {
	if s == nil {
		return nil
	}
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return fmt.Errorf("%w: not an http(s) URL", ErrOutOfScope)
	}
	m := strings.ToUpper(method)
	if m == "" {
		m = "GET"
	}
	allowed := s.Methods
	if len(allowed) == 0 {
		allowed = defaultMethods
	}
	if !slices.Contains(allowed, m) {
		return fmt.Errorf("%w: method %s", ErrOutOfScope, m)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	hosts := s.Hosts
	if len(hosts) == 0 {
		hosts = targets
	}
	if !slices.ContainsFunc(hosts, func(p string) bool { return HostMatches(p, host) }) {
		return fmt.Errorf("%w: host %s", ErrOutOfScope, host)
	}
	p, err := CleanPath(u)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOutOfScope, err)
	}
	lower := strings.ToLower(p)
	for _, d := range s.DenyPaths {
		if strings.HasPrefix(lower, strings.ToLower(d)) {
			return fmt.Errorf("%w: path %s is denied", ErrOutOfScope, d)
		}
	}
	if len(s.PathPrefixes) > 0 && !slices.ContainsFunc(s.PathPrefixes, func(pre string) bool { return underPrefix(p, pre) }) {
		return fmt.Errorf("%w: path outside the allowed prefixes", ErrOutOfScope)
	}
	return nil
}

// HostMatches reports whether host matches the pattern: equal ignoring case
// and a trailing dot, or, for "*.example.com", example.com and any name
// under it.
func HostMatches(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if pattern == "" || host == "" {
		return false
	}
	if apex, ok := strings.CutPrefix(pattern, "*."); ok {
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
	return host == strings.Trim(pattern, "[]")
}

// CleanPath is the path a server sees for u: percent-decoded, dot segments
// resolved, never empty. A path that still holds an encoded slash or a
// NUL after decoding is refused: servers disagree on it.
func CleanPath(u *url.URL) (string, error) {
	raw := u.EscapedPath()
	if raw == "" {
		return "/", nil
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return "", errors.New("encoded separator in the path")
	}
	dec, err := url.PathUnescape(raw)
	if err != nil {
		return "", errors.New("invalid percent-encoding in the path")
	}
	dec = strings.ReplaceAll(dec, "\\", "/")
	trailing := strings.HasSuffix(dec, "/")
	c := path.Clean("/" + dec)
	if trailing && c != "/" {
		c += "/"
	}
	return c, nil
}

// underPrefix reports whether p is the prefix or under it, at a segment
// boundary.
func underPrefix(p, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/")
}

func hasDotSegment(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(s string) bool { return s == "." || s == ".." })
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }
