package toolrt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// ErrHostNotAllowed is the error of a request to a host the tool's network
// permission does not allow.
var ErrHostNotAllowed = errors.New("host not allowed by the tool's network permission")

// NewHTTPClient returns the client of tool.Context.HTTP: it reaches the
// task's targets (targets, egress-proxy), the vendor hosts (vendor) or
// nothing (none, resolver), re-checks every redirect, and never dials a link-local
// or cloud-metadata address whatever a name resolves to.
func NewHTTPClient(m tool.Manifest, task tool.Task) *http.Client {
	m = m.Normalized()
	allowed := map[string]bool{}
	switch m.Permissions.Network {
	case tool.NetTargets, tool.NetEgressProxy:
		for _, t := range task.Targets {
			if h := strings.ToLower(t.Host()); h != "" {
				allowed[h] = true
			}
		}
	case tool.NetVendor:
		for _, h := range m.Permissions.VendorHosts {
			for _, v := range vendorHosts(h, task.Config) {
				allowed[strings.ToLower(v)] = true
			}
		}
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !allowed[strings.ToLower(host)] {
				return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			lastErr := fmt.Errorf("no address for %s", host)
			for _, ip := range ips {
				if MetadataIP(ip.IP) {
					lastErr = fmt.Errorf("%w: %s resolves to %s (link-local or metadata)", ErrHostNotAllowed, host, ip.IP)
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
	}
	if p := tool.EgressProxy(); p != nil {
		// A confined task (api RFC-060): its forwarder is its only way out
		// and checks every destination; the host check here stays as
		// defense in depth and fails before anything is sent.
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			if h := strings.ToLower(req.URL.Hostname()); !allowed[h] {
				return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, h)
			}
			return p, nil
		}
		tr.DialContext = dialer.DialContext
	}
	var rt http.RoundTripper = tr
	if task.WebScope != nil {
		hosts := make([]string, 0, len(task.Targets))
		for _, t := range task.Targets {
			if h := t.Host(); h != "" {
				hosts = append(hosts, h)
			}
		}
		rt = scopedTransport{next: tr, scope: task.WebScope, targets: hosts}
	}
	timeout := 5 * time.Minute
	defaults := requestDefaults{next: rt, ua: EffectiveUserAgent(m, task)}
	if h := SpecOf(m, task); h != nil {
		defaults.headers = h.Headers
		if h.Timeout > 0 {
			timeout = time.Duration(h.Timeout)
		}
		if h.TLS != nil && m.Permissions.Network != tool.NetVendor {
			// Toward targets only: a vendor tool's credentials go to its
			// vendor hosts, which are always verified.
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: h.TLS.InsecureSkipVerify, MinVersion: h.TLS.TLSMinVersion()} //nolint:gosec // the tool's declared choice for its targets (tool.yaml http.tls), logged with the task
		}
	}
	rt = defaults
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if !allowed[strings.ToLower(req.URL.Hostname())] {
				return fmt.Errorf("%w: redirect to %s", ErrHostNotAllowed, req.URL.Hostname())
			}
			return nil
		},
	}
}

// DefaultUserAgent is the User-Agent of a tool's requests when the tool sets
// none: "openctem-<tool>/<version>". A tool sets its own per request
// (req.Header.Set("User-Agent", ...)).
func DefaultUserAgent(m tool.Manifest) string {
	name := strings.Map(func(r rune) rune {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return -1
		}
		return r
	}, m.Name)
	return "openctem-" + name + "/" + strings.TrimPrefix(m.Version, "v")
}

// SpecOf is a task's http settings: the effective ones the runtime put in
// the task, else the manifest's.
func SpecOf(m tool.Manifest, task tool.Task) *tool.HTTPSpec {
	if task.HTTP != nil {
		return task.HTTP
	}
	return m.HTTP
}

// EffectiveUserAgent is the User-Agent of a task's requests: the
// effective http.user_agent, else DefaultUserAgent.
func EffectiveUserAgent(m tool.Manifest, task tool.Task) string {
	if h := SpecOf(m, task); h != nil && h.UserAgent != "" {
		return h.UserAgent
	}
	return DefaultUserAgent(m)
}

// requestDefaults sets the User-Agent and the tool's headers on a request
// that does not set them itself.
type requestDefaults struct {
	next    http.RoundTripper
	ua      string
	headers map[string]string
}

func (u requestDefaults) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := false
	set := func(k, v string) {
		if req.Header.Get(k) != "" {
			return
		}
		if !cloned {
			req = req.Clone(req.Context())
			cloned = true
		}
		req.Header.Set(k, v)
	}
	set("User-Agent", u.ua)
	for k, v := range u.headers {
		set(k, v)
	}
	return u.next.RoundTrip(req)
}

// scopedTransport refuses every request outside the job's web scope,
// redirects included (each one is a new round trip).
type scopedTransport struct {
	next    http.RoundTripper
	scope   *webscope.Scope
	targets []string
}

func (s scopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := s.scope.Allows(req.Method, req.URL, s.targets); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return s.next.RoundTrip(req)
}

// VendorHosts are the hosts of a manifest's permissions.vendor_hosts, with
// ${config.<key>} entries read from the task's configuration.
func VendorHosts(m tool.Manifest, config json.RawMessage) []string {
	var out []string
	for _, e := range m.Permissions.VendorHosts {
		out = append(out, vendorHosts(e, config)...)
	}
	return out
}

// vendorHosts resolves a vendor host entry: a host[:port], or
// ${config.<key>} naming a URL or host in the configuration.
func vendorHosts(entry string, config json.RawMessage) []string {
	if key, ok := strings.CutPrefix(entry, "${config."); ok {
		key = strings.TrimSuffix(key, "}")
		var cfg map[string]any
		if json.Unmarshal(config, &cfg) != nil {
			return nil
		}
		v, _ := cfg[key].(string)
		if v == "" {
			return nil
		}
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			return []string{u.Hostname()}
		}
		return []string{v}
	}
	if h, _, err := net.SplitHostPort(entry); err == nil {
		return []string{h}
	}
	return []string{entry}
}

var metadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"), net.ParseIP("fd00:ec2::254"), net.ParseIP("100.100.100.200"),
	net.ParseIP("168.63.129.16"),
}

// MetadataIP reports whether ip is link-local or a known cloud metadata
// address. Tool traffic never goes there.
func MetadataIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, m := range metadataIPs {
		if m.Equal(ip) {
			return true
		}
	}
	return false
}
