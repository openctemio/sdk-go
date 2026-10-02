package httpsec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/http/httpproxy"
)

// Proxy settings for the two outbound paths the SDK owns (api RFC-034 §6.1):
//
//   - the API path (NewAPIClient): requests that carry the OpenCTEM key to
//     the operator-configured platform URL;
//   - the content path (SafeHTTPClient): public content and feeds (scanner
//     templates and rules from upstream sources, KEV, EPSS, collectors).
//
// Each path has a ProxySetting. The zero value is ProxyEnvironment: the
// process environment (HTTP_PROXY, HTTPS_PROXY, NO_PROXY), which is what the
// API path always did. Scanner processes are a third path, configured in
// pkg/core (ScannerProxyMode).

// ProxyFunc is the type of http.Transport.Proxy.
type ProxyFunc = func(*http.Request) (*url.URL, error)

// ProxyMode says where a ProxySetting takes its proxy from.
type ProxyMode int

const (
	// ProxyEnvironment uses HTTP_PROXY, HTTPS_PROXY and NO_PROXY of the
	// process (http.ProxyFromEnvironment). It is the zero value.
	ProxyEnvironment ProxyMode = iota
	// ProxyDirect never uses a proxy, whatever the environment says.
	ProxyDirect
	// ProxyURL sends every request through one proxy, except the hosts in
	// the setting's NoProxy list.
	ProxyURL
)

// ProxySetting is the proxy configuration of one outbound path.
type ProxySetting struct {
	Mode ProxyMode
	// URL is the proxy for ProxyURL: http, https, socks5 or socks5h, with
	// optional user:password (Basic, or SOCKS5 user/password).
	URL *url.URL
	// NoProxy is the bypass list for ProxyURL, in NO_PROXY syntax (hosts,
	// domains, IPs, CIDRs, ":port", "*"). Loopback is never proxied.
	NoProxy string
}

// ProxyDirectValue is the setting value that means "no proxy".
const ProxyDirectValue = "direct"

// ParseProxySetting parses a proxy setting as an operator writes it:
// "" means the environment, "direct" (or "none") means no proxy, anything
// else is a proxy URL. A URL without a scheme is http, as in Go and curl.
// noProxy is the bypass list used with a URL (normally the NO_PROXY of the
// process).
func ParseProxySetting(value, noProxy string) (ProxySetting, error) {
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "":
		return ProxySetting{Mode: ProxyEnvironment}, nil
	case ProxyDirectValue, "none":
		return ProxySetting{Mode: ProxyDirect}, nil
	}
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return ProxySetting{}, fmt.Errorf("proxy %q: not a URL", redactProxyValue(value))
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return ProxySetting{}, fmt.Errorf("proxy %s: scheme must be http, https, socks5 or socks5h", u.Redacted())
	}
	if u.Hostname() == "" {
		return ProxySetting{}, fmt.Errorf("proxy %s: missing host", u.Redacted())
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return ProxySetting{}, fmt.Errorf("proxy %s: a proxy URL has no path, query or fragment", u.Redacted())
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isAPIDestinationBlocked(ip) {
		return ProxySetting{}, fmt.Errorf("proxy %s: %s cannot be a proxy (link-local, multicast, reserved or unspecified)", u.Redacted(), ip)
	}
	u.Path = ""
	return ProxySetting{Mode: ProxyURL, URL: u, NoProxy: noProxy}, nil
}

func redactProxyValue(v string) string {
	if at := strings.LastIndex(v, "@"); at >= 0 {
		return "xxxxx@" + v[at+1:]
	}
	return v
}

// String describes the setting for logs, without credentials:
// "environment", "direct" or the redacted proxy URL.
func (s ProxySetting) String() string {
	switch s.Mode {
	case ProxyDirect:
		return ProxyDirectValue
	case ProxyURL:
		if s.URL == nil {
			return "invalid"
		}
		return s.URL.Redacted()
	default:
		return "environment"
	}
}

// Func returns the http.Transport.Proxy function for the setting. It never
// returns nil, so it can be installed as is.
func (s ProxySetting) Func() ProxyFunc {
	switch s.Mode {
	case ProxyDirect:
		return noProxy
	case ProxyURL:
		if s.URL == nil {
			return noProxy
		}
		cfg := &httpproxy.Config{HTTPProxy: s.URL.String(), HTTPSProxy: s.URL.String(), NoProxy: s.NoProxy}
		fn := cfg.ProxyFunc()
		return func(req *http.Request) (*url.URL, error) { return fn(req.URL) }
	default:
		return http.ProxyFromEnvironment
	}
}

// URLFor returns the proxy a request to target would use (nil: direct). It
// answers "which proxy does this path use" for logs and for building a
// child process's environment.
func (s ProxySetting) URLFor(target *url.URL) (*url.URL, error) {
	return s.Func()(&http.Request{URL: target})
}

func noProxy(*http.Request) (*url.URL, error) { return nil, nil }

var (
	proxyMu       sync.RWMutex
	apiProxy      ProxySetting
	contentProxy  ProxySetting
	contentRoots  *x509.CertPool
	trustedUpHost = map[string]bool{}
)

// SetAPIProxy sets the proxy of every API client created afterwards
// (NewAPIClient). The zero ProxySetting goes back to the environment.
func SetAPIProxy(s ProxySetting) {
	proxyMu.Lock()
	apiProxy = s
	proxyMu.Unlock()
}

// APIProxy returns the setting of the API path.
func APIProxy() ProxySetting {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return apiProxy
}

// SetContentProxy sets the proxy of every SafeHTTPClient created afterwards.
// The zero ProxySetting goes back to the environment.
func SetContentProxy(s ProxySetting) {
	proxyMu.Lock()
	contentProxy = s
	proxyMu.Unlock()
}

// ContentProxy returns the setting of the content path.
func ContentProxy() ProxySetting {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return contentProxy
}

// SetContentRootCAs makes every SafeHTTPClient created afterwards trust
// pool instead of the system trust store (nil: the system trust store). It
// is for a TLS-inspecting egress proxy, whose CA re-signs every public
// certificate: build pool with LoadCAFile, which keeps the public CAs.
func SetContentRootCAs(pool *x509.CertPool) {
	proxyMu.Lock()
	contentRoots = pool
	proxyMu.Unlock()
}

// ContentRootCAs returns the pool set with SetContentRootCAs.
func ContentRootCAs() *x509.CertPool {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return contentRoots
}

// TrustUpstreamHosts registers host names that the program itself
// hard-codes (a public feed or content source, such as the KEV feed's host).
// When a SafeHTTPClient request goes through a proxy and such a name does
// not resolve on this host, which is normal on a network whose only way out
// is the proxy, the request is still sent and the proxy resolves the name.
// Any other name that does not resolve locally is refused, because its
// address cannot be checked.
//
// Never register a name that comes from configuration the platform or a job
// can set: that would let it skip the address check.
func TrustUpstreamHosts(hosts ...string) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			trustedUpHost[h] = true
		}
	}
}

func isTrustedUpstreamHost(h string) bool {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return trustedUpHost[strings.ToLower(h)]
}

// ErrProxiedTargetBlocked is returned (wrapped) when a request that would go
// through a proxy is refused because its target is not allowed.
var ErrProxiedTargetBlocked = errors.New("httpsec: target refused before the proxy")

// guardedProxy wraps a proxy function for a client whose targets must be
// checked (SafeHTTPClient). With a proxy, the transport dials the proxy, so
// a dial-time address check only ever sees the proxy's address. guardedProxy
// therefore checks the request's own target first:
//
//   - names in the dangerous-host list are refused;
//   - an IP literal is checked with blocked;
//   - a name is resolved on this host and every address is checked with
//     blocked; a name that does not resolve is refused, unless it was
//     registered with TrustUpstreamHosts.
//
// Only then does it return the proxy. A request that goes direct (no proxy
// for it) is left to the dialer's own check. The function also records the
// proxy's host:port in proxies, so the dialer can tell a proxy dial from a
// target dial.
func guardedProxy(next ProxyFunc, blocked func(net.IP) bool, proxies *sync.Map) ProxyFunc {
	return func(req *http.Request) (*url.URL, error) {
		p, err := next(req)
		if err != nil || p == nil {
			return p, err
		}
		if err := checkProxiedTarget(req, blocked); err != nil {
			return nil, err
		}
		if proxies != nil {
			proxies.Store(proxyDialAddr(p), true)
		}
		return p, nil
	}
}

func checkProxiedTarget(req *http.Request, blocked func(net.IP) bool) error {
	if req.URL == nil {
		return fmt.Errorf("%w: request has no URL", ErrProxiedTargetBlocked)
	}
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		return fmt.Errorf("%w: URL has no host", ErrProxiedTargetBlocked)
	}
	for _, d := range dangerousHosts {
		if host == d && !(AllowLoopback && host == "localhost") {
			return fmt.Errorf("%w: blocked hostname %s", ErrProxiedTargetBlocked, host)
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if blocked(ip) {
			return fmt.Errorf("%w: blocked IP %s", ErrProxiedTargetBlocked, ip)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(req.Context(), host)
	if err != nil || len(ips) == 0 {
		if isTrustedUpstreamHost(host) {
			return nil
		}
		return fmt.Errorf("%w: %s does not resolve on this host, so its address cannot be checked: %v", ErrProxiedTargetBlocked, host, err)
	}
	for _, ip := range ips {
		if blocked(ip.IP) {
			return fmt.Errorf("%w: %s resolves to blocked IP %s", ErrProxiedTargetBlocked, host, ip.IP)
		}
	}
	return nil
}

// proxyDialAddr is the address the transport dials for proxy p.
func proxyDialAddr(p *url.URL) string {
	port := p.Port()
	if port == "" {
		switch strings.ToLower(p.Scheme) {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(p.Hostname()), port)
}

// contentTLSConfig is the TLS configuration of a new SafeHTTPClient.
func contentTLSConfig() *tls.Config {
	pool := ContentRootCAs()
	if pool == nil {
		return nil
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// ProxyEnvVars are the proxy variables of a process environment, in both
// spellings. ScannerEnviron passes or removes them as a group.
var ProxyEnvVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "no_proxy", "all_proxy",
}

// EnvironmentProxySummary describes the proxy variables set in the process
// environment, credentials removed, e.g. "HTTPS_PROXY=http://proxy:3128".
// It is empty when none is set.
func EnvironmentProxySummary() string {
	var parts []string
	for _, name := range ProxyEnvVars {
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			continue
		}
		if !strings.HasSuffix(strings.ToUpper(name), "NO_PROXY") {
			if s, err := ParseProxySetting(v, ""); err == nil && s.Mode == ProxyURL {
				v = s.String()
			} else {
				v = redactProxyValue(v)
			}
		}
		parts = append(parts, name+"="+v)
	}
	return strings.Join(parts, " ")
}
