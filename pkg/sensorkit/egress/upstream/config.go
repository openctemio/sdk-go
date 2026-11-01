// Package upstream sends a confined task's connections through an
// organization's proxy pool (sensor proxies; api research and RFC-034 in
// openctemio/openctem). It is the Dial hook of an egress.Forwarder: the
// forwarder has already checked the destination against the job's scope,
// pinned its address and applied the per-target rate; a Pool only chooses
// the path and dials it.
//
// For every connection a Pool:
//
//   - dials a target address that is not public (private, ULA, CGNAT,
//     loopback) directly when the pool applies to public targets only
//     (an organization's default pool), and through the pool otherwise;
//   - ranks the usable endpoints (Strategy): sticky ranks them by a
//     weighted rendezvous hash of (job, target host) for failover;
//     priority keeps the given order;
//   - keeps a sticky slot per target host: the first connection to a host
//     draws its endpoint with weight Weight × (0.05 + score²), score being
//     the job-local EWMA of the endpoint's tunnels and handshake time; the
//     slot moves only when its endpoint fails as a proxy, never because of
//     a target's answer;
//   - bounds the open connections of an endpoint (MaxConns);
//   - opens a tunnel to the target address the forwarder passed (the
//     address the scope check pinned) with HTTP CONNECT, HTTP CONNECT over
//     TLS (the proxy's certificate verified) or SOCKS5; a socks5h endpoint
//     gets a target the job scoped by name by name (remote DNS), after the
//     forwarder checked the name's addresses;
//   - fails over to the next endpoint only when the proxy is down, at most
//     once per endpoint; a proxy that refuses the credentials, or that
//     says the target is unreachable or refused, ends the connection;
//   - never dials the target directly once a pool applies to it.
//
// Each endpoint has a breaker local to the job (3 consecutive proxy_down
// open it for 30 s, doubling to 10 min, with jitter, then one probe) and
// counters the sensor reports to the platform at the end of the job
// (Pool.Report). The platform computes health and weights; the sensor only
// uses them.
//
// Credentials stay in the Pool's memory: they never reach a tool, a log, an
// error or a record. Endpoints are only ever named scheme://host:port.
//
// Stability: Experimental (docs/STABILITY.md).
package upstream

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Schemes of an endpoint.
const (
	SchemeHTTP   = "http"
	SchemeHTTPS  = "https"
	SchemeSOCKS5 = "socks5"
	// SchemeSOCKS5H is SOCKS5 with remote DNS: a target the job scoped by
	// name is sent to the proxy by name and resolved there; any other
	// target (an address or range, or an address a name resolved to) by
	// address, as with socks5.
	SchemeSOCKS5H = "socks5h"
)

// Strategies of a pool.
const (
	StrategySticky   = "sticky"
	StrategyPriority = "priority"
)

// AppliesTo values.
const (
	AppliesPublic = "public" // non-public target addresses are dialed directly
	AppliesAll    = "all"    // every target address goes through the pool
)

// ModePool is the only mode of a Config.
const ModePool = "pool"

// MaxEndpoints bounds a pool.
const MaxEndpoints = 64

// MaxEndpointConns bounds Endpoint.MaxConns.
const MaxEndpointConns = 65535

// maxCredential bounds a username or a password (SOCKS5 user/pass allows
// 255 bytes each).
const maxCredential = 255

// Endpoint is one upstream proxy of a pool (the scan command's egress
// block). Username and Password are never serialized; they are set from
// the credentials the sensor fetches for the job.
type Endpoint struct {
	ID     string  `json:"id"`
	Scheme string  `json:"scheme"`
	Host   string  `json:"host"`
	Port   int     `json:"port"`
	Weight float64 `json:"weight"`
	// Auth says the endpoint has credentials on the platform.
	Auth bool `json:"auth,omitempty"`
	// MaxConns bounds the connections the job keeps open through the
	// endpoint at once, handshakes included (0: no bound). A connection
	// that finds it full waits for a free one, within its dial timeout.
	MaxConns int `json:"max_conns,omitempty"`

	Username string `json:"-"`
	Password string `json:"-"`
}

// String names the endpoint as scheme://host:port, never with credentials.
func (e Endpoint) String() string {
	return e.Scheme + "://" + joinHostPort(e.Host, e.Port)
}

// GoString keeps credentials out of %#v as well.
func (e Endpoint) GoString() string { return "upstream.Endpoint(" + e.String() + ")" }

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// Config is a pool as the scan command's egress block carries it.
type Config struct {
	Mode      string     `json:"mode"`
	PoolID    string     `json:"pool_id"`
	Revision  int64      `json:"revision"`
	Strategy  string     `json:"strategy,omitempty"`
	AppliesTo string     `json:"applies_to,omitempty"`
	Endpoints []Endpoint `json:"endpoints"`
}

// NeedsCredentials reports whether an endpoint has credentials to fetch.
func (c *Config) NeedsCredentials() bool {
	return slices.ContainsFunc(c.Endpoints, func(e Endpoint) bool { return e.Auth })
}

// ErrUnavailable is the error of a pool with no endpoint (every endpoint
// is quarantined by the platform): the job fails closed, never direct.
var ErrUnavailable = errors.New("upstream: the proxy pool has no usable endpoint")

// ErrNotAllowed is the error of an endpoint the sensor's allow list does
// not name.
var ErrNotAllowed = errors.New("upstream: endpoint not allowed by this sensor")

// Validate checks a pool and fills the defaults (strategy sticky, applies
// to public). allow is the sensor's allow list (SENSOR_SCAN_EGRESS_ALLOW,
// ParseAllow); nil allows any endpoint that passes validation. An empty
// endpoint list is ErrUnavailable; an endpoint the allow list does not
// name is ErrNotAllowed.
func (c *Config) Validate(allow Allow) error {
	if c.Mode != ModePool {
		return fmt.Errorf("egress.mode %q: only %q is known", c.Mode, ModePool)
	}
	if strings.TrimSpace(c.PoolID) == "" {
		return errors.New("egress.pool_id is empty")
	}
	switch c.Strategy {
	case "":
		c.Strategy = StrategySticky
	case StrategySticky, StrategyPriority:
	default:
		return fmt.Errorf("egress.strategy %q is unknown", c.Strategy)
	}
	switch c.AppliesTo {
	case "":
		c.AppliesTo = AppliesPublic
	case AppliesPublic, AppliesAll:
	default:
		return fmt.Errorf("egress.applies_to %q is unknown", c.AppliesTo)
	}
	if len(c.Endpoints) == 0 {
		return ErrUnavailable
	}
	if len(c.Endpoints) > MaxEndpoints {
		return fmt.Errorf("egress.endpoints: at most %d", MaxEndpoints)
	}
	seen := map[string]bool{}
	for i := range c.Endpoints {
		e := &c.Endpoints[i]
		if err := e.validate(); err != nil {
			return fmt.Errorf("egress.endpoints[%d]: %w", i, err)
		}
		if seen[e.ID] {
			return fmt.Errorf("egress.endpoints[%d]: duplicate id", i)
		}
		seen[e.ID] = true
		if !allow.Allows(e.Host, e.Port) {
			return fmt.Errorf("%w: %s", ErrNotAllowed, e)
		}
	}
	return nil
}

func (e *Endpoint) validate() error {
	if strings.TrimSpace(e.ID) == "" || len(e.ID) > 64 || hasControl(e.ID) {
		return errors.New("id is empty or invalid")
	}
	switch e.Scheme {
	case SchemeHTTP, SchemeHTTPS, SchemeSOCKS5, SchemeSOCKS5H:
	default:
		return fmt.Errorf("scheme %q is not http, https, socks5 or socks5h", e.Scheme)
	}
	if e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("port %d out of range", e.Port)
	}
	if math.IsNaN(e.Weight) || math.IsInf(e.Weight, 0) || e.Weight <= 0 {
		return errors.New("weight must be a positive number")
	}
	if e.MaxConns < 0 || e.MaxConns > MaxEndpointConns {
		return fmt.Errorf("max_conns %d out of range (0 to %d)", e.MaxConns, MaxEndpointConns)
	}
	if len(e.Username) > maxCredential || len(e.Password) > maxCredential || hasControl(e.Username) || hasControl(e.Password) {
		return errors.New("credentials too long or with control characters")
	}
	host, err := normHost(e.Host)
	if err != nil {
		return err
	}
	e.Host = host
	return nil
}

// normHost checks an endpoint host: an IP literal that is not denied, or a
// DNS name that is not localhost or a metadata name. Its addresses are
// checked again at every dial.
func normHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]")), ".")
	if h == "" {
		return "", errors.New("host is empty")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return "", errors.New("host has an IPv6 zone")
		}
		if Denied(a) {
			return "", fmt.Errorf("host %s is a loopback, link-local, metadata, multicast or reserved address", a.Unmap())
		}
		return a.Unmap().String(), nil
	}
	if len(h) > 253 || !validName(h) {
		return "", errors.New("host is not an IP address or a DNS name")
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || slices.Contains(metadataNames, h) {
		return "", fmt.Errorf("host %s is a loopback or metadata name", h)
	}
	return h, nil
}

var metadataNames = []string{"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"}

func validName(h string) bool {
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// metadataAddrs are cloud metadata and host-agent addresses outside the
// link-local range.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("168.63.129.16"),
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("240.0.0.0/4"), // includes 255.255.255.255
	netip.MustParsePrefix("fe80::/10"),
}

// Denied reports whether a proxy endpoint may never be at a: loopback,
// link-local, cloud metadata, multicast, unspecified, broadcast,
// 0.0.0.0/8 and 240.0.0.0/4. Private addresses (RFC 1918, ULA,
// 100.64.0.0/10) are allowed: segment proxies are private.
func Denied(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || slices.Contains(metadataAddrs, a) {
		return true
	}
	for _, p := range deniedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Allow is a sensor's allow list of upstream endpoints
// (SENSOR_SCAN_EGRESS_ALLOW): host:port entries, or a host for any port.
// A nil Allow allows every endpoint.
type Allow []allowEntry

type allowEntry struct {
	host string
	port int // 0: any
}

// ParseAllow parses a comma-separated list of host:port or host entries
// ("" is nil: no list). An IPv6 address is written in brackets
// ([fd00::1]:1080 or [fd00::1]).
func ParseAllow(s string) (Allow, error) {
	var out Allow
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, portStr := item, ""
		switch {
		case strings.HasPrefix(item, "["):
			end := strings.Index(item, "]")
			if end < 0 || (end+1 < len(item) && item[end+1] != ':') {
				return nil, fmt.Errorf("SENSOR_SCAN_EGRESS_ALLOW: %q is not [address] or [address]:port", item)
			}
			host = item[1:end]
			if end+1 < len(item) {
				portStr = item[end+2:]
			}
		case strings.Count(item, ":") == 1:
			host, portStr, _ = strings.Cut(item, ":")
		}
		port := 0
		if portStr != "" || strings.HasSuffix(item, ":") {
			p, err := strconv.Atoi(portStr)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("SENSOR_SCAN_EGRESS_ALLOW: %q has a bad port", item)
			}
			port = p
		}
		h, err := normHost(host)
		if err != nil {
			return nil, fmt.Errorf("SENSOR_SCAN_EGRESS_ALLOW: %q: %w", item, err)
		}
		out = append(out, allowEntry{host: h, port: port})
	}
	if len(out) == 0 && strings.TrimSpace(s) != "" {
		return nil, errors.New("SENSOR_SCAN_EGRESS_ALLOW names no endpoint")
	}
	return out, nil
}

// Allows reports whether the list names host:port (a nil list allows all).
func (a Allow) Allows(host string, port int) bool {
	if a == nil {
		return true
	}
	h, err := normHost(host)
	if err != nil {
		return false
	}
	for _, e := range a {
		if e.host == h && (e.port == 0 || e.port == port) {
			return true
		}
	}
	return false
}
