package httpsec

// Last-known-good addresses of the platform (the control channel's DNS
// fallback).
//
// The API client resolves the platform host with the host's resolver for
// every new connection. When that resolver fails (a corporate DNS server
// knocked over or blocked by an IPS during a scan, Docker's embedded DNS
// answering "server misbehaving"), every heartbeat, poll and result upload
// fails although the platform itself is up. LastGood keeps the addresses
// the last successful lookup returned and, on a DNS failure only, dials
// those instead.
//
// Security: the fallback changes which IP address is dialed, never what is
// verified. The TLS handshake still sends the platform host name (SNI) and
// verifies the certificate against it with the same trust (system store,
// SetAPIRootCAs pool, the pinned sensor CA on protocol v3), so an address
// that now belongs to someone else fails the handshake exactly as a
// spoofed DNS answer would. It is used only for hosts registered with
// Track, which the client does for an https platform URL and the gRPC
// endpoint (both TLS); a plain-http URL and a proxy are never tracked, so a
// proxy always resolves the platform itself. A TLS or HTTP failure never
// triggers it: only a lookup error does. The addresses stay subject to the
// API dial guard (no link-local, multicast or reserved addresses), and an
// entry older than MaxAge is not used.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultLastGoodMaxAge bounds how old a last-known-good address may be
// and still be dialed.
const DefaultLastGoodMaxAge = 24 * time.Hour

// Bounds of the state LastGood keeps (memory and file).
const (
	maxLastGoodHosts = 8
	maxLastGoodAddrs = 16
	// lastGoodPersistEvery: an unchanged address set is written again
	// (its resolved time refreshed) at most this often.
	lastGoodPersistEvery = time.Hour
	maxLastGoodFileBytes = 64 << 10
	lastGoodFileVersion  = 1
)

// LastGoodState is the control channel's DNS state for one host.
type LastGoodState string

// States of a tracked host.
const (
	// LastGoodUnknown: no lookup yet.
	LastGoodUnknown LastGoodState = ""
	// LastGoodResolving: the last lookup succeeded.
	LastGoodResolving LastGoodState = "resolving"
	// LastGoodCached: lookups fail; the last-known-good addresses are dialed.
	LastGoodCached LastGoodState = "cached"
	// LastGoodFailed: lookups fail and there is no usable cached address.
	LastGoodFailed LastGoodState = "failed"
)

// LastGoodEvent is a state change of a tracked host (one per change, never
// one per dial).
type LastGoodEvent struct {
	// Host is host:port.
	Host string
	From LastGoodState
	To   LastGoodState
	// Addrs are the addresses now dialed (the cached ones when To is
	// LastGoodCached).
	Addrs []netip.Addr
	// Since is when the lookups started failing (Cached, Failed) or when
	// they resolved again (Resolving).
	Since time.Time
	// FailedAt is when the outage began, set on the change back to
	// Resolving after a failure.
	FailedAt time.Time
	// ResolvedAt is when the cached addresses were last looked up.
	ResolvedAt time.Time
	// Cause classifies the lookup error (DNSCause).
	Cause string
	// Err is the lookup error (Cached, Failed).
	Err error
}

// LastGoodStatus is a tracked host's current state (for a config check).
type LastGoodStatus struct {
	Host       string
	State      LastGoodState
	Addrs      []netip.Addr
	ResolvedAt time.Time
	// Since: when the current state began.
	Since time.Time
	// FailedAt and RecoveredAt describe the last outage that ended.
	FailedAt, RecoveredAt time.Time
	Cause                 string
}

// Lookup resolves a host name, as net.Resolver.LookupIPAddr.
type Lookup func(ctx context.Context, host string) ([]net.IPAddr, error)

// LastGood keeps the last-known-good addresses of the tracked platform
// hosts. The zero value is not usable: use NewLastGood. It is safe for
// concurrent use.
type LastGood struct {
	mu        sync.Mutex
	maxAge    time.Duration
	lookup    Lookup
	now       func() time.Time
	path      string
	persisted map[string]time.Time
	onEvent   func(LastGoodEvent)
	logf      func(format string, args ...any)
	tracked   map[string]bool
	hosts     map[string]*lastGoodHost
}

type lastGoodHost struct {
	addrs      []netip.Addr
	resolvedAt time.Time
	state      LastGoodState
	since      time.Time
	failedAt   time.Time
	recovered  time.Time
	lastFailed time.Time
	cause      string
}

// NewLastGood returns an empty LastGood using the default resolver and
// DefaultLastGoodMaxAge.
func NewLastGood() *LastGood {
	return &LastGood{
		maxAge:    DefaultLastGoodMaxAge,
		lookup:    net.DefaultResolver.LookupIPAddr,
		now:       time.Now,
		persisted: map[string]time.Time{},
		tracked:   map[string]bool{},
		hosts:     map[string]*lastGoodHost{},
	}
}

var (
	apiLastGoodMu sync.RWMutex
	apiLastGood   = NewLastGood()
)

// APILastGood returns the LastGood every API client (NewAPIClient) uses.
func APILastGood() *LastGood {
	apiLastGoodMu.RLock()
	defer apiLastGoodMu.RUnlock()
	return apiLastGood
}

// SetAPILastGood replaces it for API clients created afterwards (tests, or
// a sensor that wants its own); nil restores a fresh default.
func SetAPILastGood(lg *LastGood) {
	if lg == nil {
		lg = NewLastGood()
	}
	apiLastGoodMu.Lock()
	apiLastGood = lg
	apiLastGoodMu.Unlock()
}

// SetMaxAge sets how old a cached address may be and still be dialed; 0
// turns the fallback off (lookups are still tracked for the status).
func (l *LastGood) SetMaxAge(d time.Duration) {
	if d < 0 {
		d = 0
	}
	l.mu.Lock()
	l.maxAge = d
	l.mu.Unlock()
}

// SetLookup replaces the resolver (tests); nil restores the default.
func (l *LastGood) SetLookup(f Lookup) {
	if f == nil {
		f = net.DefaultResolver.LookupIPAddr
	}
	l.mu.Lock()
	l.lookup = f
	l.mu.Unlock()
}

// SetClock replaces the clock (tests).
func (l *LastGood) SetClock(now func() time.Time) {
	l.mu.Lock()
	l.now = now
	l.mu.Unlock()
}

// OnEvent installs the state-change callback (called outside the lock).
func (l *LastGood) OnEvent(f func(LastGoodEvent)) {
	l.mu.Lock()
	l.onEvent = f
	l.mu.Unlock()
}

// SetLogger installs where state-file errors are written (nil: nowhere).
func (l *LastGood) SetLogger(logf func(format string, args ...any)) {
	l.mu.Lock()
	l.logf = logf
	l.mu.Unlock()
}

// lastGoodKey is the canonical host:port.
func lastGoodKey(host, port string) string {
	return net.JoinHostPort(strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), "."), port)
}

// Track enables the fallback for host:port. Call it only for a TLS
// endpoint whose certificate is verified against host (an https platform
// URL, the gRPC endpoint): the fallback relies on that check. An IP
// literal is ignored (there is nothing to resolve).
func (l *LastGood) Track(host, port string) {
	h := strings.Trim(host, "[]")
	if h == "" || port == "" {
		return
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := lastGoodKey(h, port)
	if !l.tracked[k] && len(l.tracked) >= maxLastGoodHosts {
		return
	}
	l.tracked[k] = true
}

// TrackURL is Track for an https URL; any other scheme is ignored.
func (l *LastGood) TrackURL(raw string) {
	host, port, ok := httpsHostPort(raw)
	if ok {
		l.Track(host, port)
	}
}

// DNSCause classifies a lookup error for a report: "timeout",
// "not_found", "server_misbehaving", "temporary" or "other".
func DNSCause(err error) string {
	var de *net.DNSError
	if !errors.As(err, &de) {
		return "other"
	}
	switch {
	case de.IsTimeout:
		return "timeout"
	case de.IsNotFound:
		return "not_found"
	case strings.Contains(de.Err, "server misbehaving"):
		return "server_misbehaving"
	case de.IsTemporary:
		return "temporary"
	}
	return "other"
}

// isLookupError reports whether err is a DNS failure (not a canceled
// request).
func isLookupError(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var de *net.DNSError
	return errors.As(err, &de)
}

// Resolve looks host up; for a tracked host it records the answer and, on a
// DNS failure, returns the last-known-good addresses while they are younger
// than the maximum age. Any other host is looked up as usual.
func (l *LastGood) Resolve(ctx context.Context, host, port string) ([]net.IPAddr, error) {
	l.mu.Lock()
	lookup := l.lookup
	k := lastGoodKey(host, port)
	tracked := l.tracked[k]
	l.mu.Unlock()
	ips, err := lookup(ctx, host)
	if !tracked {
		return ips, err
	}
	if err == nil && len(ips) > 0 {
		l.resolved(k, ips)
		return ips, nil
	}
	if err == nil {
		err = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	if !isLookupError(ctx, err) {
		return nil, err
	}
	if cached := l.failed(k, err); len(cached) > 0 {
		return cached, nil
	}
	return nil, err
}

func (l *LastGood) resolved(k string, ips []net.IPAddr) {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.IP); ok && !isAPIDestinationBlocked(ip.IP) {
			a = a.Unmap()
			if !containsNetAddr(addrs, a) {
				addrs = append(addrs, a)
			}
		}
		if len(addrs) == maxLastGoodAddrs {
			break
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	l.mu.Lock()
	now := l.now()
	h := l.host(k)
	changed := !sameNetAddrs(h.addrs, addrs)
	if len(addrs) > 0 {
		h.addrs, h.resolvedAt = addrs, now
	}
	var ev *LastGoodEvent
	if h.state != LastGoodResolving {
		e := LastGoodEvent{Host: k, From: h.state, To: LastGoodResolving, Addrs: cloneNetAddrs(h.addrs), Since: now}
		if h.state == LastGoodCached || h.state == LastGoodFailed {
			e.FailedAt = h.since
			h.failedAt, h.recovered = h.since, now
		}
		h.state, h.since, h.cause = LastGoodResolving, now, ""
		ev = &e
	}
	persist := l.path != "" && len(addrs) > 0 && (changed || now.Sub(l.persisted[k]) >= lastGoodPersistEvery)
	if persist {
		l.persisted[k] = now
	}
	snap, path, logf, cb := l.fileSnapshot(), l.path, l.logf, l.onEvent
	l.mu.Unlock()
	if persist {
		if err := writeLastGoodFile(path, snap); err != nil && logf != nil {
			logf("platform address cache: %v", err)
		}
	}
	if ev != nil && cb != nil {
		cb(*ev)
	}
}

// failed records a DNS failure and returns the addresses to dial instead
// (none: the error stands).
func (l *LastGood) failed(k string, err error) []net.IPAddr {
	l.mu.Lock()
	now := l.now()
	h := l.host(k)
	h.lastFailed, h.cause = now, DNSCause(err)
	usable := l.maxAge > 0 && len(h.addrs) > 0 && !h.resolvedAt.IsZero() && now.Sub(h.resolvedAt) <= l.maxAge
	to := LastGoodFailed
	if usable {
		to = LastGoodCached
	}
	var ev *LastGoodEvent
	if h.state != to {
		since := now
		if h.state == LastGoodCached || h.state == LastGoodFailed {
			since = h.since // the outage goes on
		}
		e := LastGoodEvent{Host: k, From: h.state, To: to, Since: since, ResolvedAt: h.resolvedAt, Cause: h.cause, Err: err}
		if usable {
			e.Addrs = cloneNetAddrs(h.addrs)
		}
		h.state, h.since = to, since
		ev = &e
	}
	var out []net.IPAddr
	if usable {
		for _, a := range h.addrs {
			out = append(out, net.IPAddr{IP: net.IP(a.AsSlice())})
		}
	}
	cb := l.onEvent
	l.mu.Unlock()
	if ev != nil && cb != nil {
		cb(*ev)
	}
	return out
}

// host returns k's entry, creating it (caller holds mu).
func (l *LastGood) host(k string) *lastGoodHost {
	h := l.hosts[k]
	if h == nil {
		h = &lastGoodHost{}
		l.hosts[k] = h
	}
	return h
}

// Status returns the tracked hosts' states, sorted by host.
func (l *LastGood) Status() []LastGoodStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []LastGoodStatus
	for k := range l.tracked {
		h := l.hosts[k]
		if h == nil {
			out = append(out, LastGoodStatus{Host: k})
			continue
		}
		out = append(out, LastGoodStatus{Host: k, State: h.state, Addrs: cloneNetAddrs(h.addrs), ResolvedAt: h.resolvedAt,
			Since: h.since, FailedAt: h.failedAt, RecoveredAt: h.recovered, Cause: h.cause})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// --- state file --------------------------------------------------------------

type lastGoodFile struct {
	V     int                          `json:"v"`
	Hosts map[string]lastGoodFileEntry `json:"hosts"`
}

type lastGoodFileEntry struct {
	Addrs      []string  `json:"addrs"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// SetStateFile keeps the addresses in path too (mode 0600, written when
// they change and at most hourly otherwise), and loads what an earlier run
// wrote there, so a sensor restarted during a DNS outage still reaches the
// platform. An entry is used only for a host tracked in this run and only
// while younger than the maximum age; a file that cannot be read is
// ignored (and replaced on the next successful lookup). "" turns it off.
func (l *LastGood) SetStateFile(path string) {
	l.mu.Lock()
	l.path = path
	logf := l.logf
	l.mu.Unlock()
	if path == "" {
		return
	}
	f, err := readLastGoodFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && logf != nil {
			logf("platform address cache: ignoring %s: %v", path, err)
		}
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range f.Hosts {
		host, port, err := net.SplitHostPort(k)
		if err != nil || host == "" || len(l.hosts) >= maxLastGoodHosts {
			continue
		}
		k = lastGoodKey(host, port)
		var addrs []netip.Addr
		for _, s := range e.Addrs {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" || isAPIDestinationBlocked(net.IP(a.AsSlice())) || containsNetAddr(addrs, a) {
				continue
			}
			addrs = append(addrs, a.Unmap())
			if len(addrs) == maxLastGoodAddrs {
				break
			}
		}
		if len(addrs) == 0 || e.ResolvedAt.IsZero() || e.ResolvedAt.After(l.now().Add(time.Minute)) {
			continue
		}
		h := l.host(k)
		if h.resolvedAt.IsZero() {
			h.addrs, h.resolvedAt = addrs, e.ResolvedAt
			l.persisted[k] = e.ResolvedAt
		}
	}
}

// fileSnapshot is the file content (caller holds mu).
func (l *LastGood) fileSnapshot() lastGoodFile {
	f := lastGoodFile{V: lastGoodFileVersion, Hosts: map[string]lastGoodFileEntry{}}
	for k, h := range l.hosts {
		if !l.tracked[k] || len(h.addrs) == 0 {
			continue
		}
		e := lastGoodFileEntry{ResolvedAt: h.resolvedAt.UTC()}
		for _, a := range h.addrs {
			e.Addrs = append(e.Addrs, a.String())
		}
		f.Hosts[k] = e
	}
	return f
}

func readLastGoodFile(path string) (lastGoodFile, error) {
	var f lastGoodFile
	fh, err := os.Open(path) //nolint:gosec // the sensor's own state file
	if err != nil {
		return f, err
	}
	defer func() { _ = fh.Close() }()
	raw, err := io.ReadAll(io.LimitReader(fh, maxLastGoodFileBytes+1))
	if err != nil {
		return f, err
	}
	if len(raw) > maxLastGoodFileBytes {
		return f, errors.New("file too large")
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return lastGoodFile{}, err
	}
	if f.V != lastGoodFileVersion {
		return lastGoodFile{}, fmt.Errorf("unknown version %d", f.V)
	}
	return f, nil
}

// writeLastGoodFile replaces path atomically (temporary file + rename).
func writeLastGoodFile(path string, f lastGoodFile) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".platform-addrs-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// --- helpers -----------------------------------------------------------------

func httpsHostPort(raw string) (host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
		return "", "", false
	}
	return u.Hostname(), effectivePort(u), true
}

func containsNetAddr(as []netip.Addr, a netip.Addr) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}

func sameNetAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneNetAddrs(a []netip.Addr) []netip.Addr {
	if len(a) == 0 {
		return nil
	}
	return append([]netip.Addr(nil), a...)
}
