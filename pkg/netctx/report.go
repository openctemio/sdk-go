package netctx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"
)

// ReportVersion is the report's schema version.
const ReportVersion = 1

// EchoResult is what the platform's egress echo answered: the address it
// saw this sensor's request come from.
type EchoResult struct {
	Address netip.Addr
	// ViaProxy: the request went through a proxy (the control proxy).
	ViaProxy bool
}

// Echo asks the platform which address this sensor's requests come from.
// It is the only network call detection makes.
type Echo func(ctx context.Context) (EchoResult, error)

// ErrEchoUnsupported is returned by an Echo when the platform does not
// serve the egress echo.
var ErrEchoUnsupported = errors.New("the platform does not serve the egress echo")

// Egress reasons (Egress.Reason): why Internet is what it is.
const (
	ReasonDeclared        = "declared"
	ReasonEchoPublic      = "echo_public"
	ReasonEchoPrivate     = "echo_private"
	ReasonEchoUnsupported = "echo_unsupported"
	ReasonEchoFailed      = "echo_failed"
	ReasonNoEcho          = "no_echo"
	ReasonNoDefaultRoute  = "no_default_route"
)

// Egress is the internet mode and how it was decided.
type Egress struct {
	Internet Internet
	// Declared: the host owner set it (SENSOR_INTERNET).
	Declared bool
	Reason   string
	// Address is the address the platform saw (zero: no echo).
	Address  netip.Addr
	ViaProxy bool
}

// DefaultEchoTimeout bounds one egress echo.
const DefaultEchoTimeout = 10 * time.Second

// ResolveEgress decides the internet mode. A declaration wins. Otherwise
// an echo the platform saw from a public address means the path crosses the
// internet (direct, or proxy when it went through one). An echo failure is
// "unknown", never "none": a blocked echo must not take internet work away
// from a sensor that has internet. "none" is detected only when the
// routing table is known and has no default route (and no proxy carried the
// echo).
func ResolveEgress(ctx context.Context, d Declared, det Detected, echo Echo, timeout time.Duration) Egress {
	var eg Egress
	var obs EchoResult
	var echoErr error
	if echo == nil {
		echoErr = errNoEcho
	} else {
		if timeout <= 0 {
			timeout = DefaultEchoTimeout
		}
		ectx, cancel := context.WithTimeout(ctx, timeout)
		obs, echoErr = echo(ectx)
		cancel()
		if echoErr == nil && !obs.Address.IsValid() {
			echoErr = errors.New("the echo carried no address")
		}
	}
	if echoErr == nil {
		eg.Address, eg.ViaProxy = obs.Address.Unmap(), obs.ViaProxy
	}
	if d.Internet != "" && d.Internet != InternetAuto {
		eg.Internet, eg.Declared, eg.Reason = d.Internet, true, ReasonDeclared
		return eg
	}
	switch {
	case echoErr == nil && eg.Address.IsGlobalUnicast() && !isPrivate(eg.Address):
		eg.Internet, eg.Reason = InternetDirect, ReasonEchoPublic
		if eg.ViaProxy {
			eg.Internet = InternetProxy
		}
	case det.RoutesKnown && !det.DefaultV4 && !det.DefaultV6 && !(echoErr == nil && eg.ViaProxy):
		eg.Internet, eg.Reason = InternetNone, ReasonNoDefaultRoute
	default:
		eg.Internet = InternetUnknown
		switch {
		case echoErr == nil:
			eg.Reason = ReasonEchoPrivate
		case errors.Is(echoErr, errNoEcho):
			eg.Reason = ReasonNoEcho
		case errors.Is(echoErr, ErrEchoUnsupported):
			eg.Reason = ReasonEchoUnsupported
		default:
			eg.Reason = ReasonEchoFailed
		}
	}
	return eg
}

var errNoEcho = errors.New("no echo")

// Scope is what the local policy lets this sensor scan; the report names
// no prefix outside it.
type Scope struct {
	// Set: targets.allow is set (or no target is allowed at all); only
	// prefixes inside Allow are named.
	Set   bool
	Allow []netip.Prefix
	// Deny are targets.deny ranges: a prefix inside one is not named.
	Deny []netip.Prefix
	// NoPrivate: private targets are refused, so no private prefix is
	// named.
	NoPrivate bool
}

// trim narrows ps to the scope: a prefix inside an allowed one stays, an
// allowed prefix inside it replaces it, anything else is dropped. It
// returns the kept prefixes (sorted, unique) and how many inputs were
// narrowed or dropped.
func (s Scope) trim(ps []netip.Prefix) ([]netip.Prefix, int) {
	trimmed := 0
	if s.NoPrivate || len(s.Deny) > 0 {
		kept := make([]netip.Prefix, 0, len(ps))
		for _, p := range ps {
			if (s.NoPrivate && isPrivate(p.Addr())) || insideAny(s.Deny, p) {
				trimmed++
				continue
			}
			kept = append(kept, p)
		}
		ps = kept
	}
	if !s.Set {
		return ps, trimmed
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range ps {
		inside := false
		var narrower []netip.Prefix
		for _, a := range s.Allow {
			switch {
			case a.Addr().Is4() != p.Addr().Is4():
			case a.Bits() <= p.Bits() && a.Contains(p.Addr()):
				inside = true
			case p.Bits() < a.Bits() && p.Contains(a.Addr()):
				narrower = append(narrower, a)
			}
		}
		if inside {
			add(p)
			continue
		}
		trimmed++
		for _, a := range narrower {
			if !(s.NoPrivate && isPrivate(a.Addr())) && !insideAny(s.Deny, a) {
				add(a)
			}
		}
	}
	sortPrefixes(out)
	return out, trimmed
}

// Report is the network member of the sensor manifest.
type Report struct {
	V    int  `json:"v"`
	Mode Mode `json:"mode"`
	// Fingerprint changes when the sensor moves (another network, other
	// gateways, resolvers, search domains or site); not when its egress
	// address changes.
	Fingerprint string   `json:"fingerprint"`
	Internet    Internet `json:"internet"`
	// InternetDeclared: the host owner set Internet.
	InternetDeclared bool `json:"internet_declared,omitempty"`
	// EgressAddress is the address the platform's echo saw (summary and
	// full only).
	EgressAddress string          `json:"egress_address,omitempty"`
	Declared      *ReportDeclared `json:"declared,omitempty"`
	Detected      *ReportDetected `json:"detected,omitempty"`
	// Trimmed counts prefixes narrowed or left out because the local
	// policy does not allow them, or because a list was over its bound.
	Trimmed int `json:"trimmed,omitempty"`
}

// ReportDeclared is the host owner's declaration as reported.
type ReportDeclared struct {
	Site        string   `json:"site,omitempty"`
	Reach       []string `json:"reach,omitempty"`
	DNSSuffixes []string `json:"dns_suffixes,omitempty"`
}

// ReportDetected is what detection found, as reported.
type ReportDetected struct {
	// OnLink are the on-link prefixes: private ones (summary), all (full).
	OnLink []string `json:"on_link,omitempty"`
	// PublicOnLink counts the public on-link prefixes summary leaves out.
	PublicOnLink int `json:"public_on_link,omitempty"`
	// Routes says whether the routing table was read: "known" or
	// "unknown" (DefaultV4/DefaultV6 mean nothing then).
	Routes        string   `json:"routes"`
	DefaultV4     bool     `json:"default_route_v4,omitempty"`
	DefaultV6     bool     `json:"default_route_v6,omitempty"`
	Resolvers     []string `json:"resolvers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

// Fingerprint is "sha256:" + the hex SHA-256 of the facts that change when
// the sensor moves: its site, its private on-link prefixes, its default
// gateways, its resolvers and search domains (each sorted). It is computed
// before any trimming, so a local policy edit does not read as a move. It
// is a change detector, not a secret: the facts are low-entropy.
func Fingerprint(d Declared, det Detected) string {
	var b strings.Builder
	b.WriteString("netctx/v1\n")
	b.WriteString("site=" + d.Site + "\n")
	for _, p := range det.OnLink {
		if isPrivate(p.Addr()) {
			b.WriteString("net=" + p.String() + "\n")
		}
	}
	for _, g := range det.Gateways {
		b.WriteString("gw=" + g.String() + "\n")
	}
	res := append([]netip.Addr(nil), det.Resolvers...)
	sortAddrs(res)
	for _, r := range res {
		b.WriteString("dns=" + r.String() + "\n")
	}
	search := append([]string(nil), det.SearchDomains...)
	sortStrings(search)
	for _, s := range search {
		b.WriteString("search=" + s + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildReport assembles the report: bounded, sorted, never wider than
// scope, and as small as the declared mode asks.
func BuildReport(d Declared, det Detected, eg Egress, scope Scope) *Report {
	mode := d.Mode
	if mode == "" {
		mode = ModeSummary
	}
	r := &Report{V: ReportVersion, Mode: mode, Fingerprint: Fingerprint(d, det), Internet: eg.Internet,
		InternetDeclared: eg.Declared}
	if r.Internet == "" {
		r.Internet = InternetUnknown
	}
	if mode == ModeOff {
		return r
	}
	if eg.Address.IsValid() {
		r.EgressAddress = eg.Address.String()
	}

	reach, trimmed := scope.trim(d.Reach)
	r.Trimmed += trimmed
	if len(reach) > MaxReach {
		r.Trimmed += len(reach) - MaxReach
		reach = reach[:MaxReach]
	}
	suffixes := d.DNSSuffixes
	if len(suffixes) > MaxDNSSuffixes {
		suffixes = suffixes[:MaxDNSSuffixes]
	}
	if d.Site != "" || len(reach) > 0 || len(suffixes) > 0 {
		r.Declared = &ReportDeclared{Site: d.Site, Reach: prefixStrings(reach), DNSSuffixes: append([]string(nil), suffixes...)}
	}

	var listed []netip.Prefix
	public := 0
	for _, p := range det.OnLink {
		if mode != ModeFull && !isPrivate(p.Addr()) {
			public++
			continue
		}
		listed = append(listed, p)
	}
	listed, trimmed = scope.trim(listed)
	r.Trimmed += trimmed
	if len(listed) > MaxOnLink {
		r.Trimmed += len(listed) - MaxOnLink
		listed = listed[:MaxOnLink]
	}
	rd := &ReportDetected{OnLink: prefixStrings(listed), PublicOnLink: public, Routes: "unknown"}
	if det.RoutesKnown {
		rd.Routes, rd.DefaultV4, rd.DefaultV6 = "known", det.DefaultV4, det.DefaultV6
	}
	// Resolvers are named under the same rule: an address the local
	// policy does not let this sensor scan is internal topology the
	// platform has no use for.
	for _, a := range det.Resolvers {
		if kept, n := scope.trim([]netip.Prefix{netip.PrefixFrom(a, a.BitLen())}); n > 0 || len(kept) == 0 {
			r.Trimmed++
			continue
		}
		if len(rd.Resolvers) == MaxResolvers {
			r.Trimmed++
			continue
		}
		rd.Resolvers = append(rd.Resolvers, a.String())
	}
	search := det.SearchDomains
	if len(search) > MaxSearchDomains {
		search = search[:MaxSearchDomains]
	}
	rd.SearchDomains = append([]string(nil), search...)
	r.Detected = rd
	return r
}

func prefixStrings(ps []netip.Prefix) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// insideAny reports whether p lies inside one of ps.
func insideAny(ps []netip.Prefix, p netip.Prefix) bool {
	for _, d := range ps {
		if d.Addr().Is4() == p.Addr().Is4() && d.Bits() <= p.Bits() && d.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
