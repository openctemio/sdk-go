package reach

import (
	"errors"
	"net"
	"strings"
	"syscall"
)

// DNSKind refines DNSFailure: whether the name is gone, or the lookup itself
// failed. The two are different facts. A name that no longer exists (NXDOMAIN,
// or NODATA: the name exists with no address) is a fact about the asset; a
// resolver that failed (SERVFAIL, REFUSED, a timeout) says nothing about the
// asset and may be the sensor's own DNS.
type DNSKind string

// DNS kinds.
const (
	// DNSNone: not a DNS failure.
	DNSNone DNSKind = ""
	// NameGone: the resolver answered that the name has no addresses
	// (NXDOMAIN or NODATA). A sensor sees only its resolver's answer; the
	// platform confirms it with its own before acting on it.
	NameGone DNSKind = "name_gone"
	// ResolverFailed: the lookup failed (SERVFAIL, REFUSED, a resolver
	// timeout, no resolver reachable). Ambiguous, and charged to the sensor
	// when its control resolver check fails too.
	ResolverFailed DNSKind = "resolver_failed"
)

// ClassifyDNS tells, for an error from a lookup of a target's name, whether
// the name is gone or the lookup failed. A nil error and an error that is not
// a lookup failure give DNSNone.
func ClassifyDNS(err error) DNSKind {
	if err == nil {
		return DNSNone
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout || dnsErr.IsTemporary:
			return ResolverFailed
		case dnsErr.IsNotFound:
			return NameGone
		}
		if k := ClassifyDNSText(dnsErr.Err); k != DNSNone {
			return k
		}
		return ResolverFailed
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno { //nolint:exhaustive // syscall.Errno is not an enum
		case wsaHOSTNOTFOUND, wsaNODATA:
			return NameGone
		case wsaTRYAGAIN, wsaNORECOVERY:
			return ResolverFailed
		}
	}
	return ClassifyDNSText(err.Error())
}

// ClassifyDNSText maps a lookup failure message (a tool's text, a wrapped
// error that lost its type) to its kind; DNSNone when it is not one. A
// message that names a DNS failure without saying which is ResolverFailed:
// the safe reading, since it does not claim the name is gone.
func ClassifyDNSText(msg string) DNSKind {
	lower := strings.ToLower(msg)
	if lower == "" {
		return DNSNone
	}
	// Resolver failures first: "temporary failure in name resolution" and
	// "server misbehaving" also contain words a looser match would read as
	// "name not found".
	for _, n := range []string{
		"servfail", "server misbehaving", "temporary failure", "try again", "query refused",
		"lookup timed out", "i/o timeout", "no servers could be reached", "connection timed out",
	} {
		if strings.Contains(lower, n) {
			return ResolverFailed
		}
	}
	for _, n := range []string{
		"nxdomain", "no such host", "no address associated with hostname", "name or service not known",
		"nodata", "non-existent domain", "host not found",
	} {
		if strings.Contains(lower, n) {
			return NameGone
		}
	}
	if ClassifyText(lower) == DNSFailure {
		return ResolverFailed
	}
	return DNSNone
}
