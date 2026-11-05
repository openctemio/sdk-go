package core

// Lookup-only capabilities. A DNS resolution job asks the sensor's resolvers
// about its targets and never connects to them, so "the name does not
// resolve" is its answer, not a reason to refuse the job: such a name is
// reported per target (refused_targets reason unresolvable, with whether the
// name is gone or the lookup failed) and the job runs on the rest, or
// completes without running when nothing is left.
//
// The name is still checked: the domain deny list applies before any lookup
// (checkHost), and with targets.allow set the name must lie under an allowed
// domain, since a name without addresses cannot be matched against the
// allowed ranges. Such a name is still not looked up, but it is reported as
// what it is, a name that does not resolve (unresolvable, rule targets.allow):
// the policy did not deny it, there is nothing to match, and a retry on
// another sensor cannot change that. A name that resolves and falls outside
// the allowed ranges, or matches targets.deny, stays denied_by_policy.
//
// Every capability that connects to its targets keeps the fail-closed rule:
// a name whose addresses cannot be checked is never handed to its tool.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// lookupOnlyCapabilities are the capabilities whose tools only ask DNS about
// the targets. A job is lookup-only when its payload names one of them
// (ScanCommandPayload.Capability); a job that names none is treated as
// connecting (fail closed).
var lookupOnlyCapabilities = map[string]bool{"resolve.dns": true}

// LookupOnlyCapability reports whether capability ("resolve.dns" or
// "resolve.dns@1") only asks DNS about its targets and never connects to
// them.
func LookupOnlyCapability(capability string) bool {
	key, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(capability)), "@")
	return lookupOnlyCapabilities[key]
}

// payloadCapability is the capability a command payload names, or "".
func payloadCapability(payload []byte) string {
	var p struct {
		Capability string `json:"capability"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return ""
	}
	return p.Capability
}

// registryOnlyCapabilities are the capabilities whose tool asks a registry
// or another third party about a name and never connects to the target nor
// resolves it: the answer does not depend on the name having an address
// (RDAP answers for the registered domain at its registry, resolving or
// not). For these, a plain domain name is checked by name only (the domain
// deny list, and with targets.allow set the allowed domains) and is handed
// to the tool whether or not it resolves. A name outside the allowed domains
// still needs addresses inside the allowed ranges, so it is checked as for
// any other capability. An address, a range, a URL or a path is checked as
// ever.
var registryOnlyCapabilities = map[string]bool{"lookup.rdap": true}

// RegistryOnlyCapability reports whether capability ("lookup.rdap" or
// "lookup.rdap@1") only asks a registry about its targets: it never
// connects to them and never needs their addresses.
func RegistryOnlyCapability(capability string) bool {
	key, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(capability)), "@")
	return registryOnlyCapabilities[key]
}

// plainDomainName is target as a lower-case domain name when it is one: a
// dotted host name with no scheme, port, path, wildcard or address literal.
func plainDomainName(target string) (string, bool) {
	t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if t == "" || !strings.Contains(t, ".") || strings.ContainsAny(t, "/:@*[] \t") {
		return "", false
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return "", false
	}
	return t, true
}

// checkRegistryName is CheckTarget for a registry-only job: a plain domain
// name is checked by name, never resolved (see registryOnlyCapabilities).
// Anything else, a sensor that requires a local policy and has none, and a
// name outside the allowed domains go through CheckTarget.
func (lp *LocalPolicy) checkRegistryName(ctx context.Context, target string) error {
	name, ok := plainDomainName(target)
	if !ok || lp.failsClosed() {
		return lp.CheckTarget(ctx, target)
	}
	if lp.Present() {
		if d := lp.nameDenied(name); d != nil {
			return refuse("targets.deny", "%s matches %s", name, d)
		}
		if lp.targetsAllowSet && !lp.nameAllowed(name) {
			return lp.CheckTarget(ctx, target)
		}
	}
	return nil
}

// lookupOnlyRefusal is the refusal of a lookup-only job's target: err as the
// target check returned it. A name that does not resolve and, with
// targets.allow set, is not under an allowed domain is still not looked up,
// but keeps the reason unresolvable (with the lookup failure kind) and gains
// the rule targets.allow in its detail. Any other error stays as it is.
func (lp *LocalPolicy) lookupOnlyRefusal(target string, err error) error {
	var te *targetRefusalError
	if err == nil || !errors.As(err, &te) || te.reason != RefusedTargetUnresolvable {
		return err
	}
	if !lp.Present() || !lp.targetsAllowSet {
		return err
	}
	name := hostNameOf(target)
	if name != "" && lp.nameAllowed(name) {
		return err
	}
	return &targetRefusalError{reason: RefusedTargetUnresolvable, dns: te.dns,
		err: refuse("targets.allow", "%s does not resolve and is not under an allowed domain", name)}
}

// hostNameOf is the host of a target (a URL, host:port or host), lower case,
// without a trailing dot or brackets.
func hostNameOf(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil {
			t = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	t = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
	return strings.TrimSuffix(strings.ToLower(t), ".")
}
