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
// allowed ranges. A name that fails that check is refused by the policy
// (denied_by_policy), as before.
//
// Every capability that connects to its targets keeps the fail-closed rule:
// a name whose addresses cannot be checked is never handed to its tool.

import (
	"encoding/json"
	"errors"
	"net"
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

// lookupOnlyRefusal is the refusal of a lookup-only job's target: err as the
// target check returned it, except that a name that does not resolve and,
// with targets.allow set, is not under an allowed domain is refused by the
// policy (rule targets.allow, reason denied_by_policy) instead of being
// reported as a name without an answer. Any other error stays as it is.
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
	return markTarget(RefusedTargetDenied, refuse("targets.allow", "%s does not resolve and is not under an allowed domain", name))
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
