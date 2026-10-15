package tool

import "strings"

// noHTTPCapabilities are the capabilities that reach targets without HTTP
// by definition (a port scan, host discovery, DNS lookups): a task's
// identification is HTTP headers, so it does not apply to them on a
// target-reaching tool. A capability a target-reaching tool could serve
// over HTTP (subdomain discovery by virtual-host probing, a lookup) is
// not listed: its tasks carry the identification. Passive tools are
// exempt by their network class, never by a capability.
var noHTTPCapabilities = map[string]bool{
	"scan.ports": true, "discover.hosts": true, "resolve.dns": true,
}

// SendsHTTPToTargets reports whether a task of the tool for capability
// (empty: a task that names none) may send HTTP requests to the task's
// targets, so must carry the job's identification (Task.Identity).
//
// Only a tool whose network class is targets reaches the targets: vendor
// APIs, the resolver, the egress proxy (registries, repositories,
// vulnerability databases, passive sources) and no network never send the
// tool's own requests to a program's targets. Of those, a task whose
// capability reaches targets without HTTP (scan.ports, discover.hosts,
// resolve.dns) does not either; a task naming no capability is judged by every
// capability the tool implements. A target-reaching tool that implements
// nothing counts as sending HTTP (fail closed).
func (m Manifest) SendsHTTPToTargets(capability string) bool {
	if m.Normalized().Permissions.Network != NetTargets {
		return false
	}
	noHTTP := func(ref string) bool {
		key, _, _ := strings.Cut(strings.TrimSpace(ref), "@")
		return noHTTPCapabilities[key]
	}
	if strings.TrimSpace(capability) != "" {
		return !noHTTP(capability)
	}
	if len(m.Implements) == 0 {
		return true
	}
	for _, im := range m.Implements {
		if !noHTTP(im.Capability) {
			return true
		}
	}
	return false
}
