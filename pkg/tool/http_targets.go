package tool

import "strings"

// noHTTPCapabilities are the capabilities whose tools reach targets
// without HTTP (a port scan, host discovery, DNS lookups, subdomain
// enumeration, registry lookups): a task's identification is HTTP
// headers, so it does not apply to them.
var noHTTPCapabilities = map[string]bool{
	"scan.ports": true, "discover.hosts": true, "resolve.dns": true,
	"lookup.rdap": true, "lookup.asn": true, "discover.subdomains": true,
}

// SendsHTTPToTargets reports whether a task of the tool for capability
// (empty: a task that names none) may send HTTP requests to the task's
// targets, so must carry the job's identification (Task.Identity).
//
// Only a tool whose network class is targets reaches the targets: vendor
// APIs, the resolver, the egress proxy (registries, repositories,
// vulnerability databases, passive sources) and no network never send the
// tool's own requests to a program's targets. Of those, a task whose
// capability reaches targets without HTTP (scan.ports, resolve.dns, ...)
// does not either; a task naming no capability is judged by every
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
