// Package absname makes a target name absolute (a trailing dot) for the
// SDK's own lookups. A resolver appends the host's search domains
// (resolv.conf "search", often set by DHCP and copied into containers) to a
// relative name that does not resolve: a lookup of "app.example.com" then
// also asks "app.example.com.lan". A target is looked up exactly as
// written, never with a suffix.
package absname

import (
	"net/netip"
	"strings"
)

// Of returns host as an absolute DNS name: host with a trailing dot. An
// address, an empty host and a name that is already absolute are returned
// unchanged.
func Of(host string) string {
	h := strings.Trim(host, "[]")
	if h == "" || strings.HasSuffix(h, ".") {
		return host
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return host
	}
	return h + "."
}
