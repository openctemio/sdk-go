package tool

import (
	"net"
	"net/netip"
	"strings"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// InferTargetType returns the CTIS 2.0 asset type of a target value that
// came without one (a scan command's plain target list): an http or https
// URL is a web_origin, an IP address an ip_address, a CIDR an ip_range,
// "host:port" or "host:port/transport" a service, a DNS name a domain_name.
// Anything else (a path, an image reference) has no inferred type and
// returns "".
func InferTargetType(value string) ctis.AssetType {
	v := strings.TrimSpace(value)
	switch {
	case v == "":
		return ""
	case strings.HasPrefix(strings.ToLower(v), "http://") || strings.HasPrefix(strings.ToLower(v), "https://"):
		if _, err := ctis.CanonicalOrigin(v); err == nil {
			return ctis.AssetTypeWebOrigin
		}
		return ""
	}
	if strings.Contains(v, "://") {
		return "" // a URL of another scheme
	}
	if _, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		return ctis.AssetTypeIPAddress
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return ctis.AssetTypeIPRange
	}
	if hp := serviceHostPort(v); hp != v || strings.Contains(v, ":") {
		if h, _, err := net.SplitHostPort(hp); err == nil && h != "" {
			return ctis.AssetTypeService
		}
		return ""
	}
	if _, err := ctis.CanonicalDomain(v); err == nil && strings.Contains(v, ".") && !strings.ContainsAny(v, "/ ") {
		return ctis.AssetTypeDomainName
	}
	return ""
}
