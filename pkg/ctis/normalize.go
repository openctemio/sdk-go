package ctis

import (
	"net"
	"strings"
)

// NormalizeAssetName normalizes an asset name for the given type.
// This is a lightweight implementation for defense-in-depth.
// The API server re-normalizes authoritatively before storage.
//
// Part of RFC-001: Asset Identity Resolution.
func NormalizeAssetName(assetType AssetType, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	switch assetType {
	case AssetTypeDomain, AssetTypeSubdomain:
		name = strings.ToLower(name)
		name = strings.TrimRight(name, ".")
		return name

	case AssetTypeIPAddress:
		if ip := net.ParseIP(name); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
			return ip.String()
		}
		return name

	case AssetTypeHost:
		// If IP, normalize as IP
		if ip := net.ParseIP(name); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
			return ip.String()
		}
		// Otherwise lowercase hostname
		name = strings.ToLower(name)
		name = strings.TrimRight(name, ".")
		return name

	case AssetTypeRepository:
		name = strings.TrimPrefix(name, "https://")
		name = strings.TrimPrefix(name, "http://")
		if strings.HasPrefix(name, "git@") {
			name = strings.TrimPrefix(name, "git@")
			if idx := strings.Index(name, ":"); idx > 0 {
				name = name[:idx] + "/" + name[idx+1:]
			}
		}
		name = strings.TrimSuffix(name, ".git")
		name = strings.ToLower(name)
		name = strings.TrimRight(name, "/")
		return name

	case AssetTypeHTTPService, AssetTypeDiscoveredURL:
		// Lightweight URL normalize: lowercase host
		name = strings.ToLower(name)
		name = strings.TrimRight(name, "/")
		return name

	default:
		return name
	}
}
