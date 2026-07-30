package ctis

import (
	"testing"
)

func TestNormalizeAssetName(t *testing.T) {
	tests := []struct {
		assetType AssetType
		input     string
		want      string
	}{
		// Domain
		{AssetTypeDomain, "Example.COM", "example.com"},
		{AssetTypeDomain, "example.com.", "example.com"},
		{AssetTypeDomain, " example.com ", "example.com"},

		// Subdomain
		{AssetTypeSubdomain, "API.Example.COM.", "api.example.com"},

		// IP
		{AssetTypeIPAddress, "192.168.1.1", "192.168.1.1"},
		{AssetTypeIPAddress, "2001:0db8::0001", "2001:db8::1"},
		{AssetTypeIPAddress, "::ffff:192.168.1.1", "192.168.1.1"},

		// Host
		{AssetTypeHost, "Web-Server-01", "web-server-01"},
		{AssetTypeHost, "192.168.1.10", "192.168.1.10"},
		{AssetTypeHost, "server.corp.local.", "server.corp.local"},

		// Repository
		{AssetTypeRepository, "https://github.com/Org/Repo", "github.com/org/repo"},
		{AssetTypeRepository, "git@github.com:Org/Repo.git", "github.com/org/repo"},
		{AssetTypeRepository, "github.com/Org/Repo.git", "github.com/org/repo"},
		{AssetTypeRepository, "org/repo", "org/repo"},

		// Unknown type: just trim
		{"unknown", " something ", "something"},

		// Empty
		{AssetTypeDomain, "", ""},
		{AssetTypeDomain, "  ", ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.assetType)+"/"+tt.input, func(t *testing.T) {
			got := NormalizeAssetName(tt.assetType, tt.input)
			if got != tt.want {
				t.Errorf("NormalizeAssetName(%s, %q) = %q, want %q", tt.assetType, tt.input, got, tt.want)
			}
			// Idempotency
			got2 := NormalizeAssetName(tt.assetType, got)
			if got2 != got {
				t.Errorf("not idempotent: NormalizeAssetName(%q) first=%q second=%q", tt.input, got, got2)
			}
		})
	}
}
