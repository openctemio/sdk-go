package ctis

import (
	"testing"
)

// NormalizeAssetName is the CTIS 2.0 canonical form of the type (the
// module's CanonicalAssetValue), or the trimmed input without one.
func TestNormalizeAssetName(t *testing.T) {
	tests := []struct {
		assetType AssetType
		input     string
		want      string
	}{
		{AssetTypeDomainName, "Example.COM", "example.com"},
		{AssetTypeDomainName, "example.com.", "example.com"},
		{AssetTypeDomainName, " API.Example.COM. ", "api.example.com"},
		{AssetTypeIPAddress, "192.168.1.1", "192.168.1.1"},
		{AssetTypeIPAddress, "2001:0db8::0001", "2001:db8::1"},
		{AssetTypeIPAddress, "::ffff:192.168.1.1", "192.168.1.1"},
		{AssetTypeIPRange, "10.1.2.3/8", "10.0.0.0/8"},
		{AssetTypeService, "Example.COM:443/TCP", "example.com:443/tcp"},
		{AssetTypeWebOrigin, "HTTPS://Example.COM:443/path", "https://example.com"},
		{AssetTypeRepository, "https://github.com/Org/Repo.git", "github.com/org/repo"},
		{"unknown", " something ", "something"},
		{AssetTypeDomainName, "  ", ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.assetType)+"/"+tt.input, func(t *testing.T) {
			got := NormalizeAssetName(tt.assetType, tt.input)
			if got != tt.want {
				t.Errorf("NormalizeAssetName(%s, %q) = %q, want %q", tt.assetType, tt.input, got, tt.want)
			}
			if got2 := NormalizeAssetName(tt.assetType, got); got2 != got {
				t.Errorf("not idempotent: NormalizeAssetName(%q) first=%q second=%q", tt.input, got, got2)
			}
		})
	}
}
