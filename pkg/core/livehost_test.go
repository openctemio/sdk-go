package core

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// A probe result keeps what it learned about the server (TLS leaf, favicon,
// JARM, ASN, CDN type) through JSON, the shape recon results travel in.
func TestLiveHostServerFieldsRoundTrip(t *testing.T) {
	in := LiveHost{
		URL: "https://example.com", Host: "example.com", Scheme: "https", StatusCode: 200,
		CDN: "cloudflare", CDNType: "waf", FaviconMMH3: "-1840324437",
		JARM: "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
		ASN:  &ASN{Number: "AS13335", Org: "CLOUDFLARENET", Country: "US"},
		TLS: &TLSLeaf{
			SubjectCN: "example.com", SANs: []string{"example.com", "www.example.com"},
			IssuerCN: "R11", IssuerOrg: "Let's Encrypt", SerialNumber: "03a1",
			NotBefore:         time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:          time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC),
			FingerprintSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			Wildcard:          true,
		},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out LiveHost
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip lost fields:\n in  %+v\n out %+v", in, out)
	}

	// A plain HTTP result carries none of them.
	plain, _ := json.Marshal(LiveHost{URL: "http://example.com"})
	var m map[string]any
	_ = json.Unmarshal(plain, &m)
	for _, k := range []string{"tls", "asn", "jarm", "favicon_mmh3", "cdn_type"} {
		if _, ok := m[k]; ok {
			t.Errorf("empty %s is serialized", k)
		}
	}
}
