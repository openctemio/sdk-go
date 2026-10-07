package tool

import (
	"strings"
	"testing"
)

// A finding check (verify.finding@1) runs on the asset the finding is on:
// it may consume any asset type, unlike a capability whose inputs are
// assets of given types.
func TestVerifyFindingConsumesTheFindingsAssets(t *testing.T) {
	doc := `apiVersion: openctem.io/tool/v1
name: finding-check
version: 1.0.0
class: target-scan
tier: T1
implements:
- capability: verify.finding@1
consumes: [domain, ip_address, http_service, open_port]
produces: ['finding:vulnerability']
permissions: {network: targets}
`
	if _, err := LoadManifest([]byte(doc)); err != nil {
		t.Fatalf("a finding check that consumes the findings' assets: %v", err)
	}
	// Another capability still constrains consumes.
	bad := strings.Replace(doc, "verify.finding@1", "scan.ports@1", 1)
	bad = strings.Replace(bad, "['finding:vulnerability']", "['asset:open_port']", 1)
	if _, err := LoadManifest([]byte(bad)); err == nil || !strings.Contains(err.Error(), "not an input") {
		t.Fatalf("scan.ports@1 consuming http_service was accepted: %v", err)
	}
}
