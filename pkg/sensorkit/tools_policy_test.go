package sensorkit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
)

// The kit's policy hands the owner's http.headers to the tool host: without
// the method the host's type assertion silently drops them.
func TestKitPolicyExposesHTTPHeaders(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	path := filepath.Join(t.TempDir(), "sensor-policy.yaml")
	pol := "apiVersion: openctem.io/sensor-policy/v1\nhttp:\n  headers:\n    - {name: X-Test-Id, value: abc123}\n"
	if err := os.WriteFile(path, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, _, _ := baseOptions(t, f)
	opts.LocalPolicy = nil
	opts.LocalPolicyPath = path
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	hp, ok := any(kitPolicy{k}).(toolhost.HTTPHeaderPolicy)
	if !ok {
		t.Fatal("kitPolicy is not an HTTPHeaderPolicy")
	}
	hs := hp.HTTPHeaders()
	if len(hs) != 1 || hs[0].Name != "X-Test-Id" || hs[0].Value != "abc123" {
		t.Fatalf("headers = %+v", hs)
	}
}
