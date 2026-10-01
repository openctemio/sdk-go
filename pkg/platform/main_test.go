package platform

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// TestMain permits loopback for this package's tests: the platform HTTP
// clients use httpsec's SSRF-guarded dialer, which hard-blocks 127.0.0.0/8,
// while the tests talk to httptest.NewServer on loopback. Production posture
// is unchanged.
func TestMain(m *testing.M) {
	httpsec.AllowLoopback = true
	os.Exit(m.Run())
}
