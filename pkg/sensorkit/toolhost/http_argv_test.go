package toolhost

import (
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// An exec tool passes its effective User-Agent to the program it wraps.
func TestExecUserAgentPlaceholder(t *testing.T) {
	m := tool.Manifest{Name: "acme-cli", Version: "1.4.0"}
	argv := []string{"acme", "-H", "User-Agent: {{http.user_agent}}"}
	got, ierr := expandArgv(argv, &prepared{m: m})
	if ierr != nil || !slices.Equal(got, []string{"acme", "-H", "User-Agent: openctem-acme-cli/1.4.0"}) {
		t.Fatalf("default: %q %v", got, ierr)
	}
	m.HTTP = &tool.HTTPSpec{UserAgent: "acme-scanner/2.0"}
	got, ierr = expandArgv(argv, &prepared{m: m})
	if ierr != nil || got[2] != "User-Agent: acme-scanner/2.0" {
		t.Fatalf("descriptor: %q %v", got, ierr)
	}
}
