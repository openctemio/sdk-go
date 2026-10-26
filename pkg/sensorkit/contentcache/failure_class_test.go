package contentcache

import (
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// A content pack that cannot be delivered, does not verify or is revoked is
// reported as infra.content_unavailable (with the reason), and the sentinels
// still match with errors.Is.
func TestContentErrorsAreClassified(t *testing.T) {
	tests := []struct {
		err    error
		reason string
	}{
		{ErrUnavailable, ""},
		{ErrNotHeld, ""},
		{ErrTooLarge, ""},
		{ErrRevoked, core.ReasonContentRevoked},
		{ErrVerify, core.ReasonVerificationRefused},
		{ErrManifest, core.ReasonVerificationRefused},
		{ErrRevocationsUnknown, core.ReasonVerificationRefused},
		{ErrUnsupported, core.ReasonContentUnsupported},
	}
	for _, tt := range tests {
		wrapped := fmt.Errorf("task prep: %w: nuclei-templates", tt.err)
		if !errors.Is(wrapped, tt.err) {
			t.Fatalf("%v: errors.Is lost", tt.err)
		}
		f := core.ClassifyFailure(core.FailureInput{Err: wrapped, Stage: core.StageFetchContent})
		if f.Class != core.FailureContentUnavailable || f.Evidence.Reason != tt.reason || f.Evidence.Stage != core.StageFetchContent {
			t.Errorf("%v: %+v", tt.err, f)
		}
	}
}
