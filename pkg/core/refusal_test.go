package core

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRefusalOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want *Refusal
	}{
		{"not a refusal", errors.New("nuclei exited 2"), nil},
		{"nil", nil, nil},
		{"local", refuse("tools.allow", "nuclei is not in tools.allow"), &Refusal{"local", "tools.allow", "nuclei is not in tools.allow"}},
		{"wrapped local", fmt.Errorf("scan: %w", refuse("allow_interactsh", "no")), &Refusal{"local", "allow_interactsh", "no"}},
		{"kill switch", refuse("kill_switch", "stopped by the sensor owner while running"), &Refusal{"local", "kill_switch", "stopped by the sensor owner while running"}},
		{"managed layer", &LocalPolicyError{Layer: RefusalLayerManaged, Rule: "pause", Detail: "paused"}, &Refusal{"managed", "pause", "paused"}},
		{"tool gate", fmt.Errorf("%w: nuclei is not allowed on this sensor by the platform's policy", ErrToolNotAllowed),
			&Refusal{"platform_tool_gate", "tools.allowed", "tool-not-allowed: nuclei is not allowed on this sensor by the platform's policy"}},
	} {
		got := RefusalOf(tc.err)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: RefusalOf = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// SECURITY (hostile input): a refusal never carries what the platform's
// sanitizer would reject or a terminal/log could misrender: unknown layers
// and malformed rules are replaced, control and bidi characters dropped,
// the detail bounded.
func TestRefusalOf_BoundsHostileValues(t *testing.T) {
	r := RefusalOf(&LocalPolicyError{Layer: "root", Rule: "Tools-Allow;rm -rf", Detail: "a\x1b[31mb\u202ec\n" + strings.Repeat("é", 1000)})
	if r.Layer != RefusalLayerLocal || r.Rule != "unknown" {
		t.Errorf("layer/rule = %q/%q", r.Layer, r.Rule)
	}
	if strings.ContainsAny(r.Detail, "\x1b\u202e\n") || len(r.Detail) > MaxRefusalDetail || !strings.HasPrefix(r.Detail, "a[31mbc") {
		t.Errorf("detail not cleaned: %q (%d bytes)", r.Detail[:20], len(r.Detail))
	}
	if r := RefusalOf(&LocalPolicyError{Rule: strings.Repeat("a", 65)}); r.Rule != "unknown" {
		t.Errorf("65-byte rule kept: %q", r.Rule)
	}
}
