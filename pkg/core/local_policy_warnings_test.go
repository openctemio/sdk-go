package core

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// The default (not required) has no warning; the required-absent warning is
// plain, once, with the fix, and cites no internal document.
func TestAbsentWarningsPlain(t *testing.T) {
	if w := absentWarnings(false); len(w) != 0 {
		t.Fatalf("the default mode must not warn: %v", w)
	}
	w := absentWarnings(true)
	if len(w) != 1 {
		t.Fatalf("want one warning, got %d: %v", len(w), w)
	}
	if !strings.Contains(w[0], LocalPolicyRuleNoPolicy) || !strings.Contains(w[0], DefaultLocalPolicyPath) {
		t.Fatalf("warning: %s", w[0])
	}
	if regexp.MustCompile(`RFC|research/|\(Q\d`).MatchString(w[0]) {
		t.Fatalf("internal reference in warning: %s", w[0])
	}
	if strings.Count(w[0], DefaultLocalPolicyPath) != 1 {
		t.Fatalf("advice repeated: %s", w[0])
	}
}

// Optional, narrow-only: with no policy a public target outside the deny list
// is admitted (the platform's signed scope decides); required fails closed; an
// explicit empty targets.allow still allows nothing, and a file without
// targets.allow reports -1 while an explicit empty list reports 0.
func TestLocalPolicyOptionalNarrowOnly(t *testing.T) {
	ctx := context.Background()
	if err := absentPolicy().CheckTarget(ctx, "203.0.113.9"); err != nil {
		t.Fatalf("absent and not required must follow the platform scope: %v", err)
	}
	if err := absentPolicy().WithRequired(true).CheckTarget(ctx, "203.0.113.9"); !isRule(err, LocalPolicyRuleNoPolicy) {
		t.Fatalf("required and absent must fail closed: %v", err)
	}
	empty := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: []}\n")
	if err := empty.CheckTarget(ctx, "203.0.113.9"); !isRule(err, "targets.allow") {
		t.Fatalf("explicit empty allow must refuse every target: %v", err)
	}
	if n := empty.Report().Summary.TargetsAllow; n != 0 {
		t.Fatalf("explicit empty list reports %d, want 0", n)
	}
	none := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\n")
	if n := none.Report().Summary.TargetsAllow; n != -1 {
		t.Fatalf("no allow list reports %d, want -1", n)
	}
	if err := none.CheckTarget(ctx, "203.0.113.9"); err != nil {
		t.Fatalf("a file without targets.allow narrows nothing: %v", err)
	}
	narrow := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [198.51.100.0/24]}\n")
	if err := narrow.CheckTarget(ctx, "203.0.113.9"); !isRule(err, "targets.allow") {
		t.Fatalf("a policy must narrow: %v", err)
	}
}
