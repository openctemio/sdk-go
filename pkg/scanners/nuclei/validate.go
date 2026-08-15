package nuclei

import (
	"fmt"
	"strings"
)

// Re-verification safety (RFC-011.2 §2 — validation executor, "nuclei" rung).
//
// Automated re-verification re-runs a finding's own detection template against
// its asset to prove the exposure condition still exists (confirm) or no longer
// does (downgrade). It is NON-DESTRUCTIVE proof-of-exposure, never exploitation:
// only detection/matcher templates may run, and templates carrying a dangerous
// tag are hard-excluded regardless of what a job asks for.

// ValidateExcludedTags is the hard-exclude allowlist for re-verification. A
// nuclei template carrying any of these tags must NEVER run during automated
// validation — they are destructive, noisy, or exploit-shaped rather than a
// non-destructive detection. Passed to nuclei as `-etags` (engine-level hard
// exclude, where exclude wins over an `-id` include) and enforced again in Go by
// CheckDetectionTemplate as defense-in-depth.
var ValidateExcludedTags = []string{
	"dos",
	"fuzz",
	"fuzzing",
	"intrusive",
	"brute-force",
}

// IsExcludedValidateTag reports whether tag is on the re-verification
// hard-exclude list (case-insensitive, whitespace-trimmed).
func IsExcludedValidateTag(tag string) bool {
	t := strings.ToLower(strings.TrimSpace(tag))
	for _, ex := range ValidateExcludedTags {
		if t == ex {
			return true
		}
	}
	return false
}

// CheckDetectionTemplate enforces the re-verification allowlist over a single
// nuclei template's metadata. A template is safe to re-run only when it is a
// detection/matcher template (hasMatcher) AND carries no excluded tag.
//
// It returns a descriptive error — naming the offending tag, or the missing
// matcher — so the caller REJECTS the job with an error outcome rather than
// silently skipping it. A nil return means the template is allowed.
func CheckDetectionTemplate(tags []string, hasMatcher bool) error {
	for _, tag := range tags {
		if IsExcludedValidateTag(tag) {
			return fmt.Errorf("nuclei template tag %q is excluded from re-verification (detection templates only, no dos/fuzz/intrusive/brute-force)", strings.TrimSpace(tag))
		}
	}
	if !hasMatcher {
		return fmt.Errorf("nuclei template has no matcher; only detection/matcher templates may run during re-verification")
	}
	return nil
}
