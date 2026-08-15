package nuclei

import (
	"strings"
	"testing"
)

func TestCheckDetectionTemplate_RejectsExcludedTags(t *testing.T) {
	// Every hard-excluded tag must be rejected even when a matcher is present.
	for _, tag := range []string{"dos", "fuzz", "fuzzing", "intrusive", "brute-force"} {
		if err := CheckDetectionTemplate([]string{"cve", tag}, true); err == nil {
			t.Errorf("tag %q: expected rejection, got nil", tag)
		}
	}
}

func TestCheckDetectionTemplate_ExcludedIsCaseInsensitive(t *testing.T) {
	for _, tag := range []string{"DOS", "Fuzz", "INTRUSIVE", "  dos  "} {
		if err := CheckDetectionTemplate([]string{tag}, true); err == nil {
			t.Errorf("tag %q: expected rejection (case/space-insensitive), got nil", tag)
		}
	}
}

func TestCheckDetectionTemplate_RejectsNoMatcher(t *testing.T) {
	if err := CheckDetectionTemplate([]string{"cve", "exposure"}, false); err == nil {
		t.Fatal("template without a matcher must be rejected")
	}
}

func TestCheckDetectionTemplate_AcceptsBenignDetection(t *testing.T) {
	cases := [][]string{
		{"cve"},
		{"exposure", "tech"},
		{"misconfig", "config"},
		{"takeover"},
		nil, // no tags but has a matcher: a detection template is allowed
	}
	for _, tags := range cases {
		if err := CheckDetectionTemplate(tags, true); err != nil {
			t.Errorf("tags %v: expected allow, got %v", tags, err)
		}
	}
}

func TestIsExcludedValidateTag(t *testing.T) {
	if !IsExcludedValidateTag("dos") || !IsExcludedValidateTag("Brute-Force") {
		t.Error("excluded tags not detected")
	}
	if IsExcludedValidateTag("cve") || IsExcludedValidateTag("exposure") {
		t.Error("benign tag wrongly flagged excluded")
	}
}

func TestBuildArgs_SingleTemplateID(t *testing.T) {
	s := NewScanner()
	s.IDs = []string{"CVE-2021-44228"}
	s.ExcludeTags = ValidateExcludedTags
	args := s.buildArgs("https://example.com", nil)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-id CVE-2021-44228") {
		t.Errorf("expected -id flag for single template, got: %s", joined)
	}
	if !strings.Contains(joined, "-etags dos,fuzz,fuzzing,intrusive,brute-force") {
		t.Errorf("expected -etags hard-exclude, got: %s", joined)
	}
	if !strings.Contains(joined, "-jsonl") {
		t.Errorf("expected -jsonl output, got: %s", joined)
	}
}
