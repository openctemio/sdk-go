package ctis

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Mirrors github.com/openctemio/ctis#12 (same sample,
// testdata/sarif/betterleaks.sarif, and the same expectations).

func readBetterleaksSARIF(t *testing.T) *Report {
	t.Helper()
	data, err := os.ReadFile("testdata/sarif/betterleaks.sarif")
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultConvertOptions()
	opts.AssetValue = "github.com/example/shop"
	report, err := FromSARIF(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// SARIF properties.tags (on the result and on its rule) are carried into
// finding.tags. FromSARIF used to drop them.
func TestFromSARIF_TagsFromResultAndRule(t *testing.T) {
	report := readBetterleaksSARIF(t)
	if len(report.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(report.Findings))
	}
	// Result tags first, then rule tags; trimmed; duplicates dropped ignoring
	// case with the first spelling kept; "", 42, null and {} skipped.
	want := [][]string{
		{"key", "verified", "cloud", "aws"},
		{"entropy"}, // a string tags value is one tag
	}
	for i, w := range want {
		if got := report.Findings[i].Tags; !reflect.DeepEqual(got, w) {
			t.Errorf("finding %d tags = %q, want %q", i, got, w)
		}
	}
}

func TestFromSARIF_NoTagsLeavesFieldUnset(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[{` + sarifSyncRepo + `"tool":{"driver":{"name":"x","rules":[{"id":"r","properties":{"tags":[1,true,""]}}]}},
	  "results":[{"ruleId":"r","message":{"text":"m"}},{"ruleId":"other","message":{"text":"n"},"properties":{"tags":{"a":"b"}}}]}]}`)
	report, err := FromSARIF(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range report.Findings {
		if f.Tags != nil {
			t.Errorf("finding %d: tags = %q, want unset", i, f.Tags)
		}
	}
	b, err := json.Marshal(report.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"tags"`) {
		t.Errorf("empty tags are serialized: %s", b)
	}
}

// A hostile log must not inflate findings: the tag count and each tag's
// length are capped, and non-string entries are ignored.
func TestFromSARIF_TagsHostileInput(t *testing.T) {
	tags := make([]any, 0, 100_002)
	tags = append(tags, strings.Repeat("A", maxSARIFTagLen+1)) // over-long: dropped
	tags = append(tags, strings.Repeat("b", maxSARIFTagLen))   // at the limit: kept
	for i := 0; i < 100_000; i++ {
		if i%2 == 0 {
			tags = append(tags, fmt.Sprintf("tag-%d", i))
		} else {
			tags = append(tags, map[string]any{"n": i})
		}
	}
	ruleTags := make([]any, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		ruleTags = append(ruleTags, "dup") // one distinct value, repeated
	}
	log, err := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"versionControlProvenance": []any{map[string]any{"repositoryUri": "https://github.com/example/shop"}},
			"tool": map[string]any{"driver": map[string]any{"name": "x", "rules": []any{
				map[string]any{"id": "r", "properties": map[string]any{"tags": ruleTags}},
			}}},
			"results": []any{
				map[string]any{"ruleId": "r", "message": map[string]any{"text": "m"}, "properties": map[string]any{"tags": tags}},
				map[string]any{"ruleId": "r", "message": map[string]any{"text": "n"}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := FromSARIF(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := report.Findings[0].Tags
	if len(got) != maxSARIFTags {
		t.Fatalf("got %d tags, want the cap %d", len(got), maxSARIFTags)
	}
	if got[0] != strings.Repeat("b", maxSARIFTagLen) || got[1] != "tag-0" || got[2] != "tag-2" {
		t.Errorf("first tags = %q, want the at-limit tag then tag-0, tag-2", got[:3])
	}
	for _, s := range got {
		if len(s) > maxSARIFTagLen {
			t.Errorf("tag of %d bytes kept, cap is %d", len(s), maxSARIFTagLen)
		}
	}
	if second := report.Findings[1].Tags; !reflect.DeepEqual(second, []string{"dup"}) {
		t.Errorf("repeated rule tag: got %q, want [dup]", second)
	}
}

// betterleaks is a gitleaks fork. Its SARIF driver name must classify the
// same way: secret findings from a secret-capability tool.
func TestFromSARIF_SecretToolsClassifyAsSecret(t *testing.T) {
	for _, name := range []string{"gitleaks", "betterleaks", "Betterleaks", "betterleaks v1.1.0", "trufflehog", "detect-secrets"} {
		log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + name + `"}},
		  "results":[{"ruleId":"generic-api-key","message":{"text":"m"}}]}]}`)
		r, err := FromSARIF(log, &ConvertOptions{AssetValue: "github.com/example/shop"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Findings[0].Type != FindingTypeSecret {
			t.Errorf("%s: finding type = %s, want secret", name, r.Findings[0].Type)
		}
		if !reflect.DeepEqual(r.Tool.Capabilities, []string{"secret"}) {
			t.Errorf("%s: capabilities = %q, want [secret]", name, r.Tool.Capabilities)
		}
	}
	report := readBetterleaksSARIF(t)
	for i, f := range report.Findings {
		if f.Type != FindingTypeSecret {
			t.Errorf("finding %d type = %s, want secret", i, f.Type)
		}
	}
}

// The module caps tags per finding (spec 6.1); the values are unexported
// there, so the test names them.
const (
	maxSARIFTags   = 50
	maxSARIFTagLen = 128
)
