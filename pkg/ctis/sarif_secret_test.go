package ctis

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Fake credentials, assembled at run time so that no secret scanner flags the
// repository. awsKey matches gitleaks' aws-access-token rule.
var (
	awsKey      = "AKIA" + "IOSFODNN7EXAMPLF"
	shortSecret = "hunter2" + "pass"
)

// testdata/sarif/gitleaks-unredacted.sarif is real gitleaks 8 SARIF output
// (run without --redact), shared byte-for-byte with ctis, with the matched
// secret restored into region.snippet as gitleaks writes it.
func unredactedGitleaks(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/sarif/gitleaks-unredacted.sarif")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "{{SECRET}}", awsKey)
	s = strings.ReplaceAll(s, "{{SHORT}}", shortSecret)
	return []byte(s)
}

// Secret scanners put the raw secret in the SARIF snippet; FromSARIF copied it
// into location.snippet, so the live credential was in the CTIS report.
func TestFromSARIF_SecretSnippetIsMasked(t *testing.T) {
	opts := DefaultConvertOptions()
	opts.AssetValue = "github.com/example/shop"
	report, err := FromSARIF(unredactedGitleaks(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{awsKey, shortSecret} {
		if strings.Contains(string(out), raw) {
			t.Errorf("raw secret %q is in the CTIS report:\n%s", raw, out)
		}
	}
	if len(report.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(report.Findings))
	}
	for i, want := range []string{"AKIA********", "REDACTED"} {
		f := report.Findings[i]
		if got := f.Location.Snippet; got != want {
			t.Errorf("finding %d snippet = %q, want %q", i, got, want)
		}
		if f.Secret != nil {
			t.Errorf("finding %d: secret block set; masked_value changes receiver fingerprints", i)
		}
	}
	if got := report.Findings[1].Title; strings.Contains(got, shortSecret) {
		t.Errorf("title = %q, want the secret masked", got)
	}
}

func TestFromSARIF_SecretRedactionCases(t *testing.T) {
	cases := []struct {
		name, tool, toolType, snippet, want string
	}{
		{"already redacted", "gitleaks", "", "REDACTED", "REDACTED"},
		{"asterisks", "gitleaks", "", "****************", "****************"},
		{"partial redaction is masked again", "gitleaks", "", "AKIAIOSFODNN...", "REDACTED"},
		{"long secret keeps a prefix", "betterleaks", "", awsKey, "AKIA********"},
		{"short secret is hidden", "gitleaks", "", shortSecret, "REDACTED"},
		{"secret tool under a sast override", "gitleaks", "sast", awsKey, "AKIA********"},
		{"ToolType secret", "acme-scanner", "secret", awsKey, "AKIA********"},
		{"code finding is untouched", "semgrep", "", "x := os.Getenv(\"X\")", "x := os.Getenv(\"X\")"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snippet, _ := json.Marshal(tc.snippet)
			log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tc.tool + `","rules":[{"id":"r"}]}},
			  "results":[{"ruleId":"r","message":{"text":"m"},
			    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":` + string(snippet) + `}}}}]}]}]}`
			opts := DefaultConvertOptions()
			opts.AssetValue = "github.com/example/shop"
			opts.ToolType = tc.toolType
			report, err := FromSARIF([]byte(log), opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := report.Findings[0].Location.Snippet; got != tc.want {
				t.Errorf("snippet = %q, want %q", got, tc.want)
			}
		})
	}
}
