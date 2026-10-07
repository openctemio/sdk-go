package adapters_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapters/betterleaks" //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/adapters/sarif"       //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/adapters/trivy"       //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// A secret that a scanner repeats in its message, description or commit
// message reaches no field of the CTIS report unmasked, whichever adapter
// or parser converts it. The fake credentials are assembled at run time so
// that no secret scanner flags this repository.
var (
	fakeKey   = "AKIA" + "Q3EGRZ7X2MNVBP4L"
	fakeToken = "ghp_" + "9fK2xLq7RzT4mWv8Np3Yb6Hc"
)

func assertNoRawSecret(t *testing.T, r *ctis.Report, err error, secrets ...string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("no findings")
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Fatalf("raw secret %q is in the CTIS report:\n%s", s, out)
		}
	}
}

func secretSARIF(driver string) []byte {
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + driver + `","rules":[{"id":"aws-access-token","shortDescription":{"text":"AWS key ` + fakeKey + `"}}]}},
	  "results":[{"ruleId":"aws-access-token","message":{"text":"aws-access-token found ` + fakeKey + `"},
	    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"config.py"},"region":{"startLine":3,"snippet":{"text":"aws_key = \"` + fakeKey + `\""}}}}]}]}]}`)
}

func TestSecretMaskedEverywhere_SARIFAdapter(t *testing.T) {
	for _, driver := range []string{"betterleaks", "gitleaks", "trufflehog"} {
		t.Run(driver, func(t *testing.T) {
			r, err := sarif.NewAdapter().Convert(context.Background(), secretSARIF(driver), repo)
			assertNoRawSecret(t, r, err, fakeKey)
		})
	}
}

func TestSecretMaskedEverywhere_SARIFParser(t *testing.T) {
	r, err := (&core.SARIFParser{}).Parse(context.Background(), secretSARIF("betterleaks"), &core.ParseOptions{AssetValue: "github.com/example/shop"})
	assertNoRawSecret(t, r, err, fakeKey)
}

func TestSecretMaskedEverywhere_BetterleaksAdapter(t *testing.T) {
	// Only the match line is reported; the description and the commit
	// message repeat the bare token.
	in := []byte(`[{"Description":"GitHub token ` + fakeToken + `","RuleID":"github-pat","File":"ci.yml","StartLine":4,
	  "Match":"token: ` + fakeToken + `","Secret":"","Message":"add ` + fakeToken + `","Commit":"abc"}]`)
	r, err := betterleaks.NewAdapter().Convert(context.Background(), in, repo)
	assertNoRawSecret(t, r, err, fakeToken)
}

func TestSecretMaskedEverywhere_TrivyAdapter(t *testing.T) {
	in := []byte(`{"SchemaVersion":2,"ArtifactName":"github.com/example/shop","ArtifactType":"repository","Results":[{"Target":"config.py","Class":"secret",
	  "Secrets":[{"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key ` + fakeKey + `","StartLine":2,"EndLine":2,"Match":"key = ` + fakeKey + `"}]}]}`)
	r, err := trivy.NewAdapter().Convert(context.Background(), in, repo)
	assertNoRawSecret(t, r, err, fakeKey)
}
