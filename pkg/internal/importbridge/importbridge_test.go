package importbridge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

const leaks = `[{"RuleID": "aws-access-token", "Description": "AWS", "File": "a.env", "StartLine": 1, "Secret": "AKIAEXAMPLEEXAMPLE00", "Match": "k=AKIAEXAMPLEEXAMPLE00"}]`

const sarifProvenance = `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": [{"id": "r"}]}},
 "versionControlProvenance": [{"repositoryUri": "https://github.com/example/from-file"}],
 "results": [{"ruleId": "r", "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.go"}, "region": {"startLine": 3}}}]}]}]}`

func repo(v string) ctis.Asset {
	return ctis.Asset{ID: "asset-1", Type: ctis.AssetTypeRepository, Value: v, Properties: ctis.Properties{"branch": "main", "commit_sha": "abc"}}
}

// A code report never gets a made-up asset.
func TestConvert_NoAssetIsAnError(t *testing.T) {
	_, err := Convert(context.Background(), Request{Format: importer.FormatBetterleaks, Tool: "betterleaks", Input: []byte(leaks), NeedsAsset: true})
	if !errors.Is(err, ctis.ErrNoAssetForFindings) {
		t.Fatalf("err = %v, want ErrNoAssetForFindings", err)
	}
	// No finding, no asset needed.
	r, err := Convert(context.Background(), Request{Format: importer.FormatBetterleaks, Tool: "betterleaks", Input: []byte(`[]`), NeedsAsset: true})
	if err != nil || len(r.Assets) != 0 {
		t.Fatalf("empty report: %v %+v", err, r)
	}
}

// The caller's repository wins over the one the file names; the file's wins
// over the CI fallback.
func TestConvert_AssetOrder(t *testing.T) {
	r, err := Convert(context.Background(), Request{Format: importer.FormatSARIF, Tool: "sarif", Input: []byte(sarifProvenance), NeedsAsset: true,
		Asset: repo("github.com/example/caller"), Fallback: repo("github.com/example/ci")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 1 || r.Assets[0].Value != "github.com/example/caller" || r.Findings[0].AssetRef != r.Assets[0].ID {
		t.Fatalf("assets = %+v", r.Assets)
	}
	r, err = Convert(context.Background(), Request{Format: importer.FormatSARIF, Tool: "sarif", Input: []byte(sarifProvenance), NeedsAsset: true,
		Fallback: repo("github.com/example/ci")})
	if err != nil {
		t.Fatal(err)
	}
	if r.Assets[0].Value != "https://github.com/example/from-file" {
		t.Fatalf("asset = %+v", r.Assets[0])
	}
	r, err = Convert(context.Background(), Request{Format: importer.FormatBetterleaks, Tool: "betterleaks", Input: []byte(leaks), NeedsAsset: true,
		Fallback: repo("github.com/example/ci")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 1 || r.Assets[0].Value != "github.com/example/ci" || r.Findings[0].AssetRef != r.Assets[0].ID {
		t.Fatalf("assets = %+v", r.Assets)
	}
	for _, a := range r.Assets {
		if a.ID == noAsset || strings.Contains(a.Value, noAsset) {
			t.Fatal("the internal no-asset marker leaked into the report")
		}
	}
}

// A caller asset of another type replaces the asset of every finding.
func TestConvert_ExplicitNonRepository(t *testing.T) {
	img := ctis.Asset{Type: ctis.AssetTypeContainer, Value: "registry.example.com/app:1"}
	r, err := Convert(context.Background(), Request{Format: importer.FormatBetterleaks, Tool: "betterleaks", Input: []byte(leaks), NeedsAsset: true, Asset: img})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 1 || r.Assets[0].Type != ctis.AssetTypeContainer || r.Findings[0].AssetRef != r.Assets[0].ID {
		t.Fatalf("assets = %+v", r.Assets)
	}
}

func TestConvert_UnreadableAndHostile(t *testing.T) {
	if _, err := Convert(context.Background(), Request{Format: importer.FormatNuclei, Tool: "nuclei", Input: []byte("not json"), Unreadable: true}); err == nil {
		t.Fatal("unreadable nuclei input accepted")
	}
	deep := strings.Repeat("[", 10000) + strings.Repeat("]", 10000)
	if _, err := Convert(context.Background(), Request{Format: importer.FormatBetterleaks, Tool: "betterleaks", Input: []byte(deep), NeedsAsset: true}); !errors.Is(err, importer.ErrTooLarge) {
		t.Fatalf("deep input: %v", err)
	}
	if !Detect([]byte(`{"template-id": "x", "info": {"name": "n"}}`), importer.FormatNuclei) || Detect([]byte(`{}`), importer.FormatNuclei) {
		t.Fatal("Detect")
	}
}

// The raw secret never reaches the report.
func TestConvert_SecretMasked(t *testing.T) {
	r, err := Convert(context.Background(), Request{Format: importer.FormatBetterleaks, Tool: "betterleaks", Input: []byte(leaks), NeedsAsset: true, Asset: repo("github.com/example/app")})
	if err != nil {
		t.Fatal(err)
	}
	f := r.Findings[0]
	for _, s := range []string{f.Title, f.Description, f.Message, f.Fingerprint, f.Location.Snippet, f.Secret.MaskedValue} {
		if strings.Contains(s, "AKIAEXAMPLEEXAMPLE00") {
			t.Fatalf("raw secret in %q", s)
		}
	}
}
