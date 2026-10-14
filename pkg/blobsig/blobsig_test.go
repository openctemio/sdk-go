package blobsig

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A real cosign keyless bundle: the cosign v3.1.3 linux-amd64 release
// binary, signed by the Sigstore release identity. Verified offline with
// the embedded trust root.
var (
	cosignDigest, _ = hex.DecodeString("4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71")
	cosignSigner    = Signer{Issuer: "https://accounts.google.com", Subject: "keyless@projectsigstore.iam.gserviceaccount.com"}
)

func cosignBundle(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cosign-3.1.3-linux-amd64.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyDigest_RealBundle(t *testing.T) {
	if err := VerifyDigest(cosignDigest, cosignBundle(t), cosignSigner); err != nil {
		t.Fatalf("a valid bundle was refused: %v", err)
	}
}

// SECURITY: a valid signature by another identity, of another file, or a
// tampered bundle is refused.
func TestVerifyDigest_Refusals(t *testing.T) {
	b := cosignBundle(t)
	other := append([]byte(nil), cosignDigest...)
	other[0] ^= 0xff
	cases := map[string]struct {
		digest []byte
		bundle []byte
		signer Signer
		want   string
	}{
		"other file":       {other, b, cosignSigner, "digest"},
		"other subject":    {cosignDigest, b, Signer{cosignSigner.Issuer, "someone@example.com"}, "SAN"},
		"other issuer":     {cosignDigest, b, Signer{GitHubActionsIssuer, cosignSigner.Subject}, "issuer"},
		"workflow signer":  {cosignDigest, b, GitHubWorkflow("openctemio/sast-rules", ".github/workflows/release.yml", "refs/tags/v0.1.0"), ""},
		"no signer":        {cosignDigest, b, Signer{}, "issuer and a subject"},
		"empty bundle":     {cosignDigest, nil, cosignSigner, "empty"},
		"not a bundle":     {cosignDigest, []byte(`{"mediaType":"x"}`), cosignSigner, "bundle"},
		"tampered bundle":  {cosignDigest, tamper(t, b), cosignSigner, ""},
		"short digest":     {cosignDigest[:10], b, cosignSigner, "SHA-256"},
		"oversized bundle": {cosignDigest, make([]byte, MaxBundleBytes+1), cosignSigner, "larger"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyDigest(c.digest, c.bundle, c.signer)
			if err == nil {
				t.Fatal("accepted")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestVerify_ReadsTheArtifact(t *testing.T) {
	if err := Verify(strings.NewReader("not the cosign binary"), cosignBundle(t), cosignSigner); err == nil {
		t.Fatal("a bundle verified for content it does not sign")
	}
}

func TestGitHubWorkflow(t *testing.T) {
	s := GitHubWorkflow("openctemio/sast-rules", ".github/workflows/release.yml", "refs/tags/v1.2.3")
	if s.Issuer != GitHubActionsIssuer || s.Subject != "https://github.com/openctemio/sast-rules/.github/workflows/release.yml@refs/tags/v1.2.3" {
		t.Fatalf("%+v", s)
	}
}

// tamper flips one bit of the bundle's signature.
func tamper(t *testing.T, b []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ms := doc["messageSignature"].(map[string]any)
	sig, err := base64.StdEncoding.DecodeString(ms["signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)/2] ^= 1
	ms["signature"] = base64.StdEncoding.EncodeToString(sig)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
