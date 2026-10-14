// Package blobsig verifies a sigstore (cosign keyless) signature of a
// downloaded file, offline: the certificate chains to the Sigstore public
// good Fulcio roots, the signature is in the Rekor transparency log (the
// inclusion proof and signed timestamp travel in the bundle), and the
// certificate names exactly the signer the caller expects (OIDC issuer and
// subject, for a GitHub workflow its file and ref).
//
// Sensors use it before they install content that runs on tenant code (the
// sast-rules bundle, for example): a mirror, a proxy or a compromised
// download host cannot substitute files, because only the expected release
// workflow can produce a valid bundle.
//
// The trust root (trusted_root.json, the Sigstore public good instance's
// Fulcio CAs, Rekor and CT log keys) is embedded and refreshed with SDK
// releases, so verification needs no network.
package blobsig

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// GitHubActionsIssuer is the OIDC issuer of GitHub Actions workflow
// identities.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// MaxBundleBytes bounds a bundle a caller reads before Verify.
const MaxBundleBytes = 1 << 20

//go:embed trusted_root.json
var publicGoodRoot []byte

var (
	rootOnce sync.Once
	rootVal  *root.TrustedRoot
	rootErr  error
)

func trustedRoot() (*root.TrustedRoot, error) {
	rootOnce.Do(func() { rootVal, rootErr = root.NewTrustedRootFromJSON(publicGoodRoot) })
	return rootVal, rootErr
}

// Signer is the identity a signature must carry: the certificate's OIDC
// issuer and its subject (SAN), both compared exactly.
type Signer struct {
	Issuer  string
	Subject string
}

// GitHubWorkflow is the signer identity of a GitHub Actions workflow run:
// https://github.com/<repo>/<workflowPath>@<ref>, for example
// GitHubWorkflow("openctemio/sast-rules", ".github/workflows/release.yml", "refs/tags/v0.1.0").
func GitHubWorkflow(repo, workflowPath, ref string) Signer {
	return Signer{Issuer: GitHubActionsIssuer, Subject: "https://github.com/" + repo + "/" + workflowPath + "@" + ref}
}

func (s Signer) valid() error {
	if strings.TrimSpace(s.Issuer) == "" || strings.TrimSpace(s.Subject) == "" {
		return errors.New("blobsig: the expected signer needs an issuer and a subject")
	}
	return nil
}

// Verify checks bundleJSON, a sigstore bundle (cosign sign-blob --bundle),
// as the signature of the content read from artifact, made by want.
func Verify(artifact io.Reader, bundleJSON []byte, want Signer) error {
	h := sha256.New()
	if _, err := io.Copy(h, artifact); err != nil {
		return fmt.Errorf("blobsig: read the artifact: %w", err)
	}
	return VerifyDigest(h.Sum(nil), bundleJSON, want)
}

// VerifyDigest is Verify for an artifact the caller already hashed (SHA-256).
func VerifyDigest(sha256Digest, bundleJSON []byte, want Signer) error {
	if err := want.valid(); err != nil {
		return err
	}
	if len(sha256Digest) != sha256.Size {
		return errors.New("blobsig: the artifact digest is not SHA-256")
	}
	if len(bundleJSON) == 0 || len(bundleJSON) > MaxBundleBytes {
		return fmt.Errorf("blobsig: bundle is empty or larger than %d bytes", MaxBundleBytes)
	}
	tr, err := trustedRoot()
	if err != nil {
		return fmt.Errorf("blobsig: trust root: %w", err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("blobsig: bundle: %w", err)
	}
	// One transparency-log entry with its integrated (signed) timestamp:
	// the certificate was valid when the log recorded the signature.
	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return fmt.Errorf("blobsig: verifier: %w", err)
	}
	id, err := verify.NewShortCertificateIdentity(want.Issuer, "", want.Subject, "")
	if err != nil {
		return fmt.Errorf("blobsig: signer: %w", err)
	}
	if _, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", sha256Digest), verify.WithCertificateIdentity(id))); err != nil {
		return fmt.Errorf("blobsig: %w", err)
	}
	return nil
}
