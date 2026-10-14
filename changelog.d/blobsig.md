### Added: offline sigstore signature check for downloaded content (pkg/blobsig)

- `blobsig.Verify` / `VerifyDigest` check a cosign keyless bundle (`cosign sign-blob --bundle`) for a file. The certificate must chain to the Sigstore public good Fulcio roots, the signature must have a Rekor inclusion proof and signed timestamp, and the certificate identity must equal the expected OIDC issuer and subject exactly. `blobsig.GitHubWorkflow(repo, workflow, ref)` builds the identity of a GitHub Actions release workflow.
- The trust root (`trusted_root.json`) is embedded, so verification needs no network. It is refreshed with SDK releases.
- New dependency: `github.com/sigstore/sigstore-go` v1.3.0.
