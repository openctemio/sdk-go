# Contributing to OpenCTEM SDK

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone: `git clone https://github.com/YOUR_USERNAME/sdk-go.git`
3. Install Go 1.26+
4. Run tests: `go test ./...`
5. Create branch: `git checkout -b feature/your-feature`
6. Make changes
7. Commit and push
8. Open a Pull Request

## Code Style

- Use `gofmt` for formatting
- Follow Go best practices
- Write meaningful commit messages
- Add tests for new features
- Update documentation

## Adding a New Scanner

Tool wrappers live in the sensor (`github.com/openctemio/sensor/internal/scanners`),
not in the SDK; see [docs/STABILITY.md](docs/STABILITY.md). Implement
`core.Scanner` there and register it with `sensorkit.Kit.AddScanner`. Add
to the SDK only what every sensor needs (an interface, a runtime or safety
helper), with tests.

## Security-sensitive changes

A pull request that changes a path listed in
[`.github/security-paths.yml`](.github/security-paths.yml) (sensor identity and keys, job and template signatures, the sensor protocol and transports, the sensor-local policy, tool sandboxing and credentials, the SSRF guard, CI and images) is
labelled `security-sensitive` and gets an automated security review comment.
The `security-gate` check passes once a maintainer has reviewed it and added
the `security-ack` label, and no HIGH finding is open. Every other pull request,
including the release pull requests, passes the check at once.

- Contributors and automation never add `security-ack` themselves.
- New commits that change a sensitive file remove the ack; the maintainer acks
  again after reviewing them.
- A reviewed false positive of a diff rule is waived on its line with
  `security-review: allow <RULE-ID> <reason>`.
- Emergency override: an administrator may bypass the check; the bypass is in
  the organization audit log and is followed by a written reason on the pull
  request.

The gate is shared with `openctemio/openctem`; details in its
[CI guide](https://github.com/openctemio/openctem/blob/develop/api/docs/development/ci-cd.md#security-gate).

## Releasing

Versioning follows the project rule (openctemio/openctem RFC-037): the version is the `vX.Y.Z` tag on `main`, proposed from the conventional commits since the last tag. Before 1.0.0, a breaking change (`type!:` or `BREAKING CHANGE:`) or a `feat` bumps the minor; anything else bumps the patch.

1. Every PR that changes behaviour adds one file `changelog.d/<short-slug>.md` (see [`changelog.d/README.md`](changelog.d/README.md)); never edit the Unreleased section of `CHANGELOG.md`.
2. **Actions › Release Prepare › Run.** Start with `dry_run` (the default) to see the proposed version and changelog preview. Run it again with `dry_run` off to open `release/vX.Y.Z → main`: the `changelog.d/` fragments are folded into `CHANGELOG.md` as `vX.Y.Z` and `pkg/sdk.Version` is set. Fill `version` to override the proposal.
3. Merge the release PR. **Release Tag** tags the merge commit, and the tag runs the release workflows. It then opens `deps: sdk-go vX.Y.Z` in openctemio/sensor. The platform learns the release from openctem's signed release feed (openctemio/openctem RFC-037 §12), so nothing is opened there.

### Nested modules

The SDK is one Go module. Code that the platform also needs is a contract and belongs in ctis (the feed transfer moved there as `github.com/openctemio/ctis/transfer`), never in a nested module of the SDK that the platform imports.

## License

This repository is licensed under GPL-3.0 (see [LICENSE](LICENSE)). Contributions are accepted
under the Contributor License Agreement below.

## Contributor License Agreement

Every outside contribution is accepted under the OpenCTEM Contributor License
Agreement (CLA). It keeps your copyright with you and grants the project a
license that lets it offer OpenCTEM under its open source license and under
other terms (for example a commercial license). A summary is in
[CLA.md](CLA.md); the full texts are the
[Individual CLA](https://docs.openctem.io/legal/cla/) and the
[Corporate CLA](https://docs.openctem.io/legal/cla-corporate/).

### How to sign

1. Make sure the e-mail address of your commits is
   [added to your GitHub account](https://github.com/settings/emails). The
   check can only match commits that are linked to a GitHub account.
2. Open your pull request. If a commit author has not accepted the CLA yet,
   the `cla` check fails and comments on the pull request.
3. Read the agreement and post this comment on the pull request:

   ```text
   I have read the CLA Document and I hereby sign the CLA
   ```

   The check re-runs and passes. You sign once; the signature covers every
   repository of the `openctemio` organization and your earlier
   contributions. Post `recheck` to run the check again.
4. If you contribute as part of your job and your employer has rights in your
   work, your employer signs the [Corporate CLA](CLA-CORPORATE.md) as well.

The maintainer and the dependency bots are on the check's allowlist. A
maintainer who opens a pull request with someone else's commits makes sure
those authors have signed; the check also runs then for every commit linked
to another GitHub account.

### What is recorded

Your acceptance is recorded in a private repository that only the maintainer
can read: your GitHub username and numeric account id, the id and time of
your signing comment, and the repository and pull request where you signed.
No e-mail address is stored. The signing comment itself stays public on the
pull request. The record is kept for as long as the project distributes your
contribution, because it is the evidence of the license. To see or correct
your record, or to ask for its removal, write to info@openctem.io; anything
not needed as evidence of the license is removed.
