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
3. Merge the release PR. **Release Tag** tags the merge commit, and the tag runs the release workflows. It then opens `deps: sdk-go vX.Y.Z` in openctemio/sensor and bumps `sdk.latest` in openctemio/openctem's `versions.yaml`.

### Nested modules

`pkg/transfer` (with `pkg/transfer/bundle`) is its own Go module, `github.com/openctemio/sdk-go/pkg/transfer`, so the platform and the feed publishers do not take the whole SDK's dependency graph. It is released on its own: **Actions › Release Module Tag › Run** with the module and a `vX.Y.Z` version tags `pkg/transfer/vX.Y.Z` on main (`.github/scripts/release/tag-module.sh` checks the version is greater than the module's last tag, the commit is on main, and its `go.mod` has the right module path and no `replace`). Its changes still add a `changelog.d/` fragment. The root `./...` does not reach a nested module, so CI runs its tests, build, vet, lint and govulncheck in its directory; run them there locally too (`cd pkg/transfer; go test ./...`).

`pkg/politeness` is a nested module the same way (`github.com/openctemio/sdk-go/pkg/politeness`, standard library only, tagged `pkg/politeness/vX.Y.Z` with the same workflow), because the platform imports it: the platform and the sensor must compute the same per-host keys. A change to its keys changes what the platform holds back, so it ships with a tag the platform then pins.

Do not tag by hand. Without the `RELEASE_TOKEN` secret (a fine-grained PAT with Contents, Pull requests and Workflows read/write), you open the PR yourself from the link in the run summary, and the cross-repository PRs are skipped.

## License

By contributing, you agree to license your contributions under Apache 2.0.
