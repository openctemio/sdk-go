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

## Releasing

Versioning follows the project rule (openctemio/openctem RFC-037): the version is the `vX.Y.Z` tag on `main`, proposed from the conventional commits since the last tag. Before 1.0.0, a breaking change (`type!:` or `BREAKING CHANGE:`) or a `feat` bumps the minor; anything else bumps the patch.

1. Keep `CHANGELOG.md`'s Unreleased section current in every PR that changes behaviour.
2. **Actions › Release Prepare › Run.** Start with `dry_run` (the default) to see the proposed version and changelog preview. Run it again with `dry_run` off to open `release/vX.Y.Z → main`: the Unreleased section of `CHANGELOG.md` becomes `vX.Y.Z` and `pkg/sdk.Version` is set. Fill `version` to override the proposal.
3. Merge the release PR. **Release Tag** tags the merge commit, and the tag runs the release workflows. It then opens `deps: sdk-go vX.Y.Z` in openctemio/sensor and bumps `sdk.latest` in openctemio/openctem's `versions.yaml`.

Do not tag by hand. Without the `RELEASE_TOKEN` secret (a fine-grained PAT with Contents, Pull requests and Workflows read/write), you open the PR yourself from the link in the run summary, and the cross-repository PRs are skipped.

## License

By contributing, you agree to license your contributions under Apache 2.0.
