### Upgrade notes: `pkg/transfer` is its own Go module

- `pkg/transfer` and `pkg/transfer/bundle` moved into a nested module, `github.com/openctemio/sdk-go/pkg/transfer`, released as `pkg/transfer/vX.Y.Z` (first: `pkg/transfer/v0.1.0`). Import paths are unchanged.
- A consumer requires `github.com/openctemio/sdk-go/pkg/transfer` instead of `github.com/openctemio/sdk-go`. A build that requires both the new module and an `sdk-go` version that still contains `pkg/transfer` (v0.19.0 and earlier) fails with "ambiguous import": drop the `sdk-go` require, or require an `sdk-go` release made after this change.
- `transfer.New` now refuses a URL origin without `Config.Client`; there is no unguarded default client. Pass an SSRF-guarded client such as `httpsec.SafeHTTPClient(0)`. A fetcher with local (directory) origins only needs no client.

### Changed: the transfer module depends on the standard library and the Prometheus client only

- The DSSE envelope, pre-authentication encoding and key id are restated in `pkg/transfer/bundle`, byte-identical to `pkg/jobsig`; one golden vector in both test suites keeps them together. Envelopes signed before and after this change verify the same way.
- CI runs tests, build, vet, `go mod tidy -diff`, golangci-lint and govulncheck for the nested module; **Release Module Tag** (`.github/scripts/release/tag-module.sh`) tags it.
