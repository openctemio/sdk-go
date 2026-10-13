### Removed: the `github.com/openctemio/sdk-go/pkg/politeness` module

- The per-host politeness keys are part of the CTIS contract now: `github.com/openctemio/ctis/politeness`, with the same API and keys. The platform imports them from ctis, so it no longer depends on the SDK. The nested module was never tagged and nothing outside OpenCTEM imported it; import `github.com/openctemio/ctis/politeness` instead.

### Changed: the command poller takes its politeness keys from ctis

- `pkg/core` (the poller's per-host admission, and the deprecated `core.HostKey`) uses `github.com/openctemio/ctis/politeness`. The keys and the admission behaviour are unchanged.
