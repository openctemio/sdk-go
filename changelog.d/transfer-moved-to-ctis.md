### Removed: pkg/transfer moved to ctis

- The feed transfer module `github.com/openctemio/sdk-go/pkg/transfer` (`transfer`, `transfer/bundle`) moved unchanged to the contract module `github.com/openctemio/ctis/transfer`. Bundles are byte-identical (a golden test in ctis pins them to v0.1.0). The tag `pkg/transfer/v0.1.0` stays fetchable, so existing pins keep building.
- The module-tag workflow and script are removed with it: the SDK has no nested module left.

### Upgrade notes

- Replace the import path `github.com/openctemio/sdk-go/pkg/transfer` with `github.com/openctemio/ctis/transfer`; nothing else changes.
