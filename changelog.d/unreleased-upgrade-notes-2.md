### Upgrade notes

- **`pkg/ctis` is now `github.com/openctemio/ctis`.** It re-exports the
  module (type aliases, constants and wrapper functions generated from the
  version in go.mod) instead of keeping a hand copy. Code that only uses
  the CTIS types, constants, `NewReport`, `FromSARIF`, `ConvertReconToCTIS`
  and so on builds unchanged, and `pkg/ctis` and module values are now the
  same types. `SARIFLog` and `SARIFRun` stay SDK types (the module's plus
  `versionControlProvenance` and `SARIFRun.Repository()`); the nested SARIF
  types are the module's, so one detail breaks:
  - `SARIFResult.RuleIndex` is `*int` (was `int`), so index 0 is
    distinguishable from absent.
  apidiff reports every exported signature that mentions a `pkg/ctis` type
  as changed, because the named types now live in the module; source code
  using the same names is unaffected.
  The sensor builds unchanged (`sensor-compat`).
