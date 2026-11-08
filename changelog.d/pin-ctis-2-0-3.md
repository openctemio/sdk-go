### Changed: CTIS 2.0.3, the Nessus compliance ERROR state is kept

- `pkg/ctis` aliases are regenerated from `github.com/openctemio/ctis/v2` v2.0.3. A Nessus compliance result of ERROR (the check could not run) is kept as `compliance_outcome: error` instead of being folded into `skipped`.
