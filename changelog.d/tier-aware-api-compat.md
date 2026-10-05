### Documentation: every public package states its stability tier

- Each public package comment now ends with `Stability: <Tier>
  (docs/STABILITY.md).` (Stable, Beta, Frozen or Internal-bound; deprecated
  packages keep their `Deprecated:` paragraph), as `docs/STABILITY.md`
  lists them. The CI `api-compat` job weighs an incompatible change by that
  tier: Stable and Frozen fail unless the pull request is labelled
  `breaking-change` with an `### Upgrade notes` fragment, Beta warns,
  Internal-bound and Deprecated are listed only, and a package without a
  tier fails. A push to `main` reports against the latest release without
  failing (every change on `main` passed the gate as a pull request).
