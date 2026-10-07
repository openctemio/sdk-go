### Security: a secret scanner's raw match no longer survives in the title or other fields

- The adapters (`betterleaks`, `sarif`, `trivy`), `core.SARIFParser` and `importtool` run on `github.com/openctemio/ctis` with `RedactSecretFinding`. A secret that a scanner repeats in its message, description, commit message, tags or properties is masked there too, not only in the snippet. Before, a SARIF snippet holding the whole code line, or a leak record with only a match line, left the bare secret in the finding title.
- The tool runtime's output rules (`internal/toolrt`, applied on both sides of the process boundary) mask any secret finding whose snippet or masked value a tool left unmasked, and the same value wherever another field repeats it.
- `pkg/ctis` re-exports `RedactSecretFinding` and `ContainsSecret`.

### Changed

- The pinned ctis module locates Nessus host-level results on their host: `importtool` output for `.nessus` now carries `network` on port-0 results.
