### Added: signed `openctem` CLI binaries on each release, and `openctem version`

- Each release now attaches `openctem_<version>_<os>_<arch>.tar.gz` for linux and darwin on amd64 and arm64, a `SHA256SUMS` file and its keyless cosign bundle `SHA256SUMS.sigstore.json`, so authors of Python or shell tools no longer need the Go toolchain. Verification steps are in docs/tools/cli.md.
- `openctem version` (also `openctem --version` and `openctem tool version`) prints `openctem <version>`.

### Fixed: the tool and adapter JSON Schema `$id`s resolve

- `pkg/tool/schema/tool.v1.schema.json` and `adapter.v1.schema.json` now use their raw.githubusercontent.com URL as `$id`, so editors and validators can fetch them. Schemas that referenced the old `https://openctem.io/schema/...` ids must use the new ones.
