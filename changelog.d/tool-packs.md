### Added: tool packs (pack.yaml) and pack support in `openctem tool`

- `pkg/tool/pack` reads `pack.yaml` (`openctem.io/pack/v1`, JSON Schema `pkg/tool/schema/pack.v1.schema.json`): the unit in which tools are versioned, built, signed and delivered. It lists the pack's tools, the third-party engines they bundle (version, license, a sha256 per platform), the platforms, the SDK and protocol the pack needs, and the base image of a pack image (pinned by digest).
- The pack's tier is checked, not trusted: it must equal the highest minimum tier of its tools (declared tier, capability tier floors, side effects), so a pack cannot label an active tool passive. Unlisted tools, unlisted engines, tool paths that leave the pack or pass through a symbolic link, and an SDK requirement below a tool's `sdk.min` are refused.
- `openctem tool validate|test|describe` work on a pack directory (every tool it lists); `openctem tool init` writes a one-tool `pack.yaml` next to the new tool.
- `examples/packs/http-title`: a Python pack for `probe.http@1`, tested in CI with the capability suite and the scope check.
- Spec: `docs/tool-packs.md`.
