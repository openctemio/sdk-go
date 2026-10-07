### Added: tools declare the capabilities they implement (tool.yaml `implements`)

- A manifest names the capabilities of the OpenCTEM capability taxonomy (`github.com/openctemio/ctis/capability`) it implements, with the major: `implements: [{capability: scan.ports@1, params: {top_n: {key: top_ports}}, output_shape: open_port_assets}]`. `params` maps the capability's standard params to the tool's config keys and may narrow enum values or integer bounds. A standard param that is not mapped is one the tool does not take.
- New optional keys:
  - `input` (`batch: one|list`, `max_targets`);
  - `presentation` (`display_name`, `category` and `icon` from closed sets, an https `docs_url`);
  - `publisher` and `license` (SPDX);
  - `engine` (`name`, `license`, `min_version`, a `version_probe` argv);
  - `safety` (`rate_param`, `side_effects`, `expands_targets`);
  - `features` (`retest`, `cancel`; `streaming` is reserved);
  - `permissions.proxy` (`honors|ignores`);
  - `sdk.min`;
  - `deprecated`.

  Manifests that use none of them keep their digest.
- Builder: `Implements("vuln.templates@1")` maps standard params to parameters of the same name and a matching type. `ImplementsWith(tool.Implementation{...})` maps them explicitly. `BatchTargets(n)` sets list input.
- `Manifest.ImplementedCapabilities`, `Implementation`, `MinimumTier`, `Batches` and `RetestFeature`.
- `core.ToolContract` carries `implements` and `batch`.
- The JSON Schema of tool.yaml describes the new keys.

### Security

- A manifest is refused when it:
  - implements a capability outside the taxonomy (matched exactly), or a reserved one;
  - declares a tier below a capability's tier floor;
  - declares side effects without tier T2;
  - consumes an asset type no implemented capability takes, or produces an output none may emit;
  - maps a param to a missing or mistyped config key, or widens a standard param's values or bounds.
- With `implements` set, the old `capabilities` list may only repeat its ids.
- `MinimumTier` is the highest of the declared tier, the capability floors, and T2 for any side effect. The platform may assign a higher tier, never a lower one.
- Display strings are refused when they contain control or bidirectional-override characters. Icons come from a closed set, never a URL. `docs_url` must be https without credentials. `engine.version_probe` refuses shells and placeholders.

### Deprecated

- `capabilities` in tool.yaml and `Builder.Capabilities`: use `implements` / `Builder.Implements`. The top-level `retest` key is the older spelling of `features.retest`; a manifest may set one, not both.
