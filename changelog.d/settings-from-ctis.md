### Changed: tool settings come from the CTIS contract

- `pkg/core` settings types (`SettingsSchema`, `SettingProperty`, `ToolSettings`, `SettingsLayer`, `SettingsErrors`, scopes, sources) are now aliases of `github.com/openctemio/ctis/settings`, so the platform validates administrators' values with the same code the sensor runs. The golden vectors moved to ctis (`settings/testdata/vectors`).
- New from the contract: `x-octm-common` (a manifest key is a common tool option: `timeout`, `rate`, `concurrency`, `retries`; type and bounds checked) and `x-octm-flag` (the tool's native flag, display only); top-level `proxy`, `user_agent` and `headers` keys are refused; layers `SettingSourceTenant` and `SettingSourceJob`; a later layer that raises a narrowing option (`rate`, `concurrency`, `retries`) an earlier layer set is an error.

### Removed

- `(*SettingsSchema).ManifestSettings()`: the manifest builds the schema's version and digest itself.

### Added: layered tool settings in the command executor

- A scan command may carry `settings_layers: {tenant, sensor}`: the administrators' tool settings, covered by the job signature. The executor checks each layer against the tool's own schema and resolves, in order: the tool's defaults, the tenant's and the sensor's layers, the scan's config (declared keys), the job's decision and the local policy. An invalid layer, a key a layer may not set, or a raise of a narrowing option fails the command.
- The job's decision reaches every tool through its common options (`x-octm-common`): the command's rate and concurrency (never above the value in force: the tool's default or what an administrator set), and the per-target budget as the tool's per-request timeout (budget ÷ (retries + 1), at least 2 s, never longer than the timeout in force). The local policy's `rate.max_rps` lowers the common rate (source `local`).
- The result's metadata says what ran: `effective_settings` (each key's value and the layer that set it).

### Upgrade notes

- Source compatible for callers: every settings identifier of `pkg/core` (and `pkg/tool`'s `DecodeConfig` / `Manifest.ConfigSchema`, which use them) keeps its name; the types are now aliases of `github.com/openctemio/ctis/settings`, which the API compatibility check reports as type changes. A sensor that mixes both names needs no edit.
- `(*core.SettingsSchema).ManifestSettings()` is removed (it was only used inside the SDK to build the manifest). Build `core.ManifestToolSettings{SchemaVersion: s.Version, Digest: s.Digest()}` if you need it.
- A tool manifest that declares a top-level `proxy`, `user_agent` or `headers` setting no longer loads.
