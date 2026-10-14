### Changed: tool settings come from the CTIS contract

- `pkg/core` settings types (`SettingsSchema`, `SettingProperty`, `ToolSettings`, `SettingsLayer`, `SettingsErrors`, scopes, sources) are now aliases of `github.com/openctemio/ctis/settings`, so the platform validates administrators' values with the same code the sensor runs. The golden vectors moved to ctis (`settings/testdata/vectors`).
- New from the contract: `x-octm-common` (a manifest key is a common tool option: `timeout`, `rate`, `concurrency`, `retries`; type and bounds checked) and `x-octm-flag` (the tool's native flag, display only); top-level `proxy`, `user_agent` and `headers` keys are refused; layers `SettingSourceTenant` and `SettingSourceJob`; a later layer that raises a narrowing option (`rate`, `concurrency`, `retries`) an earlier layer set is an error.

### Removed

- `(*SettingsSchema).ManifestSettings()`: the manifest builds the schema's version and digest itself.
