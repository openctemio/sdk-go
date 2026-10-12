### Upgrade notes: every sensor setting is SENSOR_-prefixed; old names are refused

- Renamed: `API_URL` → `SENSOR_API_URL`, `API_KEY` → `SENSOR_API_KEY`, `REGION` → `SENSOR_REGION`, `PLATFORM_KEY_AUTORENEW` → `SENSOR_KEY_AUTORENEW` (`sensorkit.EnvAPIURL`, `EnvAPIKey`, `EnvRegion`, `EnvKeyAutoRenew`).
- `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` are no longer read as aliases.
- One switch for private scan targets: `SENSOR_ALLOW_PRIVATE_TARGETS`. `OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS` is gone (`core.EnvAllowPrivateTargets` is a deprecated alias of `core.EnvSensorAllowPrivateTargets`), and the SDK's egress switch `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE` no longer widens scan targets. The SDK no longer honors the API's `OPENCTEM_HTTPSEC_ALLOW_PRIVATE`.
- `sensorkit.MigrateLegacyEnv` (run by `New`) refuses every removed name (`sensorkit.RemovedEnv`) with exit code 2, naming the replacement and never the value. Rename them in `.env` files, compose files, systemd units and Helm values before upgrading. The `-agent-id` flag is still migrated.
