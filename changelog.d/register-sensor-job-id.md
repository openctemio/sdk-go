### Fixed: `SENSOR_JOB_ID` is in the SDK settings registry

- `RegisterSDKSettings` registers `SENSOR_JOB_ID` (`EnvJobID`, group `runtime`), the variable a kit-based sensor reads to run one platform command and exit. The config report now lists it, `docs/SETTINGS.md` documents it, and a sensor started with it no longer gets a `config.env_unknown` check for it.
- Sensors that register `SENSOR_JOB_ID` themselves must drop that line when they move to this release: the registry refuses a name registered twice.
