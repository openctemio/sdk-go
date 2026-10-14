### Added: `SENSOR_PAIRING_CODE` pairs a new sensor in one start

- `pkg/sensorkit`: a sensor with no identity and no API key attaches to the pairing code in `SENSOR_PAIRING_CODE` (the code an administrator created with "expect a sensor") on its first start, so reverse pairing needs no separate `pair` command. The code is validated before any request (a malformed one stops the sensor with exit 2), is a secret in the settings registry, and is never printed: the pairing instructions name the variable instead. Once the sensor is paired, or when it has an API key, the variable is ignored with a note and can be removed.

### Changed: a tools allowlist no longer drops sensor-wide built-ins

- `pkg/sensorkit`: new `ScannerOption` `Builtin()` marks a scanner that is part of the sensor itself (the reachability probe, compiled-in passive lookups). `Options.Tools` / `SENSOR_TOOLS` no longer drop such scanners from the inventory; the local policy's `tools.allow` still narrows them.

### Deprecated: `SENSOR_TOOLS`

- When the kit reads `SENSOR_TOOLS` itself it logs a deprecation warning: the variable only narrows the installed tools and will be removed. Narrow with the local policy's `tools.allow` instead.
