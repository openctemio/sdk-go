### Security: shared mode is refused when the sensor takes no platform jobs

- `SENSOR_SHARED_MODE=1` with `Options.DisableCommands` or `Options.Standalone` now fails at start with a usage error. Shared mode isolates the jobs of many organizations; a sensor that takes no platform jobs gains nothing from it and would only appear to be a shared sensor.
