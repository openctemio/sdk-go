### Fixed: `SENSOR_SANDBOX_NETWORK=required` is checked before pairing

- A sensor without an identity paired first and only then refused to start because this host cannot confine a tool's network. `sensorkit.New` now checks the requirement before pairing, so the platform does not admit a sensor that cannot run.
- Added `sensorkit.ValidateSandboxNetwork`: the same check for a program's own pair command.
