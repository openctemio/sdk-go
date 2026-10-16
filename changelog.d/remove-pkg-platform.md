### Removed: pkg/platform (routes the core never served)

- `pkg/platform` is removed. Its bootstrap registration, lease and poll clients called `/api/v1/platform/{register,lease,poll,jobs}`, which no OpenCTEM API serves, so a sensor built on them could never connect. Shared sensors of an instance enroll with `SENSOR_INSTANCE_ENROLLMENT_TOKEN` and speak the same protocol as every sensor (api RFC-100).
- The parts `sensorkit` used (the state directory, the credentials file, the key choice at start and the API key renewal client and loop) move to `internal/sensorstate` unchanged. Sensors built on `sensorkit` see no difference.
- **Upgrade note:** code that imported `github.com/openctemio/sdk-go/pkg/platform` no longer builds. There is no replacement for the platform-mode client; use `sensorkit` (or `pkg/client` with `core.CommandPoller`). `cmd/sensor-migrate` no longer covers `pkg/platform`.
