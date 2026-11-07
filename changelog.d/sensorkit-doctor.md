### Added: a `doctor` subcommand that checks the sensor's host

- `sensorkit.DoctorCommand` (and `RunDoctor`) is the `doctor` subcommand a
  sensor's `main` dispatches to. It changes nothing and checks: the tool
  sandbox and user namespaces (with the classified cause), cgroup v2
  delegation, free disk on the data directories, the state directory, the
  platform's DNS, TLS (the CA fingerprint) and clock skew from one request
  without any credential, the local policy as the sensor parses it, and the
  kill switch path.
- `--json` prints `openctem.io/sensor-doctor/v1`
  (`docs/schemas/sensor-doctor.v1.schema.json`). Exit codes: 0 all passed,
  3 a warning, 4 a failure, 2 a usage error.
- The output never carries a secret setting's value, URL credentials or key
  bytes (the config report's scrubber).
- New: `executor.CheckEnvelopes` (read-only cgroup delegation check),
  `resource.DiskFree`, `core.LocalPolicy.KillSwitchFiles`.
