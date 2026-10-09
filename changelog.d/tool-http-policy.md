### Added: the sensor's local policy decides last about the tools' requests (schema v3)

- Local policy schema v3 (`openctem.io/sensor-policy/v3`: every v2 key plus `http`):
  - `http.user_agent` replaces every tool's User-Agent;
  - `http.allow_insecure_tls: false` refuses, with `refused_by_policy`, a tool whose `tool.yaml` skips TLS verification.

  `core.LocalPolicy.HTTPPolicy()` reads it. v1 and v2 files are unchanged and still refuse the key.
- The effective settings (the manifest's `http` with the policy applied) travel in the task (`tool.Task.HTTP`, `run.task.http` for adapters). The runtime sets them; a job's value is discarded. `ctx.HTTP()`, `{{http.user_agent}}` and the task's start log line use them.
