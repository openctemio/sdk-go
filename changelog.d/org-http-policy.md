### Added: the organization's HTTP policy narrows its tools' requests (job `http_policy`)

- A scan job can carry `http_policy: {user_agent, allow_insecure_tls}` (`core.OrgHTTPPolicy`, `ScanCommandPayload.HTTPPolicy`).
- The tool host merges it after the sensor-local policy:
  - its User-Agent applies unless the local policy forces one;
  - `allow_insecure_tls: false` refuses, with `refused_by_policy`, a tool whose `tool.yaml` skips TLS verification;
  - it never allows what the local policy forbids.
- An invalid policy fails the job. The tool sees only the effective settings (`task.http`).
