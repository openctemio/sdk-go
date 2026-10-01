# Changelog

All notable changes to `github.com/openctemio/sdk-go`.

## Unreleased

### Fixed

- **A rejected API key no longer floods the platform or hides in the logs.**
  When a heartbeat gets 401/403 (key wrong, revoked, expired or regenerated,
  sensor disabled without the doorbell, or deleted), `BaseSensor` now waits a
  capped exponential backoff (30 s doubling to 10 min, ±20 % jitter) instead
  of the normal interval, and the `CommandPoller` stops polling until a
  heartbeat is accepted again (it shares the sensor's new `AuthGate` through
  the doorbell, or via `CommandPoller.SetAuthGate(sensor.AuthGate())`). A
  poller without a heartbeat backs off its own polls the same way. Before,
  a revoked sensor kept sending a heartbeat and a poll every interval.
- **Connection trouble is logged without `-verbose`.** Heartbeat and poll
  errors were printed only in verbose mode, so a sensor that lost the
  platform said nothing. The `AuthGate` now logs once per backoff step or
  change of state, never per request: the HTTP status, the key's non-secret
  prefix (`core.APIKeyHint`, at most 8 characters) and what to do (create or
  regenerate a key under Settings → Sensors, set `API_KEY`, restart). Network
  failures are logged at 1, 2, 4, 8, ... consecutive attempts, and recovery
  is logged too.
- **The plain-http warning is printed once per process per base URL**,
  shared by `pkg/client` and `pkg/platform` (`httpsec.FirstWarning`).

### Added

- `core.AuthGate`, `core.AuthFailureStatus`, `core.APIKeyHint`,
  `core.APIKeyHinter`, `BaseSensor.AuthGate`/`SetAuthGate`,
  `CommandPoller.SetAuthGate`, `client.HTTPError.HTTPStatusCode`,
  `client.Client.APIKeyHint`, `httpsec.FirstWarning`.

## Unreleased — release as **v0.7.3**

### Fixed

- **`CheckEnv` rejects allow-private values it would ignore.** Only `1`
  enables `SENSOR_ALLOW_PRIVATE_TARGETS`, `OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS`
  and the httpsec switches, so `true`, `yes` or `on` used to be ignored
  without a word and every private target refused. `core.CheckEnv()` now
  returns an error naming the variable and the accepted values (`1`, `0` or
  unset). Per-target behavior is unchanged; a sensor that calls `CheckEnv`
  at startup refuses to start instead.

## v0.7.2 — 2026-10-01

### Fixed

- **Sensors can reach a platform on a private network again.** The API
  client (`httpsec.NewAPIClient`, used by `pkg/client` and `pkg/platform`)
  applied the scan-target SSRF blocklist to the operator-configured API base
  URL, so a platform on loopback, RFC1918 (Docker, Kubernetes service IPs),
  ULA or CGNAT/Tailscale addresses was refused with `ssrf guard: blocked IP`
  unless `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE=1` was set (affected since
  v0.6.0). The API client now allows them, still refuses link-local (cloud
  metadata), multicast, reserved and unspecified addresses and every
  redirect, and honors `HTTP(S)_PROXY` / `NO_PROXY` again (dropped in
  v0.6.0). Scanners, collectors and enrichers keep the full guard.

## v0.7.1 — 2026-10-01

### Added

- **Heartbeat doorbell** (API RFC-023 §9.2a, api#619). `core.Doorbell`,
  `BaseSensor.SetDoorbell` and `CommandPoller.SetDoorbell` let the heartbeat
  tell a daemon when work is waiting: the heartbeat announces
  `X-OpenCTEM-Sensor-Features: doorbell`, `pending_jobs > 0` wakes the
  poller at once, `next_heartbeat_seconds` sets the next heartbeat (clamped
  5 s – 5 min), and while the server sends hints the fixed command poll is
  replaced by the doorbell plus a 5-minute safety poll. Actions: `pause` /
  `drain` stop job intake (running jobs finish, heartbeats continue),
  `resume` lifts a pause, `rotate_key` calls `DoorbellConfig.OnRotateKey`,
  `update` and unknown actions are only logged. Against a server without the
  doorbell nothing changes, detected per response.
- `client.Client.SendHeartbeatWithHints` returns the parsed hints;
  `SendHeartbeat` is unchanged (no feature header, body ignored).
- `platform.KeyRenewManager.RenewNow` renews immediately (debounced to one
  per `MinInterval` after a rotation). The manager now keeps running after a
  no-expiry discovery renewal, and with `CurrentKeyNeverExpires`, so that a
  later `RenewNow` still works; it still renews nothing on its own then.

## v0.7.0 — 2026-10-01 (breaking)

The SDK moves from the *agent* to the *sensor* vocabulary
([RFC-023 §9.5](https://github.com/openctemio/api/blob/develop/docs/rfcs/RFC-023-scan-zones-and-scanners.md)).
The module is pre-1.0, so this ships as a minor version with breaking
changes: **v0.6.x → v0.7.0**.

### Upgrade in one command

Run the codemod in the root of your module while it still builds against
v0.6:

```bash
# Show what would change
go run github.com/openctemio/sdk-go/cmd/sensor-migrate@v0.7.0 -dry-run
# Rewrite, then upgrade the SDK to v0.7.0 (go get) in the same run
go run github.com/openctemio/sdk-go/cmd/sensor-migrate@v0.7.0
```

It type-checks your code and renames only identifiers that resolve to SDK
objects (your own `agent` variable or `AgentPool` type are never touched),
including the embedded field of a struct that embeds a renamed SDK type. It
refuses, changing nothing, when a new name would collide with one of yours.
A second run finds nothing to rename. Flags: `-dir`, `-dry-run`,
`-sdk-version vX.Y.Z|none`, and `-tags t1,t2` (repeatable) for files behind
build tags — every build configuration is checked against the old SDK before
anything is written, e.g. `sensor-migrate -tags platform`.

### What did not change: protocol v1

Sensors built with any earlier SDK keep working against the platform, and
sensors built with this one keep working against an older platform: the wire
is byte-for-byte the same. All of it lives in `pkg/sensorproto/legacyv1` and is
pinned by a golden recording made before the rename
(`pkg/sensorproto/legacyv1/goldentest`):

- routes `/api/v1/agent/*` (heartbeat, ingest, ingest/check,
  ingest/baseline-diff, ingest/chunk, commands, renew) and `/api/v1/platform/*`;
- header `X-Agent-ID`, gRPC metadata `x-agent-id`, `Authorization: Bearer`;
- JSON keys `agent_id` in the registration response, lease info and exposure
  ingest, `agent_preference` in job payloads;
- CTIS `discovery_source: "agent"` from the recon converter;
- the gRPC schema `proto/openctemio/v1/agent.proto` (`AgentService`).

### Renamed identifiers (BREAKING)

| Package | Before | After |
|---|---|---|
| `pkg/audit` | `audit.Event.AgentID` | `audit.Event.SensorID` |
| `pkg/audit` | `audit.EventAgentError` | `audit.EventSensorError` |
| `pkg/audit` | `audit.EventAgentStart` | `audit.EventSensorStart` |
| `pkg/audit` | `audit.EventAgentStop` | `audit.EventSensorStop` |
| `pkg/audit` | `audit.LoggerConfig.AgentID` | `audit.LoggerConfig.SensorID` |
| `pkg/chunk` | `chunk.Metadata.AgentID` | `chunk.Metadata.SensorID` |
| `pkg/client` | `client.Config.AgentID` | `client.Config.SensorID` |
| `pkg/client` | `client.WithAgentID` | `client.WithSensorID` |
| `pkg/core` | `core.Agent` | `core.Sensor` |
| `pkg/core` | `core.AgentState` | `core.SensorState` |
| `pkg/core` | `core.AgentStateError` / `Running` / `Stopped` / `Stopping` | `core.SensorStateError` / `Running` / `Stopped` / `Stopping` |
| `pkg/core` | `core.AgentStatus` | `core.SensorStatus` |
| `pkg/core` | `core.BaseAgent` | `core.BaseSensor` |
| `pkg/core` | `core.BaseAgentConfig` | `core.BaseSensorConfig` |
| `pkg/core` | `core.NewBaseAgent` | `core.NewBaseSensor` |
| `pkg/core` | `core.ValidateBaseAgentConfig` | `core.ValidateBaseSensorConfig` |
| `pkg/errors` | `errors.ErrMissingAgentID` | `errors.ErrMissingSensorID` |
| `pkg/metrics` | `metrics.AgentActiveJobs` / `AgentHeartbeats` / `AgentJobDuration` / `AgentJobsTotal` / `AgentQueueSize` | `metrics.SensorActiveJobs` / `SensorHeartbeats` / `SensorJobDuration` / `SensorJobsTotal` / `SensorQueueSize` |
| `pkg/options` | `options.ClientConfig.AgentID`, `options.GRPCConfig.AgentID` | `.SensorID` |
| `pkg/options` | `options.WithAgentID`, `options.WithGRPCAgentID` | `options.WithSensorID`, `options.WithGRPCSensorID` |
| `pkg/platform` | `platform.AgentBuilder`, `platform.NewAgentBuilder` | `platform.SensorBuilder`, `platform.NewSensorBuilder` |
| `pkg/platform` | `platform.AgentCredentials` (`.AgentID`) | `platform.SensorCredentials` (`.SensorID`) |
| `pkg/platform` | `platform.AgentInfo` | `platform.SensorInfo` |
| `pkg/platform` | `platform.AgentStatus` (`.AgentID`) | `platform.SensorStatus` (`.SensorID`) |
| `pkg/platform` | `platform.ClientConfig.AgentID`, `platform.LeaseInfo.AgentID`, `platform.RegistrationResponse.AgentID` | `.SensorID` |
| `pkg/platform` | `platform.ErrAgentAlreadyExists` | `platform.ErrSensorAlreadyExists` |
| `pkg/platform` | `platform.PlatformAgent` | `platform.PlatformSensor` |
| `pkg/retry` | `retry.QueueItem.AgentID` | `retry.QueueItem.SensorID` |
| `pkg/transport/grpc` | `grpc.Config.AgentID` | `grpc.Config.SensorID` |

Files: `pkg/core/base_agent.go` → `base_sensor.go`; `agent.yaml.template` →
`sensor.yaml.template`.

### Migrated automatically

| Old | New | How |
|---|---|---|
| `~/.openctem/agent-credentials.json` | `~/.openctem/sensor-credentials.json` | `platform.EnsureRegistered` / `platform.ResolveCredentialsFile` with no explicit path move it on first start: read and validate the old file, write the new one atomically (temp file 0600, fsync, rename, directory fsync), read it back and compare, then remove the old file. The sensor keeps its id and key and does not register again. If both files exist the new one wins and a warning names both (the old one is left in place). If the old file cannot be moved (read-only volume, Kubernetes Secret, single bind-mounted file) nothing is changed and it is used where it is, with a warning. An explicit path is used as is. |
| credentials JSON key `agent_id` | `sensor_id` | still read; written as `sensor_id`; both set to different values is an error |
| `AGENT_ALLOW_PRIVATE_TARGETS` | `SENSOR_ALLOW_PRIVATE_TARGETS` | new name read first; the old one is applied with a one-time `WARN deprecated configuration` naming both; both set to different values makes `core.DefaultScanTargetPolicy` refuse every target and `core.CheckEnv()` return the error (fail closed) |
| config key `agent_id` in `client.Config` / `grpc.Config` (YAML or JSON) | `sensor_id` | still read with a warning (`UnmarshalJSON`, and `UnmarshalYAML` in the form yaml.v2 and v3 both accept); both set to different values is an error |

`legacyv1.LookupEnv(new, old)` / `legacyv1.Resolve` implement this rule for
sensor binaries' own renamed settings too.

### Renamed outputs (update dashboards and log filters)

| Kind | Before | After |
|---|---|---|
| Prometheus metrics | `openctem_agent_jobs_total`, `openctem_agent_job_duration_seconds`, `openctem_agent_queue_size`, `openctem_agent_active_jobs`, `openctem_agent_heartbeats_total` | `openctem_sensor_*` |
| Audit log event types | `agent_start`, `agent_stop`, `agent_error` | `sensor_start`, `sensor_stop`, `sensor_error` |
| Audit log field | `agent_id` | `sensor_id` |
| Retry-queue item / chunk metadata field (on disk; never populated by the SDK) | `agent_id` | `sensor_id` |
| Lease holder identity default prefix | `agent-<host>-<pid>-…` | `sensor-<host>-<pid>-…` |
| Console messages | `[agent] …`, `Starting agent …` | `[sensor] …`, `Starting sensor …` |

### Added

- `pkg/sensorproto/legacyv1`: protocol v1 vocabulary, renamed-setting table
  and `LookupEnv` / `Resolve` / `MergeSensorID` helpers.
- `platform.DefaultCredentialsFile`, `platform.LegacyCredentialsFile`,
  `platform.ResolveCredentialsFile`, `platform.MigrateCredentialsFile`.
- `core.EnvSensorAllowPrivateTargets`, `core.CheckEnv`.
- `httpsec` also strips `X-Sensor-API-Key` and `X-Agent-API-Key` on
  cross-origin redirects.
- `cmd/sensor-migrate` (codemod) and `scripts/rename/sensor-rename.sh` (the
  re-runnable rename the SDK itself went through).
- A test that fails on agent-vocabulary identifiers or strings outside
  `pkg/sensorproto/legacyv1` and the rename tooling.
