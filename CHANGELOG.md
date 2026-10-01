# Changelog

All notable changes to `github.com/openctemio/sdk-go`.

## Unreleased — release as **v0.7.0** (breaking)

The SDK moves from the *agent* to the *sensor* vocabulary
([RFC-023 §9.5](https://github.com/openctemio/api/blob/develop/docs/rfcs/RFC-023-scan-zones-and-scanners.md)).
The module is pre-1.0, so this ships as a minor version with breaking
changes: **v0.6.x → v0.7.0**. Nothing has been tagged yet.

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
`-sdk-version vX.Y.Z|none`.

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
| `~/.openctem/agent-credentials.json` | `~/.openctem/sensor-credentials.json` | `platform.EnsureRegistered` / `platform.ResolveCredentialsFile` with no explicit path move it on first start: read and validate the old file, write the new one atomically (temp file 0600, fsync, rename, directory fsync), read it back and compare, then remove the old file. The sensor keeps its id and key and does not register again. If both files exist the new one wins and a warning names both (the old one is left in place). An explicit path is used as is. |
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
