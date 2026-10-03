# SDK stability

Goal (owner, 2026-10-02): the SDK is good enough that it rarely has to
change. A new tool, a new flag, a new output format or a new platform
feature must not need an SDK release. This page says what the SDK
promises, how it grows without breaking anyone, and what moves out.

## 1. The stable surface

The SDK is the shared contract between the platform and every sensor or
collector. It holds only what every one of them needs and nothing
tool-specific.

| Package | Role | Status |
|---|---|---|
| `pkg/core` | Interfaces (`Scanner`, `Collector`, `Parser`, `CommandExecutor`, `Pusher`, …), registries (`ToolRegistry`, `ParserRegistry`), the command runtime (`BaseSensor`, `CommandPoller`), the safe-exec helpers (section 5), `ScanTargetPolicy` | stable |
| `pkg/sensorkit` | The runtime in one call: settings, connection, heartbeat, commands, outbox, key renewal, drain | stable |
| `pkg/client` | Platform protocol client (v2 negotiated, v1 fallback) | stable |
| `pkg/sensorproto/v2` | Protocol v2 wire types | stable |
| `pkg/sensorproto/legacyv1` | Protocol v1 wire vocabulary | frozen (no additions) |
| `pkg/ctis` | CTIS types; kept identical to `github.com/openctemio/ctis` by the `ctis-parity` CI job | stable, follows CTIS |
| `pkg/outbox` | Durable, encrypted result queue | stable |
| `pkg/httpsec` | SSRF-safe HTTP clients and URL validation | stable |
| `pkg/resource` | Slot sizing from CPU, memory and tool cost | stable |
| `pkg/conformance` | Fake platform and the sensor conformance suite | stable |
| `pkg/platform` | Credentials file, key renewal (used by sensorkit) | stable for those parts; its bootstrap/lease client serves the removed platform mode and is a removal candidate |
| `pkg/useragent`, `pkg/sdk` | Build identity on the wire | stable |

**Deprecated, moving to the sensor** (`github.com/openctemio/sensor/internal/...`):
`pkg/scanners/*` (nuclei, trivy, semgrep, betterleaks, codeql, recon tools,
tenable), `pkg/adapters/*`, `pkg/strategy`, `pkg/gitenv`. They keep working
in v0.16.x with a `Deprecated:` package comment and are removed in v0.17.0.
Tool wrappers change whenever a tool does; they belong to the program that
ships the tool binaries.

**Outside the stable surface** (no stability promise; each gets a
keep/move/remove decision while planning v0.17.0): `pkg/connectors`,
`pkg/providers`, `pkg/enrichers`, `pkg/handler` (the sensor's CI mode uses
it), `pkg/pipeline`, `pkg/chunk`, `pkg/compress`, `pkg/retry` (partly
deprecated already), `pkg/errors`, `pkg/health`, `pkg/metrics`,
`pkg/audit`, `pkg/credentials`, `pkg/options`, `pkg/transport/grpc`,
`pkg/shared/*`, `pkg/mocks`. Most have no importer in the sensor or the API.

`pkg/internal/*` is private.

## 2. Extending without an SDK release

Tools plug in through interfaces and registries the sensor fills; the SDK
never lists tools.

- **A new tool**: implement `core.Scanner` (or `core.Collector`) in the
  sensor and register it with `sensorkit.Kit.AddScanner` / `AddCollector`.
  The kit reports it on the heartbeat and in the manifest
  (`core.ToolRegistry`); the platform dispatches by that report.
- **A new output format**: implement `core.Parser` and register it with
  `Kit.AddParser` (`core.ParserRegistry`).
- **A new command type**: `Kit.HandleCommand(type, executor)`; wrap
  existing ones with `Kit.UseCommandMiddleware`. A type a sensor does not
  handle stays pending for a sensor that does (the poller's allowed types).
- **A new tool option or flag**: it travels in the command payload
  (`core.Command.Payload` is raw JSON) and in the tool wrapper's own
  configuration, both in the sensor. `core.ScanOptions` holds only
  cross-tool concepts (target, include/exclude, extra args, env, asset).
  User-supplied flags still pass `core.ValidateExtraArgs`.

**Rules for the SDK's own types**

1. Never change or remove an exported signature, field or constant within a
   major version. Add instead.
2. An added struct field's zero value means the old behavior.
3. Configuration grows by fields on option structs (`sensorkit.Options`,
   `client.Config`, `core.ExecConfig`, …), never by new constructor
   parameters.
4. A new behavior that changes what goes on the wire is off until the
   platform announces it (section 3) or the operator turns it on.
5. Interfaces stay small. A new capability is a new, optional interface
   the runtime detects with a type assertion (as `core.MultiTargetScanner`,
   `core.LimitedCommandClient`, `core.ManifestStateReader` are today), never
   a method added to an existing interface.

## 3. Protocol compatibility

**Unknown JSON members are ignored on the control plane, both ways.** The
SDK decodes every platform answer with plain `encoding/json`, which ignores
members it does not know; the conformance fake can add one to every answer
(`FakePlatform.FutureFields`) and the suite checks a sensor keeps working.
The platform's heartbeat, command and manifest handlers decode leniently
too, so a newer SDK's extra members reach an older platform harmlessly.

**CTIS results are the exception, on purpose.** The platform decodes
reports strictly (`DisallowUnknownFields` after an I-JSON pre-pass, api
`internal/app/ingest/strictjson.go`) to rule out parser-differential
attacks. So a CTIS addition is receiver-first: the platform takes the new
`ctis` version before any sensor sends the new member. CTIS 1.3.0 says so
in its CHANGELOG; the platform still pins `ctis v1.2.0` (openctem#789 takes
1.3.0). The SDK's CTIS types use `omitempty`, so a sensor that does not set
a new member sends nothing new.

**Feature negotiation.** The platform's hello (`GET /api/v2/sensor/hello`,
`protov2.Hello`) carries `protocol`, `features`, media types, encodings,
digests, limits and `deprecations`. The client asks it before using a
protocol v2 resource and falls back to v1 per resource when a feature is
not listed (`Client.controlV2`), so a sensor works against older and newer
platforms alike. A sensor gates its own optional behavior the same way
with `Client.PlatformSupports(ctx, feature)`, which also answers for
feature names newer than the SDK. Per-sensor policy (allowed tools,
slim heartbeats) comes back on the manifest answer (`core.ManifestAck`).

**Versions.** `protov2.ProtocolVersion` is the protocol level; a hello
below it means v1 only. A protocol is retired with a `deprecations` entry on
hello (`protocol_v1`, with a sunset date) long before the platform drops it.
A sensor can be pinned with `SENSOR_PROTOCOL=v1|v2|auto` (default `auto`).

## 4. Versioning

- Semantic versioning. Before v1.0.0 a minor release may remove only what
  a previous minor deprecated; patch releases fix bugs only.
- `scripts/check-api-compat.sh` runs on every PR (`api-compat` job) and
  fails any incompatible change to the exported API. A deliberate break
  needs the `breaking-change` label and an "Upgrade notes" section in
  CHANGELOG.md. The `sensor-compat` job builds the sensor against the PR.
- Removal: mark `Deprecated:` (with the replacement) → keep it for at least
  one minor release → remove it in a later minor, with an upgrade note.
- **v1.0.0** when (a) the deprecated tool packages are gone (v0.17.0),
  (b) the packages "outside the stable surface" each have a decision, and
  (c) one further minor release has shipped with no breaking change and no
  `breaking-change` label. From v1.0.0 on, removals wait for v2.

## 5. Safety every sensor gets for free

A tool wrapper only builds arguments and parses output; the SDK applies
these to every scanner it runs:

| Control | API |
|---|---|
| Child env allow-list (no API key or proxy credentials leak into scanners) | `core.ScannerEnviron`, `SetScannerEnvAllowlist`, used by `ExecuteScanner` / `StreamScanner` / `BaseScanner` |
| Dangerous scanner flags refused in user-supplied args | `core.ValidateExtraArgs`, `core.DangerousToolFlags` |
| Output caps | `ExecConfig.MaxOutputBytes`, `ErrScannerOutputTooLarge` |
| Process-group kill on cancel/timeout, reaping, die-with-parent | `core.ConfigureScannerProcess`, `core.ReapScannerProcess` |
| Scanner priority (nice, I/O class, OOM score) | `core.ScannerPriority`, `SetScannerPriority`, `ApplyScannerPriority`; sensorkit `SENSOR_SCANNER_PRIORITY`, `SENSOR_PROTECT_FROM_OOM` |
| Scan-target policy (roots, private ranges, metadata endpoints) | `core.ScanTargetPolicy` |
| SSRF-safe HTTP, proxy-aware, checked per redirect and at dial | `httpsec.SafeHTTPClient`, `httpsec.ValidateURL` |
| Durable results; no silent key replacement | `pkg/outbox` (`ErrKeyMissing`), `client.OutboxConfig` |
| API key renewal that survives restarts | `platform.KeyRenewManager`, sensorkit `PLATFORM_KEY_AUTORENEW`, state dir |

A wrapper that starts processes without these helpers must call
`ConfigureScannerProcess`, `ScannerEnviron` and `ValidateExtraArgs` itself.

## 6. Conformance

`pkg/conformance` has two halves:

- `FakePlatform`, an in-process platform that implements protocol v2
  strictly (and the v1 routes), records every request and injects faults.
  The SDK's own tests run against it.
- `RunSensorSuite(t, start, opts)`, the contract every sensor must keep:
  heartbeat with SDK identity, manifest registration, unknown command types
  left for another sensor, forward-compatible decoding, and a command run to
  completion with its reports committed first. A third-party sensor runs it
  from its own tests; the kit runs it in `pkg/sensorkit`.

The live suite (`live_test.go`, `OPENCTEM_CONFORMANCE_URL` /
`OPENCTEM_CONFORMANCE_KEY`) runs the results contract against a real
platform.
