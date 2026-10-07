# SDK stability

Goal (owner, 2026-10-02): the SDK is good enough that it rarely has to
change. A new tool, a new flag, a new output format or a new platform
feature must not need an SDK release. This page says what the SDK
promises, how it grows without breaking anyone, and what moves out.

## 1. Stability tiers

The SDK is the shared contract between the platform and every sensor or
collector. It holds only what every one of them needs and nothing
tool-specific. The direction of the public surface (one tool contract,
one runtime, a small public API, everything else internal) is set by
[docs/rfcs/sensor-sdk-v2.md](rfcs/sensor-sdk-v2.md); this page states what
holds today.

| Tier | Promise |
|---|---|
| **Stable** | No incompatible change within the major version (before v1.0.0: removal only after a released `Deprecated:` period, section 4). |
| **Beta** | May change in a minor release, after one minor with a `Deprecated:` notice and an upgrade note. |
| **Frozen** | No additions; removed when the protocol it serves is sunset. |
| **Internal-bound** | Public today because other public packages use it; it moves under `internal/` before v1.0.0 (deprecated aliases for one minor). Do not import it from a sensor. |
| **Deprecated** | Marked `Deprecated:` in its package documentation; removed in a later minor release with an upgrade note. |

Every public package states its tier in its package comment
(`Stability: <Tier> (docs/STABILITY.md).`, or a `Deprecated:` paragraph).
The `api-compat` CI job (`scripts/check-api-compat.sh`) weighs each
incompatible change against the PR's base by that tier: Stable and Frozen
fail unless the PR is labelled `breaking-change` with a `### Upgrade notes`
fragment in `changelog.d/`; Beta is a warning (write the upgrade note
anyway); Internal-bound and Deprecated are listed only. A public package
without a tier fails the job.

| Package | Role | Tier |
|---|---|---|
| `pkg/sensorkit` | The runtime in one call: settings, connection, heartbeat, commands, outbox, key renewal, drain, preflight checks and the config report; runner mode (`CIRun`, `Kit.RunOnce`: CI OIDC exchange, uploads, gate verdict, api RFC-051) | Stable; runner mode Beta |
| `pkg/sensorkit/settings` | The settings registry: every setting declared once (name, type, required, default, secret, description, docs link, validation); `docs/SETTINGS.md` is generated from it | Stable |
| `pkg/tool` | The tool contract: `tool.yaml` manifest, `Run(ctx, task)`, emitter, categorized errors, the `Define` builder for simple tools (docs/rfcs/sensor-sdk-v2.md) | Stable |
| `pkg/tool/adapter` | Adapter protocol v1, the tool side (`Serve`, `Dispatch`) | Stable |
| `pkg/tool/toolcompat` | Transitional bridges: a `core.Scanner` or `core.Collector` run as a tool of the contract (`FromScanner`, `FromCollector`), out of process; a contract tool served to the command executor (`AsScanner`) | Beta; removed once every in-tree scanner is ported |
| `pkg/testkit` | Run a tool in-process with the runtime's rules; golden CTIS | Stable |
| `pkg/importtool` | The file importer as a parser-class tool: Nessus, Qualys with KnowledgeBase, DefectDojo Generic JSON, CycloneDX, SPDX, osv-scanner, CSAF and OpenVEX files to CTIS (the `ctis/importer` package), sandboxed with no network | Beta |
| `pkg/sensorkit/toolhost` | The runtime side of the tool contract: runs one task out of process and checks, assembles and stamps its output | Beta |
| `pkg/sensorkit/identity` | A key-bound sensor's identity on disk (permission-checked) and the interactive pairing client (api RFC-052) | Beta |
| `pkg/sensorkit/executor` | Per-task tool sandbox behind a small backend interface (`Backend`, `TaskSpec`, `Status`) | Beta |
| `pkg/core` | Interfaces (`Scanner`, `Collector`, `Parser`, `CommandExecutor`, `Pusher`, …), registries, the command runtime (`BaseSensor`, `CommandPoller`), the safe-exec helpers (section 5), `ScanTargetPolicy` | Stable; its runtime internals are Internal-bound and its overlapping tool interfaces are replaced by the tool contract (RFC) |
| `pkg/client` | Platform protocol client (protocol v2; v1 is retired) | Stable; its protocol internals are Internal-bound |
| `pkg/sensorproto/v2` | Protocol v2 wire types | Frozen once protocol v3 ships; Stable until then |
| `pkg/sensorproto/legacyv1` | Pre-sensor names still read from existing installations (AGENT_* settings, credentials file) and the platform-sensor header | Frozen |
| `pkg/sensorproto/pairing` | Interactive pairing protocol (api RFC-052): wire types, commitment, SAS, codes, shared test vectors | Beta |
| `pkg/sensorsig` | RFC 9421 request signatures of a key-bound sensor (api RFC-052 §4.3): signer, verifier, signing transport | Beta |
| `pkg/ctis` | CTIS types: re-exports `github.com/openctemio/ctis` (generated aliases; the `ctis-parity` CI job fails when they are stale) | Stable, follows CTIS |
| `pkg/httpsec` | SSRF-safe HTTP clients and URL validation | Stable |
| `pkg/conformance` | Fake platform, the sensor conformance suite and the tool (adapter protocol) suite | Stable |
| `pkg/useragent`, `pkg/sdk` | Build identity on the wire | Stable |
| `pkg/outbox`, `pkg/resource`, `pkg/chunk`, `pkg/compress`, `pkg/retry`, `pkg/shared/*` | Runtime internals used by `client`, `core` and `sensorkit` | Internal-bound |
| `pkg/platform` | Credentials file and key renewal (used by sensorkit); its bootstrap/lease client serves the removed platform mode | Internal-bound (credentials, key renewal); the bootstrap/lease client is a removal candidate |
| `pkg/gitenv` | CI environment detection | Moves to the sensor (runner mode) |
| `pkg/mocks` | Test doubles | Stable until `pkg/testkit` replaces it |

**Deprecated** (no importer in the sensor, the platform or the asset
collector; removal is planned for a later minor release, with an upgrade
note in CHANGELOG.md):

| Package | Replacement |
|---|---|
| `pkg/transport/grpc`, `proto/openctemio/v1` | none: no platform serves it. Removed in the next minor, which also drops the `google.golang.org/grpc` dependency. Sensor protocol v3 is generated from its own proto definitions. |
| `pkg/pipeline`, `pkg/audit` | the outbox (through `sensorkit`) |
| `pkg/credentials` | credentials by declaration in the tool contract |
| `pkg/errors` | categorized tool errors in the tool contract |
| `pkg/health`, `pkg/metrics`, `pkg/options` | preflight checks, the config report and the settings registry in `sensorkit` |
| `pkg/enrichers/{epss,kev}` | the platform enriches findings itself |
| `pkg/connectors`, `pkg/connectors/github`, `pkg/providers/github` | the connectors module (api RFC-049) |

**Moved to the sensor** (removed in v0.17.0, deprecated in v0.16.0): the
tool wrappers `pkg/scanners` (the registry),
`pkg/scanners/{nuclei,trivy,semgrep,betterleaks,codeql}`,
`pkg/scanners/recon` and `pkg/scanners/recon/{subfinder,dnsx,httpx,naabu,katana}`,
and the CI-mode `pkg/handler` and `pkg/strategy`. Their code lives in
`github.com/openctemio/sensor/internal/{scanners,recon,handler,strategy}`.
Tool wrappers change whenever a tool does; they belong to the program that
ships the tool binaries.

**Removed:** `pkg/scanners/tenable` (a Nessus REST client and `.nessus`
converter with no importer). Convert `.nessus` exports with
`github.com/openctemio/ctis/importer` (format `nessus`).

`pkg/internal/*` is private.

**Config report ids are API.** The check ids (`identity.state_persistent`,
`tool.<name>.binary`, ...), their codes and parameter names, and the setting
names in the config report are what the platform explains and links docs
to: a rename is a breaking change. New ids and codes are additive (the
platform shows an unknown id as plain text without a fix).

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
digests, limits and `deprecations`. Protocol v2 is the only sensor
protocol: the platform retired v1 in 2026-10, and a platform that does not
serve a v2 route answers `client.ErrV2Unsupported` (no fall-back). A sensor
gates optional behavior with `Client.PlatformSupports(ctx, feature)`, which
also answers for feature names newer than the SDK. Per-sensor policy (allowed tools,
slim heartbeats) comes back on the manifest answer (`core.ManifestAck`).

**Versions.** `protov2.ProtocolVersion` is the protocol level; a hello
below it means no protocol v2. A protocol is retired with a `deprecations`
entry on hello before the platform drops it. `SENSOR_PROTOCOL` takes `auto`
(default) or `v2`, which are the same; `v1` is refused.

## 4. Versioning

- Semantic versioning. Before v1.0.0 a minor release may remove only what
  a previous minor deprecated; patch releases fix bugs only.
- `scripts/check-api-compat.sh` runs on every PR (`api-compat` job) and
  fails any incompatible change to the exported API. A deliberate break
  needs the `breaking-change` label and an "Upgrade notes" section in
  CHANGELOG.md. The `sensor-compat` job builds the sensor against the PR.
- Removal: mark `Deprecated:` (with the replacement) → keep it for at least
  one minor release → remove it in a later minor, with an upgrade note.
- **v1.0.0** when (a) the deprecated tool packages are gone (done in v0.17.0),
  (b) every package has a tier (section 1) and the Deprecated and
  Internal-bound ones are removed or moved under `internal/`, and
  (c) one further minor release has shipped with no breaking change and no
  `breaking-change` label. From v1.0.0 on, removals wait for v2.

## 5. Safety every sensor gets for free

A tool wrapper only builds arguments and parses output; the SDK applies
these to every scanner it runs:

| Control | API |
|---|---|
| Child env allow-list (no API key or proxy credentials leak into scanners) | `core.ScannerEnviron`, `SetScannerEnvAllowlist`, used by `ExecuteScanner` / `StreamScanner` / `BaseScanner` |
| Dangerous scanner flags refused in user-supplied args | `core.ValidateExtraArgs`, `core.DangerousToolFlags`, `core.RateLimitToolFlags` |
| Custom templates run only with a signed manifest a pinned key verifies | `core.TemplateVerifier`, `core.TemplateManifest`, `core.SignedEnvelope`, `core.DSSEPreAuthEncoding`, `DefaultCommandExecutor.SetTemplateVerifier` / `SetSensorID` |
| A scan can lower rate limits, never raise them past the sensor's ceiling | `ScanOptions.RateLimit` / `BulkSize` / `Concurrency`, `core.CapScanLimit` |
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

`pkg/conformance` has three parts:

- `FakePlatform`, an in-process platform that implements protocol v2
  strictly (and the v1 routes), records every request and injects faults.
  The SDK's own tests run against it.
- `RunSensorSuite(t, start, opts)`, the contract every sensor must keep:
  heartbeat with SDK identity, manifest registration, unknown command types
  left for another sensor, forward-compatible decoding, and a command run to
  completion with its reports committed first. A third-party sensor runs it
  from its own tests; the kit runs it in `pkg/sensorkit`.
- `RunToolSuite(t, "tool.yaml", opts)`, the contract every tool that is its
  own program (any language) must keep with adapter protocol v1: handshake,
  self-description equal to its tool.yaml, configuration validation,
  protocol-only stdout, exit on end of input, cancel, and its self-test
  fixtures through the runtime's own host. `cmd/openctem-conformance tool
  <tool.yaml>` runs it without Go code (docs/adapter-protocol.md).

The live suite (`live_test.go`, `OPENCTEM_CONFORMANCE_URL` /
`OPENCTEM_CONFORMANCE_KEY`) runs the results contract against a real
platform.
