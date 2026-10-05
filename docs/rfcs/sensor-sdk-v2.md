# RFC — Sensor SDK v2: one tool contract, one runtime, any language

> Status: **Accepted** (2026-10-05). Decisions S1–S14 below are adopted as recommended. Implementation: phase S0 and S1 in progress.
> Scope: sdk-go (public API, runtime, CLI, test tools), a new `protocol` module (language-neutral contracts), sensor (built-in tools ported to the contract, runner mode on the kit), openctem api/web (tool manifests, output binding, ingest tokens), a new sdk-python (adapter SDK).
> Builds on: api RFC-023 (sensor naming), RFC-029 (protocol v2 and SDK stability), RFC-032 (enrollment and identity), RFC-033 (sensor manifest), RFC-034 (network egress), RFC-038 (tool settings), RFC-040 (mutual distrust), RFC-046 (scans), RFC-049 (connector framework); `docs/STABILITY.md` and `docs/SECURITY.md` in this repository.

## Summary

- **One tool contract** (`pkg/tool`) replaces the overlapping scanner, collector, parser and adapter interfaces: a manifest (`tool.yaml`) plus `Run(ctx, task)`. The manifest declares the execution class (target-scan, connector, parser, enricher), tier, consumes/produces, a typed config schema, permissions, resources and self-test fixtures.
- **Out-of-process execution, always.** Go tools are written as plain functions and run by the sensor re-executing its own binary inside the Executor sandbox. Tools in other languages speak adapter protocol v1 (newline-delimited JSON on stdin/stdout). A CLI that already writes CTIS or SARIF becomes a tool with a manifest and no code.
- **One runtime** (`pkg/sensorkit`) owns identity, transport, control, dispatch, policy admission, sandboxing, credentials, output validation and provenance, delivery, settings and preflight checks, for both daemon and runner modes.
- **A small public API** with stability tiers; everything else internal. Language-neutral contracts (sensor protocol v3, `tool.yaml`, adapter protocol, policy, settings and config-report schemas) live in a `protocol` module with conformance suites anyone can run.
- **Secure by default**: none of the runtime's guarantees can be turned off from sensor or tool code.

## Motivation

`pkg/sensorkit` already turns a sensor into "implement your tools, the kit runs the rest". The surface around it makes that hard to see and hard to extend:

1. **Too much public API.** About 44 public packages and 3,200 exported identifiers; `pkg/core` holds the developer interfaces next to the command poller, doorbell, executor, template signing and local-policy internals. Every internal is API, so the compatibility gate freezes implementation details. About twenty-five packages have no importer in the sensor, the platform or the asset collector; `pkg/transport/grpc` is unused and pulls grpc-go into every sensor.
2. **Overlapping contracts.** Thirteen interfaces describe a data-producing component; the runtime dispatches three. None declares what it consumes or produces, its intrusiveness, its permissions or its resources, so the platform cannot plan with it and the runtime cannot enforce it.
3. **Implicit behaviour.** Tools return raw bytes and the runtime guesses the format; optional capabilities are found by type assertion; asset attribution is a separate callback; errors carry no category; there is no streaming, progress, log or artifact channel for tools.
4. **Go only, in-process.** A tool must be Go and compiled into the sensor; adding one needs a sensor release. Until the Executor lands, tools share the sensor's process.
5. **No language-neutral path.** No published spec for the sensor protocol or a tool protocol, no runnable local platform, no scaffolding, no conformance outside Go tests.
6. **Two runtimes in the sensor.** The daemon uses the kit; the CI path is hand-wired.

The goal: an outside team connects its tool or sensor in minutes, in the language it already uses, without weakening any guarantee the platform and the network owner rely on.

## Goals and non-goals

Goals: one tool contract; the lightest integration rung first; the same guarantees for built-in and third-party tools; a public API small enough to keep stable for years; language-neutral, conformance-tested contracts.

Non-goals: running tools inside the sensor process; a remote shell or any inbound port on the sensor; host-level container management by the sensor (the Executor backends use rootless runtimes or a Pod per task, never the host's Docker socket); running third-party code before sandbox enforcement and artifact signing exist.

## Vocabulary

| Term | Meaning |
|---|---|
| Sensor | The deployable runtime (one binary or image) |
| Mode | `daemon` (long-lived, receives jobs) or `runner` (ephemeral, CI) |
| Tool | Any workload a sensor runs, described by a manifest; built-in or adapter |
| Adapter | A tool running as its own program, speaking adapter protocol v1 |
| Executor | The runtime component that runs one task in a sandbox through a backend |
| sensorkit | The single Go runtime implementation |
| CTIS | The one output schema |

## Design

### D.1 Principles

1. **One contract for every tool.** A tool is described by one manifest and implements one interface (or one wire protocol). Target scanners, connectors, parsers and enrichers differ by *execution class* in the manifest, not by Go interface.
2. **Author in-process, execute out of process.** A Go author writes an ordinary function. The runtime always runs it in a separate, sandboxed process through the Executor, speaking the same adapter protocol a Python or shell tool speaks. Tests may run it in-process; a sensor never does.
3. **The runtime owns every guarantee.** Admission against policy, sandboxing, credentials, output validation, provenance, delivery and transport are done by `sensorkit`, outside the tool's reach. No option, interface or setting lets tool code skip them.
4. **Small public surface, hard internal boundary.** Public packages are the developer contract, the runtime façade and the test tools. Everything else is `internal/`, so it can change without breaking anyone and without the api-compat gate freezing implementation details.
5. **Language-neutral first.** Every contract (manifest, adapter protocol, sensor protocol v3, CTIS, settings, local policy, config report) is published as a schema (JSON Schema or protobuf) with a conformance suite that runs against any implementation. The Go SDK is the reference implementation, not the definition.
6. **Lightest rung first.** Push → zero-code tool (manifest only) → tool in any language → custom Go sensor → sensor in another language. Each rung is documented, scaffolded and testable on its own.

### D.2 Package layout

```
github.com/openctemio/sdk-go
├── pkg/tool/                 STABLE   the developer contract
│   ├── tool.go                        Tool, New[C], Manifest, Task, Target, Context, Emitter
│   ├── errors.go                      Error, Class, constructors
│   ├── manifest.go                    Manifest types, Load/Validate tool.yaml, JSON Schema export
│   ├── adapter/              STABLE   Serve(tool): run a Tool as an adapter process (protocol v1)
│   ├── toolexec/             STABLE   run a CLI safely inside the task (env allow-list, extra-arg
│   │                                  checks, process group, output caps, line streaming)
│   └── parse/                STABLE   helpers: SARIF → CTIS, JSON lines, XML; wrap ctis converters
├── pkg/sensorkit/            STABLE   the one runtime: Main, New, Kit.Run, Kit.RunOnce, Options
│   ├── settings/             STABLE   settings registry
│   ├── doctor/               BETA     Check interface and Result, for sensor-added checks
│   ├── executor/             BETA     Backend interface + process backend
│   └── policy/               STABLE   local/managed policy load, validate, explain (for sensor CLIs)
├── pkg/ctis/                 STABLE   CTIS types (re-export of github.com/openctemio/ctis) + builders
├── pkg/push/                 STABLE   rung 0: push a CTIS or SARIF file with a scoped ingest token
├── pkg/httpsec/              STABLE   SSRF-safe HTTP clients (unchanged)
├── pkg/testkit/              STABLE   run a tool against a fake task; golden CTIS; selftest fixtures
├── pkg/conformance/          STABLE   fake platform + sensor suite + tool/adapter suite
├── pkg/sensorproto/v2/       FROZEN   wire v2 types (kept for v2 sensors); legacyv1 FROZEN
├── pkg/x/...                 EXPERIMENTAL  no promise (new ideas incubate here)
├── cmd/openctem/                      the developer CLI (init, validate, run, test, dev, push, migrate)
├── cmd/openctem-conformance/          the conformance runner (also shipped as a container image)
└── internal/
    ├── runtime/identity               enrollment, sensor key, client-certificate rotation, key renewal
    ├── runtime/transport              Transport interface: v3 (gRPC | Connect/HTTPS), v2, v1
    ├── runtime/control                control stream, actions (pause, drain, cancel, run_checks, …)
    ├── runtime/dispatch               claim, leases, slots, capacity, refusal re-queue
    ├── runtime/task                   the task pipeline (D.7)
    ├── runtime/adapterhost            adapter protocol v1, runtime side
    ├── runtime/emit                   CTIS assembly, validation, caps, provenance stamping
    ├── runtime/outbox                 durable encrypted queue (today pkg/outbox)
    ├── runtime/policy                 evaluation of L0..L4 (today core local_policy*)
    ├── runtime/content                managed content (templates, rules, databases)
    ├── runtime/creds                  credential broker
    └── wire/…                         protocol clients (today pkg/client, pkg/platform, pkg/chunk, pkg/retry)
```

The language-neutral contracts live outside sdk-go, in a leaf module both the platform and the SDK import (decision S6):

```
github.com/openctemio/protocol
├── proto/openctem/sensor/v3/*.proto        sensor ↔ platform (buf lint + buf breaking in CI)
├── gen/go/openctem/sensor/v3/              generated Go (protobuf + Connect)
├── schema/tool/v1/tool.schema.json         tool.yaml
├── schema/adapter/v1/*.schema.json         adapter protocol messages
├── schema/sensor-policy/{local.v1,local.v2,managed.v1}.schema.json
├── schema/sensor-settings/v1.schema.json   settings export format (x-octm-*)
├── schema/config-report/v1.schema.json
└── openapi/sensor-v3-https.yaml            the HTTPS (Connect JSON) binding, generated
```

CTIS keeps its own module and schemas (`github.com/openctemio/ctis`).

#### What a newcomer learns

| Journey | Packages | Concepts |
|---|---|---|
| Push results | `pkg/push` (or `curl`) | token, CTIS or SARIF |
| Write a tool (Go) | `pkg/tool` | `tool.New`, `Manifest`, `Task`/`Target`, `Context` (Emit, Log, HTTP, Progress), error helpers |
| Write a tool (any language) | none | `tool.yaml`, adapter protocol v1 (or the language SDK) |
| Wrap a CLI with no code | none | `tool.yaml` with `run.profile: exec` |
| Write a sensor (Go) | `pkg/sensorkit` (+ `settings`, `doctor` if needed) | `sensorkit.Main`, `Options` |
| Test any of the above | `pkg/testkit`, `cmd/openctem` | `testkit.Run`, golden files, selftest fixtures |

### D.3 The tool contract (`pkg/tool`)

#### D.3.1 Interface

```go
package tool

// Tool is the one contract for every workload a sensor runs.
type Tool interface {
	Manifest() Manifest
	Run(ctx Context, task Task) error
}

// Validator is optional: semantic checks beyond the manifest's schemas,
// run before any target is touched (and by `openctem validate --task`).
type Validator interface {
	Validate(ctx context.Context, task Task) error
}

// New builds a Tool from a manifest and a typed run function. C is the
// tool's configuration: the runtime validates the task's config against
// the manifest's config schema, then New decodes it into C (unknown keys
// refused). When m.Config is nil the schema is derived from C's struct
// tags (json, default, min, max, enum, pattern, maxItems, secret:"true"
// is refused: secrets are credentials, never config).
func New[C any](m Manifest, run func(ctx Context, task Task, cfg C) error) Tool

// NoConfig is the C of a tool without configuration.
type NoConfig struct{}
```

There is nothing else to implement: no `Name()`, `Version()`, `IsInstalled()`, `Capabilities()`, `Type()` methods. They are manifest fields. Installation state is the self-test and the runtime's probe (D.3.6).

#### D.3.2 Manifest (`tool.yaml`, `apiVersion: openctem.io/tool/v1`)

```go
type Manifest struct {
	Name        string   // ^[a-z][a-z0-9-]{1,62}$, unique per sensor
	Version     string   // semver of the tool adapter
	Description string
	Class       Class    // TargetScan | Connector | Parser | Enricher
	Modes       []Mode   // Daemon, Runner; empty = both
	Tier        Tier     // T0 passive | T1 active, non-intrusive | T2 intrusive
	Capabilities []string // stage catalogue ids ("vuln.templates", "web.probe", …)
	Consumes    []string // CTIS asset types ("http_service", "domain", "repository", …),
	                     // or "file:<media type>" for parsers
	Produces    []string // "asset:<type>", "finding:<type>", "dependency"
	Config      *Schema  // JSON Schema, RFC-038 subset (UI hints via x-octm-*)
	Inputs      *Schema  // optional extra task inputs (e.g. a scan profile id)
	Permissions Permissions
	Resources   Resources
	Selftest    []Fixture // golden input → expected CTIS (or a directory)
	Protocol    Range     // adapter protocol versions, e.g. {Min: 1, Max: 1}
	Run         *RunSpec  // how to start it (non-Go tools, or a Go tool shipped as its own binary)
	Artifact    *ArtifactRef // catalogue only: image or binary digest + signature
}

type Permissions struct {
	Network      Network         // None | Targets | EgressProxy | Vendor
	VendorHosts  []string        // Vendor only; may reference config ("${config.base_url}")
	Filesystem   FS              // Workdir (default) | ScanRootsReadOnly
	Credentials  []CredentialReq // {Name, Kind, Required}; delivered by the broker
	LinuxCaps    []string        // e.g. NET_RAW for SYN scans; granted only if local policy allows
}

type Resources struct {
	CPU            float64
	MemoryBytes    int64
	Timeout        time.Duration // wall time per task
	IdleTimeout    time.Duration // no message for this long → killed (default 10m)
	MaxOutputBytes int64         // CTIS bytes per task (default 64 MiB)
	MaxRecords     int           // records per task (default 200k)
	Cost           int           // slot cost for the capacity model
}
```

`tool.yaml` example (a CLI that already writes SARIF, no code at all):

```yaml
apiVersion: openctem.io/tool/v1
name: acme-lint
version: 1.4.0
class: target-scan
modes: [runner, daemon]
tier: T0
capabilities: [code.sast]
consumes: [repository]
produces: [finding:vulnerability, finding:misconfiguration]
config:
  type: object
  additionalProperties: false
  properties:
    ruleset: {type: string, enum: [default, strict], default: default}
permissions: {network: none, filesystem: scan-roots-read-only}
resources: {cpu: 1, memory: 1Gi, timeout: 20m}
run:
  profile: exec
  argv: [acme-lint, --format, sarif, --ruleset, "{{config.ruleset}}", "{{target.path}}"]
  output: {format: sarif, from: stdout}
selftest: fixtures/
protocol: {min: 1}
```

Rules the manifest validator enforces (CI and runtime):
- the class constrains permissions: `parser` and `enricher` default to `network: none`; `connector` must use `vendor` with hosts; only `target-scan` may use `targets`;
- `produces` must be non-empty and drawn from the CTIS vocabulary; `consumes` must name CTIS asset types or `file:` media types;
- `T2` requires `class: target-scan`;
- the config schema follows the RFC-038 subset (`additionalProperties: false`, bounded strings and arrays, RE2 patterns), and contains no secret fields;
- `run.argv` placeholders are a closed set (`{{config.<key>}}` of scalar type, `{{target.*}}`, `{{task.targets_file}}`, `{{task.config_file}}`, `{{task.output}}`, `{{task.workdir}}`); never a shell; every expanded value is checked against the dangerous-flag list exactly as user extra args are today.

#### D.3.3 Task and targets

```go
type Task struct {
	ID       string
	Attempt  int
	Deadline time.Time
	Targets  []Target         // already admitted by the runtime (D.7)
	Config   json.RawMessage  // already validated against Manifest.Config
	Inputs   []Input          // parser input files, placed in the workdir
	Repo     *Repo            // runner mode: repository, branch, commit, PR (from workload identity)
	Scope    Scope            // the job's scope, read-only (for tools that expand targets)
}

type Target struct {
	Ref   string            // opaque reference; links records to the platform asset
	Type  string            // CTIS asset type
	Value string            // "https://a.example:8443", "10.0.4.7", "/src"
	Attrs map[string]string // typed hints from the platform (port, scheme, tech, …)
}

func (t Target) URL(path string) string
func (t Target) Host() string
func (t Target) Port() int
```

A tool that discovers new targets (a crawler, a subdomain enumerator) emits them as assets. It never scans them in the same task: expansion is a new stage the platform plans, so every target passes the ownership gate and the policy.

#### D.3.4 Context

```go
type Context interface {
	context.Context                       // cancelled on cancel, deadline or kill switch

	Log() *slog.Logger                    // structured; secrets redacted; bounded rate and size
	Progress(done, total int, msg string) // throttled by the runtime
	Emit() Emitter
	TargetDone(t Target)
	TargetError(t Target, err error)      // per-target outcome → scan coverage
	Artifact(name, mediaType string) (io.WriteCloser, error) // size-capped; uploaded separately
	Workdir() string                      // private, wiped after the task
	Secret(name string) (Secret, error)   // only credentials the manifest declares and policy grants
	HTTP() *HTTPClient                    // per Permissions.Network; context-bound; SSRF-guarded
	Dialer() Dialer                       // same rules for non-HTTP protocols
}

// Secret redacts itself in String, GoString, Format, MarshalJSON and MarshalText.
type Secret struct{ /* unexported */ }
func (s Secret) Reveal() string // explicit; never logged by the SDK
```

`HTTP()` and `Dialer()` are convenience and defence in depth. The boundary is the Executor backend's network class (D.9): a tool that opens raw sockets meets the backend, not the helper.

#### D.3.5 Emitter

```go
type Emitter interface {
	Asset(a ctis.Asset) error
	Finding(t Target, f ctis.Finding) error // links f to t's asset (asset_ref/value/type)
	Dependency(t Target, d ctis.Dependency) error
	Report(r *ctis.Report) error            // bulk, e.g. the output of parse.SARIF
}
```

Each call is checked when it is made, so a tool learns about a bad record at the line that produced it:
- the record validates against CTIS (required fields, enums, lengths);
- its kind is in `Manifest.Produces`, else `ErrUndeclaredOutput`;
- counts and bytes stay under `Resources.MaxRecords` / `MaxOutputBytes`, else `ErrOutputLimit` (the tool should stop; the task ends `partial`);
- control and bidirectional characters are stripped, strings capped;
- provenance fields (tool name, version, digest, sandbox status, sensor, task) are **overwritten** by the runtime: a tool cannot claim to be another tool.

The runtime repeats every check on its side of the process boundary (D.7 step 7). The in-tool checks exist for the author's feedback; the runtime's checks are the guarantee.

#### D.3.6 Errors

```go
type Class string

const (
	InvalidInput      Class = "invalid_input"      // config or targets wrong; not retried
	TargetUnreachable Class = "target_unreachable" // per target; retried on the next run
	RefusedByPolicy   Class = "refused_by_policy"  // scope or local policy; re-queued elsewhere (RFC-040 refusal re-queue)
	Transient         Class = "transient"          // retry with back-off
	RateLimited       Class = "rate_limited"       // retry after RetryAfter
	AuthFailed        Class = "auth_failed"        // connector credentials
	PermissionDenied  Class = "permission_denied"
	NotFound          Class = "not_found"
	ToolError         Class = "tool_error"         // the tool failed; not retried by default
	// Set by the runtime only:
	Timeout, Cancelled, ResourceExhausted, OutputRejected, ToolCrashed Class = …
)

type Error struct {
	Class      Class
	Retryable  bool          // defaults from Class; a tool may only turn it off
	RetryAfter time.Duration
	Detail     string        // redacted by the runtime; capped at 256 bytes
	Err        error         // local only; never sent
}

func Unreachable(err error) error
func Retry(err error) error
func RateLimit(after time.Duration, err error) error
func Refused(reason string) error
func Invalid(format string, args ...any) error
func Failed(err error) error
```

A plain `error` returned from `Run` is `tool_error`. The classes map one to one onto the connector taxonomy of RFC-049 (`invalid_config`↔`invalid_input`, `unreachable`↔`target_unreachable`/`transient`, `blocked_by_policy`↔`refused_by_policy`, `upstream_error`↔`transient`), so connector runs and tool runs report errors the same way.

Task outcome: `ok` (every target done), `partial` (some targets failed or output was capped), `failed`, `cancelled`.

#### D.3.7 Execution classes

| Class | Touches | Network default | Credentials | Consumes → produces | Dispatch rules |
|---|---|---|---|---|---|
| `target-scan` | customer targets | `targets` (job targets only, through the zone's egress) | none (authenticated scanning later, via the broker) | asset types → assets, findings | ownership gate, tier gate, local policy target checks |
| `connector` | a vendor API | `vendor` (declared hosts only) | required, by reference (sensor-local store) | none / instance → assets, findings | RFC-049 relay commands, sensor-pinned instance |
| `parser` | a file | `none` | none | `file:<media type>` → findings, dependencies, assets | runner mode or an upload job |
| `enricher` | CTIS records | `none` or `vendor` | optional | `finding:*` → `finding:*` (annotations only) | never creates assets; cannot change asset identity |

#### D.3.8 Minimal tool (Go, about 15 lines)

```go
package dotenv

import "github.com/openctemio/sdk-go/pkg/tool"

var Tool = tool.New(tool.Manifest{
	Name: "dotenv-check", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	for _, t := range task.Targets {
		resp, err := ctx.HTTP().Get(t.URL("/.env"))
		if err != nil {
			ctx.TargetError(t, tool.Unreachable(err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			ctx.Emit().Finding(t, tool.Misconfig("dotenv-exposed", ".env file is publicly readable", tool.High))
		}
		ctx.TargetDone(t)
	}
	return nil
})
```

#### D.3.9 The same tool in Python

```python
from openctem_tool import tool, misconfig, HIGH, Unreachable

@tool(name="dotenv-check", version="1.0.0", cls="target-scan", tier="T1",
      consumes=["http_service"], produces=["finding:misconfiguration"], network="targets")
def run(ctx, task, config):
    for t in task.targets:
        try:
            r = ctx.http.get(t.url("/.env"))
        except Unreachable as e:
            ctx.target_error(t, e)
            continue
        if r.status_code == 200:
            ctx.emit.finding(t, misconfig("dotenv-exposed", ".env file is publicly readable", HIGH))
        ctx.target_done(t)

if __name__ == "__main__":
    run.serve()      # adapter protocol v1 on stdin/stdout; `--describe` prints the manifest
```

`openctem manifest export -- python3 dotenv.py` writes `tool.yaml` from `--describe`; the file is what gets reviewed, signed and loaded (D.4.4).

### D.4 In-process authoring, out-of-process execution

#### D.4.1 Three ways a tool reaches the runtime, one protocol

| Tool | How the runtime starts it | Protocol |
|---|---|---|
| Go tool compiled into the sensor (`Options.Tools`) | re-executes the sensor's own binary as `<sensor> __openctem-tool <name>` inside the Executor sandbox (the same multi-call pattern the process backend's launcher already uses) | adapter v1 |
| Go tool shipped as its own binary (`adapter.Serve(Tool)` in `main`) | `run.argv` from its `tool.yaml` | adapter v1 |
| Any other language (Python SDK, or hand-written) | `run.argv` | adapter v1 |
| A CLI wrapped with no code | `run.profile: exec` | exec profile (D.4.3) |

The runtime never calls `Tool.Run` in its own process. Only `pkg/testkit` does, so authors get a debugger and fast tests; `testkit.RunIsolated` runs the same test through the real process backend.

Why re-execute instead of calling in-process: the runtime can then apply the per-task sandbox (private workdir, rlimits, no_new_privs, Landlock, seccomp, process-group kill), deny the tool the sensor's key, outbox, credentials and policy files, and kill it without killing the sensor. The cost is one `exec` per task (milliseconds) against scans that run seconds to hours.

#### D.4.2 Adapter protocol v1

**Transport.** The adapter's stdin and stdout, UTF-8, newline-delimited JSON (one message per line). stderr is free-form diagnostics: captured, redacted, capped (64 KiB per task kept), never parsed. A Unix socket binding with the same messages is reserved for long-lived adapters (v1.1, not in v1).

**Limits.** A line is at most 1 MiB (larger data goes through an artifact). The runtime announces its limits in `hello`; it kills the adapter with `output_rejected` on a longer line, invalid UTF-8, or more than 1,000 invalid messages.

**Process model.** One task per process. The process ends after `result`. A fresh sandbox per task means no state, credential or file leaks from one task (or tenant) to the next.

**Envelope.** `{"v":1,"type":"<type>", …}`. Unknown `type` values from the other side are ignored (forward compatibility), except during the handshake.

Runtime → adapter:

| Type | Fields | Notes |
|---|---|---|
| `hello` | `protocol: [1]`, `runtime: {name, version, os, arch}`, `limits: {max_line, max_records, max_output_bytes, max_artifact_bytes}`, `features: ["artifacts","progress","credentials","target_status"]` | first message |
| `describe` | — | answer `manifest` |
| `validate` | `task` | answer `validation` |
| `run` | `task: {id, attempt, deadline, targets[], config, inputs[], workdir, credentials: [{name, file}], repo?, scope}` | starts the task |
| `cancel` | `reason` | then SIGTERM after `grace` (default 10 s), SIGKILL after 2×grace |

Adapter → runtime:

| Type | Fields | Notes |
|---|---|---|
| `hello` | `protocol: 1`, `sdk: {name, version}`, `features: […]` | chosen version; mismatch → `tool_error` "protocol" |
| `manifest` | `manifest` | must equal the loaded `tool.yaml` (digest compare) |
| `validation` | `ok`, `errors: [{path, message}]` | `path` is a JSON pointer |
| `log` | `level`, `msg`, `fields` | redacted, rate-limited |
| `progress` | `done`, `total`, `msg` | throttled to 1/s upstream |
| `record` | `kind: asset|finding|dependency`, `target`, `data` (one CTIS object) | validated on arrival |
| `target_status` | `target`, `status: done|failed|skipped`, `error?: {class, detail}` | coverage |
| `artifact` | `name`, `media_type`, `path` (relative to workdir), `sha256`, `size` | runtime opens it beneath the workdir (no symlink escape), checks size and digest |
| `heartbeat` | — | keeps a quiet adapter alive under `idle_timeout` |
| `result` | `status: ok|partial|failed|cancelled`, `error?: {class, retryable, retry_after_ms, detail}`, `stats` | final; exit 0 afterwards |

Exiting without `result` is `tool_crashed`. A `result` claiming `ok` while targets were never reported is downgraded to `partial` by the runtime.

Example exchange:

```json
{"v":1,"type":"hello","protocol":[1],"runtime":{"name":"openctem-sensor","version":"0.12.0"},"limits":{"max_line":1048576,"max_records":200000}}
{"v":1,"type":"hello","protocol":1,"sdk":{"name":"openctem-tool-python","version":"0.1.0"}}
{"v":1,"type":"run","task":{"id":"t-81","attempt":1,"deadline":"2026-10-05T12:30:00Z","targets":[{"ref":"a1","type":"http_service","value":"https://shop.example"}],"config":{},"workdir":"/run/task"}}
{"v":1,"type":"record","kind":"finding","target":"a1","data":{"type":"misconfiguration","rule_id":"dotenv-exposed","title":".env file is publicly readable","severity":"high"}}
{"v":1,"type":"target_status","target":"a1","status":"done"}
{"v":1,"type":"result","status":"ok","stats":{"records":1}}
```

#### D.4.3 The exec profile (zero-code tools)

For a CLI that already writes CTIS or SARIF:
- the runtime writes `targets.json` / `targets.txt` and `config.json` into the workdir;
- it expands `run.argv` placeholders (closed set, typed, no shell, dangerous-flag check);
- it runs the command in the sandbox and reads `run.output` (`from: stdout | file`, `format: ctis | sarif | jsonl-ctis`);
- it converts SARIF with the shared converter, then applies the same emitter checks;
- exit codes are mapped by `run.exit_codes` (`{0: ok, 1: ok, 2: tool_error}`; default 0 = ok, anything else = `tool_error`).

The exec profile has no progress, no per-target status (all targets share the outcome) and no artifacts. It exists so that "add my scanner" can be a 20-line YAML file.

#### D.4.4 Manifest trust

The runtime trusts the **file**, never the adapter's self-description:
- built-in tools: manifests embedded in the signed sensor binary;
- adapter directories (`AdapterDirs`): `tool.yaml` plus its artifact, signature-verified when the catalogue is on, and allowed by the local policy's tool allow-list;
- `describe` must return the same manifest (canonical digest); a mismatch refuses the tool at load time;
- the manifest is registered with the platform in the sensor manifest (`tools[].manifest`, content-addressed like RFC-038 schemas), so the planner and the UI use the same consumes/produces/tier/permissions the sensor enforces.

### D.5 The runtime (`pkg/sensorkit`)

#### D.5.1 API

```go
package sensorkit

type Options struct {
	Name, Version string

	Tools       []tool.Tool    // Go tools compiled in; run out of process
	AdapterDirs []string       // directories of tool.yaml + adapters (any language)

	Settings func(r *settings.Registry) // the sensor's own settings
	Checks   []doctor.Check             // the sensor's own preflight checks

	// Advanced.
	Executor executor.Backend        // nil: from SENSOR_EXECUTOR (process)
	Commands map[string]CommandHandler // custom command types (beta; see D.9)

	// Overrides set settings from code (tests, embedding); same validation
	// as env/flags/file. There is no other way to configure the runtime.
	Overrides map[string]string
}

// Main is the whole program: it dispatches the hidden launcher and tool
// re-exec entry points, the sub-commands (daemon is the default; run,
// doctor, policy, tools, version), signals and exit codes. It never returns.
func Main(opts Options)

func New(opts Options) (*Kit, error)
func (k *Kit) Run(ctx context.Context) error                          // daemon mode
func (k *Kit) RunOnce(ctx context.Context, r RunRequest) (*RunReport, error) // runner mode (CI)
```

As implemented in S1-6 (before `Main` and the settings-only `Options`): `Options.Tools` already names the operator's tool allow-list (`SENSOR_TOOLS`), so compiled-in tools are added with `Kit.AddTool(t)` (a legacy scanner through `toolcompat.FromScanner`); `Options.AdapterDirs` (`SENSOR_ADAPTER_DIRS`) loads operator-installed `tool.yaml` files, only from files no other user can change and only with a run section; `Options.ToolCredentials` supplies the operator's credentials, of which only the declared ones are delivered, inside the task's run message on the adapter's stdin (never the environment, argv or a file another task could read). Each tool is served to the existing command executor through `toolcompat.AsScanner`, so the outbox, scheduling, heartbeat and manifest paths are unchanged; every task is admitted (`toolhost.Admit`) against the local policy in force and runs out of process.

Today's `sensorkit.Options` has about 45 fields that mirror environment settings. In v1 those are settings in the registry (resolved from flags > env > file > default, with provenance and doctor checks), and `Options` keeps only what must be code. One way to configure means one place to validate and one place to report.

`Main` gives every sensor the same command line:

```
<sensor>                       daemon (default)
<sensor> run <tool> [--target …] [--config k=v] [--push] [--fail-on …]   runner mode
<sensor> doctor [--json] [--offline]
<sensor> policy validate|digest|explain|install
<sensor> tools [--json]        loaded manifests and their status
<sensor> version
```

Runner and daemon share the same kit, task pipeline and checks. Today the sensor has two runtimes (the kit for the daemon, a hand-written one-shot path with its own handlers); they merge.

#### D.5.2 Minimal sensor (Go, about 20 lines)

```go
package main

import (
	"github.com/openctemio/sdk-go/pkg/sensorkit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/settings"
	"github.com/openctemio/sdk-go/pkg/tool"

	"example.com/acme/tools/dotenv"
	"example.com/acme/tools/feed"
)

var version = "dev"

func main() {
	sensorkit.Main(sensorkit.Options{
		Name: "acme-sensor", Version: version,
		Tools:       []tool.Tool{dotenv.Tool, feed.Tool},
		AdapterDirs: []string{"/opt/acme/tools"}, // tool.yaml + adapters in any language
		Settings: func(r *settings.Registry) {
			r.Register(settings.Setting{Name: "ACME_FEED_URL", Type: settings.URL, Group: "tools",
				Description: "Base URL of the internal feed the feed connector reads"})
		},
	})
}
```

That program enrolls, holds its identity, negotiates transport v3 with fallback, keeps the control stream, reports its manifest, settings and checks, claims jobs within capacity, enforces the local and managed policy, runs each task sandboxed, validates and stamps output, delivers it exactly once through the encrypted outbox, renews its credentials, drains on SIGTERM, and offers `run`, `doctor`, `policy` and `tools`. The smallest sensor is `sensorkit.Main(sensorkit.Options{Name: "x", Tools: []tool.Tool{dotenv.Tool}})`.

#### D.5.3 Work already landed, placed in the layout

| Landed | Where it lives | Change needed |
|---|---|---|
| Executor + `process` backend (`Backend`, `TaskSpec`, `Limits`, `NetworkClass`, `Status`, launcher re-exec, Landlock, seccomp, rlimits) | `pkg/sensorkit/executor` (decision S3, done) | Add to `TaskSpec`: `Stdin io.Reader` (adapter protocol), `ReadOnlyPaths` (scan roots), `Credentials` (broker files), and to `Status`: `NetworkEnforced bool`. The task pipeline is its only caller; `core.ExecuteScanner` keeps routing through it until removed. |
| Settings registry, doctor, config report | `pkg/sensorkit/settings`, `pkg/sensorkit/doctor`; the report's wire types move from `core` to the protocol module | `doctor.Check` becomes a public interface (sensors add checks via `Options.Checks`); the registry replaces most `Options` fields (D.5.1); tool manifests add `tool.<name>.selftest` checks automatically. |
| Local policy v2 + SIGHUP reload, structured refusal | `internal/runtime/policy`, public `pkg/sensorkit/policy` for CLIs | The refusal maps to `refused_by_policy` with the rule; manifest permissions join the admission (D.7 step 3). |
| Outbox one-hour outage test | `internal/runtime/outbox` | none |

### D.6 Testing

#### D.6.1 `pkg/testkit`

```go
func TestDotenv(t *testing.T) {
	srv := testkit.HTTP(t, testkit.Routes{"/.env": {Status: 200, Body: "KEY=1"}})
	res := testkit.Run(t, dotenv.Tool, testkit.Task{
		Targets: []tool.Target{testkit.Target("http_service", srv.URL)},
	})
	res.RequireStatus(t, tool.OK)
	res.Golden(t, "testdata/dotenv.golden.json") // normalized CTIS; `go test -update` rewrites
}

func TestSelftest(t *testing.T)   { testkit.Selftest(t, dotenv.Tool) }        // manifest fixtures
func TestIsolated(t *testing.T)   { testkit.RunIsolated(t, dotenv.Tool, task) } // real sandbox
func TestMain(m *testing.M)       { testkit.Main(m) }                            // enables RunIsolated
```

- `testkit.Run` runs in-process with a fake `Context` that applies the runtime's rules: undeclared output, caps, a network class that refuses hosts outside the task's targets, undeclared secrets. A tool that would be stopped in production fails its unit test.
- Golden files hold normalized CTIS: sorted, ids and timestamps removed, provenance replaced by placeholders.
- `testkit.Selftest` runs every fixture in the manifest; the same fixtures run in `openctem test`, in the conformance suite and in the sensor's `doctor` (`tool.<name>.selftest`), so "installed" means "produces the expected output", not "the binary exists".
- Test doubles: `testkit.HTTP`, `testkit.DNS`, `testkit.TCP` (banner servers), `testkit.Secret`, `testkit.Clock`.

#### D.6.2 Conformance

| Suite | Checks | Run as |
|---|---|---|
| Tool (adapter) | handshake and version choice; `describe` equals `tool.yaml`; `validate` refuses invalid config; selftest fixtures → golden CTIS; `cancel` honoured within grace; nothing but protocol on stdout; caps respected; error classes valid; unknown messages ignored; oversized line handled | `conformance.RunToolSuite(t, conformance.Command("python3", "dotenv.py"))`, `openctem test`, container |
| Sensor | today's suite (heartbeat identity, manifest, unknown command types, forward-compatible decoding, command to completion) plus: v3 on both bindings, fallback reasons, control-stream actions, signed job verification, policy refusal and re-queue, exactly-once delivery across a disconnect, config report, capacity | `conformance.RunSensorSuite(t, start, opts)`, container (acts as the platform the sensor connects to) |
| Platform (for our api) | the server half of v3/v2 against recorded sensor traffic | api CI |

Suites take a `conformance.T` (the subset of `testing.TB` they use), so the same code runs under `go test` and under the CLI. The container `ghcr.io/openctemio/conformance:<version>` (signed, digest-pinned) runs `tool <dir>` or `sensor --listen :8443` and writes a human report and JUnit XML. Passing the suite at a given version is what "compatible" means in the catalogue.

### D.7 The task pipeline (security-critical order)

1. **Job in.** Verify the job envelope (RFC-040: signature by the separate signer, nonce, expiry, sensor binding). The tenant comes from the transport identity, never from the message.
2. **Resolve the tool** by name to its loaded manifest (embedded or signed `tool.yaml`, catalogue pin when enabled).
3. **Admission.** Effective permission = manifest ∩ L0 built-in ∩ L1 local policy ∩ L2 managed policy ∩ job. Check the tier against `tiers.max`, each target against the target guard (private ranges need both switches, metadata endpoints refused, local deny lists). Refused targets get `refused_by_policy`; a fully refused job is released for another sensor (RFC-040 refusal re-queue).
4. **Validate input.** Config against the manifest schema (strict); extra arguments against the dangerous-flag list; inputs against declared media types and sizes.
5. **Credentials.** The broker writes only declared and granted credentials into a per-task file (mode 0400, tmpfs where available) and passes its path. Wiped at the end.
6. **Execute.** `executor.Backend.Prepare(TaskSpec{…})` with limits = manifest ∧ policy, the network class, the write and read-only paths and the protected paths denied; then start the adapter.
7. **Stream.** The adapter host validates every message and record (schema, produces, caps, sanitization), stamps provenance (tool, version, artifact digest, sandbox `Status`, sensor, task), assembles CTIS and writes it to the encrypted outbox in segments.
8. **Deliver.** Resumable, chunked, exactly-once upload bound to the command (lease epoch echo); logs streamed (redacted, capped); artifacts through their own upload; the command completed with outcome and error class.
9. **Clean up.** Kill the process group, wipe the workdir and credentials, release the slot, record duration and cost for the capacity model.

### D.8 Transport v3 behind the SDK

#### D.8.1 Proto layout (in the protocol module)

```
proto/openctem/sensor/v3/
  common.proto     Limits, Feature, Problem (error detail), Outcome, ErrorClass
  identity.proto   IdentityService: Enroll, RenewCertificate, RotateKey
  control.proto    ControlService: Hello, Subscribe (server stream), Heartbeat,
                   PutManifest, PutConfigReport, PutSettingsSchema, AckAction
  jobs.proto       JobService: Claim, Start, Progress, Complete, Release, Refuse
  results.proto    ResultService: Begin, PutSegment, Commit, Status, Abandon
  logs.proto       LogService: Append (batched)
  artifacts.proto  ArtifactService: Create, PutChunk, Finish
```

- Served with Connect, so one handler answers gRPC (primary, HTTP/2, mTLS) and Connect over HTTP/1.1 with JSON (the HTTPS fallback).
- `buf lint` and `buf breaking` gate every change; `protovalidate` constraints on every field (sizes, patterns, enums); no server reflection in production.
- The control channel is **server-streaming `Subscribe` plus unary calls** on both bindings (decision S7): jobs, cancels, pause, drain, `run_checks` and `send_manifest` come down the stream; heartbeats and acknowledgements go up as unary calls. Server streaming works over HTTP/1.1, so both bindings have the same semantics and the same conformance tests. DB leases stay the source of truth; a lost stream loses no job.
- Generated: Go (protobuf + Connect) in the protocol module; an OpenAPI description of the HTTPS binding; Python stubs when the Python sensor SDK starts.

#### D.8.2 Negotiation and fallback

```
SENSOR_TRANSPORT = auto (default) | grpc | https | v2
local policy: transport.fallback = allow (default) | deny
platform policy: tenant "require mTLS" (refuses fallback server-side)

auto:
  1. Hello over gRPC (h2, client certificate)            → use v3/gRPC
  2. on a transport-level incompatibility only:
       ALPN without h2, proxy refuses CONNECT or HTTP/2, stream reset by an intermediary,
       415/426 from a middlebox, gRPC not served (Unimplemented on Hello)
     → Hello over Connect/HTTPS (HTTP/1.1, RFC 9421 signature with the sensor key; client
       certificate too when the path allows it)            → use v3/HTTPS, report the reason
  3. platform without v3 (no Hello)                     → protocol v2 (today's client)
  re-probe the primary every 30 min (jittered); switch back without dropping work
never fall back on: certificate verification failure, pin mismatch, revoked or expired
  identity, 401/403, a policy refusal. Those are errors, not reasons to try a weaker path.
```

The heartbeat carries `transport: {binding, protocol, fallback_reason, since}` and the platform shows it per sensor.

#### D.8.3 What the SDK exposes

Nothing from the proto. `pkg/tool` never mentions transport; `sensorkit` exposes only the `SENSOR_TRANSPORT` setting, the doctor checks (`platform.transport`, `platform.tls`, `identity.certificate`) and the transport in `Kit.Status()`. Internally:

```go
// internal/runtime/transport
type Transport interface {
	Hello(ctx context.Context) (*Hello, error)
	Subscribe(ctx context.Context) (ActionStream, error)
	Heartbeat(ctx context.Context, hb *Heartbeat) (*HeartbeatAck, error)
	Jobs() JobClient
	Results() ResultClient   // resumable segments
	Logs() LogClient
	Artifacts() ArtifactClient
	Binding() Binding        // grpc | https | v2 | v1
}
```

The v2 and v1 implementations wrap today's `pkg/client`, so the v3 work changes no behaviour for existing platforms. Identity (`internal/runtime/identity`) turns the enrollment key (RFC-032) into short-lived client certificates (24 h to 7 days, URI SAN `spiffe://<trust domain>/tenant/<id>/sensor/<id>`), rotates at two thirds of the lifetime, and adds the certificate and key paths to the Executor's protected paths.

### D.9 Security defaults

The SDK protects the operator from tools and protects the customer network from a compromised platform. It cannot protect the platform from a malicious sensor author: the platform's ingest validation and per-sensor authorization do that, and every sensor is treated as untrusted input.

| Control | Default | Who can change it | Can sensor or tool code weaken it? |
|---|---|---|---|
| TLS verification to the platform | always on; platform CA pinned after enrollment | operator adds roots (`SENSOR_CA_CERT_FILE`) | no: there is no skip-verify option anywhere in the public API |
| Sensor identity (key, certificate) | in the state dir, denied to every task | — | no |
| Job authenticity (RFC-040) | verified before admission | operator pins the signer (local policy) | no |
| Policy ceiling (L0/L1) | evaluated by the kit before the Executor | the network owner's local file only | no: admission has no bypass flag and runs for custom command handlers too |
| Target guard (private ranges, metadata endpoints) | refused | two switches (env + local policy) | no |
| Tool sandbox | `auto` (all controls the host supports, missing ones reported) | operator: `off` / `auto` / `required` | no: a manifest can request resources, never lower the mode |
| Network class | from the manifest, intersected with policy | policy narrows | no; untrusted adapters need a backend with `NetworkEnforced` (S12) |
| Credentials | broker; declared ∧ granted only; per-task file; wiped | operator stores them locally | no: tools never see the store, the sensor key or other tasks |
| Secrets in logs | redacting `slog` handler in the kit and in `tool.Context`; `tool.Secret` redacts itself; settings marked secret are reported as presence only; the masker runs over stderr and log streams | — | no |
| Output | validated, size-capped, `produces` enforced, provenance stamped by the runtime | — | no |
| Exec safety (env allow-list, dangerous flags, process group) | in `toolexec` and the process backend | operator extends the env allow-list | no |
| SSRF guard for SDK HTTP clients | on | operator: proxies | no |
| Remote shell, inbound listener, Docker socket | do not exist | — | — |

`Options.Commands` (custom command types) stays beta: each handler is wrapped by the kit's job verification, kill switch, pause and tool allow-list, receives no broker credentials, and runs in the sensor process, so the docs steer every new integration to a tool instead.

### D.10 DX toolkit

#### D.10.1 `openctem` CLI (`cmd/openctem`, one signed static binary)

| Command | Does |
|---|---|
| `openctem init tool --lang go|python|exec --class target-scan|connector|parser|enricher` | scaffold: `tool.yaml`, adapter, fixture, golden test, Makefile, CI file |
| `openctem init sensor --lang go` | scaffold a sensor with one tool, settings, Dockerfile, Helm values |
| `openctem validate <file>` | detects CTIS, SARIF, `tool.yaml`, local policy, settings export; errors with JSON pointer, line:column and a hint |
| `openctem manifest export -- <cmd>` / `manifest check` | write `tool.yaml` from `--describe`; compare the file with `describe` |
| `openctem run <tool.yaml|dir> --target … [--config k=v] [--sandbox auto|required] [--format table|ctis|sarif]` | run a tool through the real Executor and adapter host, offline |
| `openctem test [--update]` | selftest fixtures, golden files and the tool conformance suite |
| `openctem conformance tool|sensor` | the conformance runner (same as the container) |
| `openctem dev` | local platform emulator on 127.0.0.1: issues dev keys (`octdev_`, refused by real platforms), dispatches jobs (`openctem dev dispatch <tool> --target …`), shows received records, validation errors, logs and artifacts in a small web view |
| `openctem push <file> --token …` | rung 0: validate, then push CTIS or SARIF with a scoped ingest token |
| `openctem migrate [v1|sensor] [-dry-run]` | the codemods (absorbs `cmd/sensor-migrate`) |

#### D.10.2 Docs

```
docs/
  README.md                 the integration ladder, lightest rung first
  quickstart/  push.md · tool-exec.md · tool-go.md · tool-python.md · sensor-go.md
  concepts/    tool-contract · manifest · execution-classes · permissions · errors ·
               output-and-provenance · sandbox-and-policy · runner-vs-daemon
  guides/      wrap-a-cli · write-a-connector · write-a-parser · testing · signing-and-publishing ·
               migrating-from-v0
  reference/   tool.yaml (generated) · adapter-protocol-v1 · sensor-protocol-v3 (generated) ·
               settings (generated) · cli (generated) · error-classes · doctor-checks
  STABILITY.md · SECURITY.md · COMPATIBILITY.md
```

#### D.10.3 Examples gallery (each with `tool.yaml`, a test and a README; CI runs all of them)

`exec-sarif-cli` · `go-target-scan` (the dotenv tool) · `go-connector` (vendor API, credentials, cursor) · `go-parser` · `python-target-scan` · `python-parser` · `minimal-sensor` · `sensor-with-settings-and-checks` · `push-curl` · `ci-runner-github` · `ci-runner-gitlab`.

### D.11 Versioning and stability

**Module version (decision S1).** The redesign ships in `github.com/openctemio/sdk-go` as v0.18 … v0.2x and ends at **v1.0.0**. There is no `/v2` module path: "SDK v2" is this design's name, not a Go major version. From v1.0.0, nothing Stable is removed until a `/v2` module.

**Stability tiers** (stated in each package's `doc.go`, enforced by the api-compat job):

| Tier | Promise | Packages |
|---|---|---|
| Stable | no incompatible change within the major version | `tool`, `tool/adapter`, `tool/toolexec`, `tool/parse`, `sensorkit`, `sensorkit/settings`, `sensorkit/policy`, `ctis`, `push`, `httpsec`, `testkit`, `conformance` |
| Beta | may change in a minor, with a `Deprecated:` period of one minor and an upgrade note | `sensorkit/executor` (Backend), `sensorkit/doctor`, `Options.Commands` |
| Frozen | no additions; removal announced on the protocol's sunset | `sensorproto/v2`, `sensorproto/legacyv1` |
| Experimental | none | `pkg/x/...` |
| Internal | none (compiler-enforced) | `internal/...` |

**Protocols and negotiation.**

| Contract | Version | Negotiated by |
|---|---|---|
| Sensor ↔ platform | v1 frozen, v2 maintained, v3 primary | `Hello` features (as today) |
| Runtime ↔ tool | adapter protocol 1, features in `hello` | adapter `hello`; manifest `protocol: {min, max}` |
| Manifest | `openctem.io/tool/v1` | `apiVersion`; unknown fields refused (it is a security document) |
| Output | CTIS 1.x, receiver first (the platform accepts a new member before any sensor sends it) | CTIS `version` |
| Local policy | v1 frozen, v2 opt-in | `policy_schemas` in the manifest |

**Deprecation policy.**
- Go API: `Deprecated:` with the replacement, CHANGELOG entry, at least two minors before removal while < 1.0; after 1.0, no removal of Stable API.
- Protocols: a `deprecations` entry on `Hello` with a sunset date at least six months and three release trains ahead; the platform counts and shows sensors still on the old version.
- Every rename ships with a codemod (`openctem migrate`).

**Compatibility matrix** (published in `COMPATIBILITY.md`, tested in CI with the oldest and newest supported platform):

| SDK | Sensor protocol | Adapter protocol | Platform |
|---|---|---|---|
| ≤ v0.17 | v2 (v1 fallback) | — | all current |
| v0.18–v0.2x | v2; v3 behind a setting once the platform serves it | 1 | v2 platforms; v3 from the release that ships B1 |
| v1.0 | v3 default, v2 fallback | 1 | platforms that serve v3 or v2 |

### D.12 Migration and codemod

| Today | v1 | Migration |
|---|---|---|
| `core.Scanner` (+ `MultiTargetScanner`, `SettingsSchemaProvider`), `core.ScaScanner`, `core.SecretScanner`, `core.ReconScanner`, `core.Collector`, `core.Parser`, `core.Adapter`, `core.Enricher`, `core.Connector`, `core.Provider`, `core.Processor` | `tool.Tool` with a class | `toolcompat.FromScanner(s, manifest)` and `toolcompat.FromCollector(c, manifest)` bridges (deprecated on arrival) keep old code running out of process; the codemod inserts them and the manifest skeleton |
| `core.ScanOptions` / `core.ScanResult` (raw bytes, format sniffing) | `tool.Task` / `Emitter` | manual: emit records or `Emit().Report(parse.SARIF(out))` |
| `core.ExecuteScanner`, `StreamScanner`, `BaseScanner`, `ValidateExtraArgs`, `ScannerEnviron`, `ConfigureScannerProcess` | `toolexec` | codemod renames |
| `core.BaseSensor`, `CommandPoller`, `DefaultCommandExecutor`, `Doorbell`, `ToolRegistry`, template signing, local policy internals | `internal/runtime/*` | use `sensorkit`; aliases kept one minor |
| `pkg/client` | `internal/wire` + `pkg/push` for rung 0 | `client.New(...).PushReport` → `push.New(...).Report` |
| `sensorkit.Options` env-mirroring fields | settings registry, `Options.Overrides` | codemod moves literals into `Overrides` |
| `kit.AddScanner(s, As(n), WithCapabilities(c…))` | `Options.Tools` | codemod + bridge |
| `pkg/transport/grpc`, `proto/openctemio/v1/agent.proto` | deleted (no importer; drags in grpc-go) | none |
| `pkg/{pipeline,audit,health,metrics,errors,options,credentials,compress,mocks,providers,enrichers,adapters}` | deleted | none known (no importer in sensor, api or asset-collector) |
| `pkg/connectors`, `pkg/scanners/tenable` | the connectors module (RFC-049) | per RFC-049 |
| `pkg/gitenv` | sensor `internal/` (runner mode lives there) | sensor PR |

`openctem migrate v1` reuses the type-checked rename engine of `cmd/sensor-migrate` (it renames only identifiers that resolve to SDK objects, refuses on collisions, is idempotent) and adds rewrite rules for the bridges and `Options` fields. It prints the manual steps it could not do.

## Phased implementation plan

Each row is one PR. "After" names what it waits for. Every PR carries a threat model and tenant-isolation note, negative tests (wrong or expired identity refused, hostile and oversized input bounded, secrets never in logs or reports, cross-tenant ids → 404 where the platform is touched) and docs.

### Phase S0 — land the in-flight work in its final place (now, alongside the Executor and config-doctor work)

| # | Repo | PR | After | Acceptance |
|---|---|---|---|---|
| S0-1 | sdk-go | Executor at `pkg/sensorkit/executor` (landed); add `Stdin`, `ReadOnlyPaths`, `Credentials` to `TaskSpec` and `NetworkEnforced` to `Status` | — | the existing hostile-tool tests pass unchanged (key unreadable, no write outside workdir, fork bomb killed); `Status` reports `NetworkEnforced=false` for the process backend |
| S0-2 | sdk-go | config doctor (landed); follow-up moves `core.ConfigReport*` wire types next to the other wire types and makes `doctor.Check` public | #158 | report bytes identical before and after (golden) |
| S0-3 | sdk-go | mark `pkg/transport/grpc`, `proto/openctemio/v1` and the no-importer packages `Deprecated:`; fix the module description (no bundled scanners any more); one minor later delete `pkg/transport/grpc` and `proto/openctemio/v1` and drop the grpc-go dependency (removal follows a released deprecation, `docs/STABILITY.md` §4) | — | deprecation: api-compat green; deletion: `go mod tidy` drops grpc-go, api-compat with the `breaking-change` label, sensor-compat green |
| S0-4 | sdk-go | `STABILITY.md` tiers + `doc.go` tier line per package; api-compat job learns tiers (Beta may break with label + upgrade note) | — | a deliberate break in a Beta package passes with the label, fails without |

### Phase S1 — the tool contract

| # | Repo | PR | After | Acceptance |
|---|---|---|---|---|
| S1-1 | protocol (new) | until the module exists (decision S6, option (c) during the transition) the schemas live in sdk-go next to their Go types (`pkg/tool/schema`) with drift tests; then: module scaffold; `schema/tool/v1/tool.schema.json`; `schema/adapter/v1/*`; CI with schema lint; copy of the local-policy and settings schemas (moved from sdk-go with a drift test during transition) | S6 | 40 manifest cases (valid/invalid) in golden tests; schemas validate with two independent validators |
| S1-2 | sdk-go | `pkg/tool`: Manifest, Task, Target, Context, Emitter, Error, classes; `tool.New[C]` with schema derivation; manifest loader + validator | S1-1 | invalid manifests refused (class/permission mismatch, secret in config, unknown placeholder, T2 on a parser); schema export deterministic |
| S1-3 | sdk-go | `internal/runtime/emit` + `pkg/testkit` (Run, Golden, Selftest, test doubles) | S1-2 | undeclared kind → `ErrUndeclaredOutput`; record and byte caps → `partial`; control/bidi characters stripped; provenance overwritten; golden normalizer stable across runs |
| S1-4 | sdk-go | adapter protocol v1: `pkg/tool/adapter.Serve`, `internal/runtime/adapterhost`, exec profile; `conformance.RunToolSuite` | S1-3, S0-1 | hostile-adapter matrix bounded: garbage lines, a 2 MiB line, stdout flood, no `result`, silent adapter past `idle_timeout`, `describe` ≠ `tool.yaml`, artifact path escaping the workdir by symlink, invalid UTF-8 |
| S1-5 | sdk-go | `pkg/tool/toolexec` (moves the safe-exec helpers out of `core`; old names become deprecated forwarders) | S1-2 | existing exec tests pass against the new package; env allow-list and dangerous-flag tests unchanged |
| S1-6 | sdk-go | task pipeline in the kit: admission with manifest permissions, credential broker v0 (file per task), Executor, adapter host, outbox; in-binary re-exec `__openctem-tool`; `Options.Tools`, `AdapterDirs`; `toolcompat.FromScanner/FromCollector` | S1-4, S1-5 | kit conformance passes for a bridged legacy scanner **and** a new tool; a tool cannot read the sensor key, outbox or credentials of another task; an undeclared credential is never delivered; a refused target is never touched (recording dialer) |
| S1-7 | sensor | port `httpx` and `nuclei` to `pkg/tool` | S1-6 | CTIS identical to before on the golden corpus; undeclared output quarantined; over-limit task killed with a reason |
| S1-8 | sensor | port the remaining built-ins (subfinder, dnsx, naabu, katana, trivy, semgrep, betterleaks, codeql); manifests embedded | S1-7 | golden parity per tool; `sensor tools --json` lists manifests |
| S1-9 | sensor | runner mode on the kit: `sensor run <tool>` replaces the hand-written one-shot path; CI flags kept as aliases | S1-6 | CI templates for both hosts pass unchanged; `-fail-on` and comments behave as before |
| S1-10 | openctem api | accept `tools[].manifest` in the sensor manifest (content-addressed, like RFC-038 schemas); bind output-type quarantine to `produces` (extends #1169); planner reads consumes/produces/tier/class | S1-2 | a report with an undeclared asset type is quarantined; cross-tenant manifest digests never shared; old sensors without manifests unchanged |
| S1-11 | openctem web | tool settings forms rendered from the manifest config schema; tool detail shows class, tier, permissions and self-test status | S1-10 | form renders for every built-in; secret-looking keys never rendered |

### Phase S2 — developer experience

| # | Repo | PR | After | Acceptance |
|---|---|---|---|---|
| S2-1 | sdk-go | `cmd/openctem`: `validate`, `manifest export|check`, `run`, `test`, `init` (go, exec) | S1-4 | `openctem init tool --lang exec` → `openctem test` green with no edits; validator errors carry JSON pointer + line:column |
| S2-2 | sdk-go | `openctem dev` emulator (from the fake platform), loopback-only, dev keys | S2-1 | binds 127.0.0.1 only; `octdev_` keys refused by the platform (api test); dispatch → records visible |
| S2-3 | sdk-go | conformance runner + container (`cmd/openctem-conformance`), signed and digest-pinned in the release workflow | S1-4 | the container certifies the Python example adapter and fails a broken one with a readable report and JUnit XML |
| S2-4 | sdk-go | `pkg/push` + `openctem push`; docs tree; examples gallery wired into CI | S2-1 | time to first finding ≤ 10 min (push) in a scripted walkthrough |
| S2-5 | openctem api/web | scoped ingest tokens per integration (tenant-bound, write-only, revocable, audited) + "Add integration" wizard with a copyable snippet and "waiting for first result" | — | token cannot read; token of tenant A cannot write tenant B (404); revoked token refused |
| S2-6 | sdk-python (new) | adapter SDK: protocol v1, emitter checks, testkit, `--describe`; published with signed provenance | S2-3 | conformance container green; the dotenv and parser examples pass |

### Phase S3 — transport v3

| # | Repo | PR | After | Acceptance |
|---|---|---|---|---|
| S3-1 | sdk-go | `internal/runtime/transport` interface; v2/v1 implementations wrap today's client (no behaviour change) | S1-6 | full kit and conformance suites unchanged |
| S3-2 | protocol | `proto/openctem/sensor/v3`, buf lint/breaking, protovalidate, generated Go | RFC for v3 | breaking change fails CI |
| S3-3 | openctem api | Connect server behind a flag on the dedicated sensors endpoint; per-RPC authorization from the certificate identity | S3-2 | tenant id in a message is ignored; cross-tenant job id → NotFound; no reflection in production |
| S3-4 | sdk-go | identity: certificates from the enrollment key, rotation, protected paths | S3-3 | expired or revoked certificate refused; rotation without dropping a task |
| S3-5 | sdk-go | v3 client with gRPC/HTTPS bindings, negotiation, fallback reasons, re-probe; conformance on both bindings | S3-4 | an HTTP/2-blocking proxy → HTTPS binding with the reason in the heartbeat; a bad certificate never falls back; disconnect mid-upload → exactly once |

### Phase S4 — the boundary and v1.0.0

| # | Repo | PR | After | Acceptance |
|---|---|---|---|---|
| S4-1 | sdk-go | move runtime internals from `core`, `client`, `platform`, `outbox`, `resource`, `chunk`, `retry` under `internal/`; deprecated aliases for one minor | S1-9, S3-5 | sensor and asset-collector build on the codemod output alone |
| S4-2 | sdk-go | `openctem migrate v1` codemod (bridges, `Options` → `Overrides`, renames) | S4-1 | idempotent; refuses on collisions; run on sensor and asset-collector in CI |
| S4-3 | sdk-go | delete the deprecated packages (after the RFC-049 connectors module takes `connectors` and `scanners/tenable`; `gitenv` moved to the sensor) | S4-2 | api-compat with label; upgrade notes |
| S4-4 | sdk-go | v1.0.0: one minor with no break, compatibility matrix tested against oldest and newest platform | all | release checklist in STABILITY.md met |

### Sequencing

S0 lands the Executor and config-doctor work in its final place. S1 starts once the Executor package is in place; S2 starts when the adapter protocol (S1-4) is stable; S3 needs the task pipeline (S1-6) for its transport interface and runs in parallel with S2; S4 closes the major version after S1 and S3.

## Owner decisions

| # | Question | Options | Recommendation |
|---|---|---|---|
| **S1** | Version identity of the redesign | (a) ship in `sdk-go` as v0.18…v0.2x, ending at v1.0.0; "SDK v2" is only the design name; (b) a `/v2` module path now | **(a)**: the module is pre-1.0; a `/v2` path would force every importer to rewrite imports for no gain and contradict STABILITY.md's v1.0.0 plan. |
| **S2** | Where Go tools execute | (a) always out of process: the sensor re-executes its own binary as `__openctem-tool <name>` inside the Executor; in-process only in `testkit`; (b) in-process allowed for built-ins | **(a)**: it is the only way the sandbox, kill and key isolation apply to Go tools too; one path for built-ins and plugins. |
| **S3** | Executor package path | (a) `pkg/sensorkit/executor`, renamed before its first tag; (b) keep `pkg/executor` | **(a)**: it is part of the runtime; renaming is free until it ships in a release. |
| **S4** | Adapter protocol v1 framing | (a) NDJSON on stdin/stdout, one task per process, 1 MiB lines, stderr free-form; plus the zero-code `exec` profile; socket binding later; (b) length-prefixed JSON-RPC; (c) gRPC to the adapter | **(a)**: easiest for Python and shell authors, natural back-pressure, clean sandbox per task; (b) adds framing work for every language; (c) is heavy for a script and needs a port or socket. |
| **S5** | Source of truth for a tool's manifest | (a) the static `tool.yaml` (signed with the artifact); Go may derive the config schema from struct tags and `openctem manifest export` writes the file; the runtime refuses a tool whose `describe` differs; (b) runtime self-description | **(a)**: the runtime must know permissions before running any code; a self-described manifest would let a tool grant itself permissions. |
| **S6** | Home of the language-neutral contracts (proto v3, tool.yaml, adapter, local policy, settings, config report schemas, OpenAPI) | (a) new leaf module `openctemio/protocol`, imported by api and sdk-go; (b) nested module in the monorepo; (c) copies in api and sdk-go with drift tests (today's pattern) | **(a)**: one place for non-Go implementers; no copies to drift; mirrors `ctis` and RFC-049's connectors module. (c) remains acceptable during transition. |
| **S7** | Shape of the v3 control channel | (a) server-streaming `Subscribe` + unary calls on both bindings; (b) bidi stream on gRPC, degraded shape on HTTPS | **(a)**: identical semantics on gRPC and HTTP/1.1 (bidi does not work over HTTP/1.1), one conformance suite, friendlier to proxies. This refines, not reverses, the transport decision. |
| **S8** | Relation between the `connector` tool class and RFC-049 connectors | (a) RFC-049 stays the vendor-integration contract (runs on platform and sensor); on the sensor its host runs each connector as a `connector`-class tool (descriptor → manifest generated); new sensor-only data sources written by others use `pkg/tool`; (b) two unrelated contracts | **(a)**: one sandbox, credential broker, error taxonomy and output path on the sensor; RFC-049 code remains linkable by the platform. |
| **S9** | Python | (a) new repo `openctemio/sdk-python` with the adapter SDK only; a Python sensor runtime only on demand (others can implement from the spec + conformance container); (b) adapter + sensor runtime now | **(a)**: the adapter is the strategic rung; a second runtime doubles the security-critical code to maintain. |
| **S10** | Cleanup pace | (a) deprecate no-importer packages in the next minor, delete one minor later; (b) keep them until v1.0.0 | **(a)**: they have no importer in sensor, api or asset-collector, and they inflate what newcomers read. |
| **S11** | Custom command handlers (`HandleCommand` → `Options.Commands`) | (a) keep as Beta, always wrapped by job verification, kill switch, pause and allow-list, no broker credentials; steer new integrations to tools; (b) remove | **(a)**: content refresh and the Tenable.sc connector still use them; removal waits for S8. |
| **S12** | Untrusted (third-party or unsigned) adapters on the process backend | (a) refused unless the backend reports `NetworkEnforced` (per-task network namespace or forwarder that cannot be bypassed, or the kubernetes/container backend) and the sandbox mode is `required`; (b) allowed with a warning | **(a)**: the process backend records the network class but does not enforce it, and no code from outside the project runs on a sensor without enforcement. |
| **S13** | Developer CLI | (a) `openctem` from `sdk-go/cmd/openctem`, released and signed with the SDK, also inside the conformance container; (b) separate repo | **(a)**: it shares the validator, emitter, adapter host and fake platform code. |
| **S14** | Runner (CI) mode in the SDK | (a) `Kit.RunOnce` in the same kit, workload-identity token exchange built in, no fleet row; (b) keep the runner path only in the sensor | **(a)**: one pipeline, the same admission and output checks in CI as in the daemon. |

## Threat model

| Attacker | Goal | Control in this design |
|---|---|---|
| Malicious or compromised tool (adapter or built-in) | read the sensor key, outbox, policy or other tasks' credentials; reach hosts outside the job; pose as another tool; flood the platform | Executor sandbox with protected paths; one task per process; broker-only, per-task credentials; network class enforced by the backend (untrusted adapters need `NetworkEnforced`); runtime-side validation, caps, `produces` and provenance stamping; protocol limits (line size, invalid-message budget, idle timeout) |
| Compromised platform or tenant admin | turn sensors into a pivot into customer networks | RFC-040 signed jobs verified before admission; local policy ceiling evaluated before the Executor; no remote shell, no inbound port, no platform-written host config; tool manifests from signed files only; fallback never weakens identity checks |
| Network attacker between sensor and platform | downgrade or impersonate | TLS always verified, platform CA pinned, mTLS on gRPC, RFC 9421 signatures on HTTPS; no fallback on certificate or identity errors; tenant policy can require mTLS |
| Malicious sensor author (custom sensor) | inject data into another tenant, pose as a built-in, exhaust the platform | out of the SDK's reach by definition: per-RPC authorization from the certificate identity, tenant never taken from messages, strict CTIS decoding and caps at ingest, platform-stamped provenance, rate limits |
| Careless sensor author | weaken defaults by accident | no public API to disable TLS verification, admission, output validation or the broker; sandbox mode is an operator setting; secret type and redacting logger by default |
| Developer tooling | dev keys or the emulator reaching production | emulator binds loopback only; `octdev_` keys refused by real platforms; `openctem push` requires HTTPS except to loopback |

Tenant isolation: the tenant of every job, report, log and artifact comes from the transport identity. Tool manifests registered by a sensor are content-addressed and readable only within its tenant; built-in manifests are shared because they are public.

## Alternatives considered

- **Keep the scanner/collector interfaces and add fields.** Rejected: the overlap stays, capabilities stay invisible, and nothing can run out of process.
- **In-process plugins (Go plugin packages, embedded interpreters).** Rejected: the runtime cannot limit, kill or sandbox code in its own process.
- **gRPC between the runtime and every adapter.** Rejected for v1: heavy for scripts, needs a socket or port per task; the Unix-socket binding of the same messages remains possible later for long-lived adapters.
- **A self-describing adapter (manifest only from `describe`).** Rejected: permissions must be known, reviewed and signed before any tool code runs.
- **A `/v2` Go module path.** Rejected: the module is pre-1.0; a path change forces import rewrites with no benefit.
- **Bidi control stream on gRPC only.** Rejected in favour of server streaming plus unary calls on both bindings, which keeps the HTTPS fallback semantically identical.
