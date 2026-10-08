# Writing a tool in any language: adapter protocol v1

A sensor runs every tool out of process. A tool written in Go uses `pkg/tool`
and `pkg/tool/adapter`. A tool in any other language (Python, Rust, a shell
binary, ...) is a program with a `tool.yaml` next to it that speaks **adapter
protocol v1** on its standard input and output. No SDK is needed. This page is
the contract. The design and the full message tables are in
[rfcs/sensor-sdk-v2.md](rfcs/sensor-sdk-v2.md) (D.4.2), and the machine-readable
form is [pkg/tool/schema/adapter.v1.schema.json](../pkg/tool/schema/adapter.v1.schema.json).

A complete example in Python, with no dependencies:
[examples/python-adapter](../examples/python-adapter).

**Python helper.** [`openctem_tool.py`](../internal/toolcli/templates/openctem_tool.py) is one file, standard library only, that speaks this protocol so a Python tool writes only `run(ctx, task)`. `openctem tool init --kind python` puts it next to the tool. It provides:
- the handshake, `describe` (from `tool.yaml` in its JSON form, or YAML with PyYAML installed) and `validate`;
- `cancel`, read on a thread while `run` works (`ctx.check()` raises `Canceled`), and heartbeats;
- records, per-target status, logs and progress, and the result (`partial` when a target failed);
- `ctx.connect(host, port)`: a TCP connection made through the task's forwarder when the sensor confines the network (where a confined task has no other way out), else directly.

## The manifest is the contract

`tool.yaml` (`apiVersion: openctem.io/tool/v1`, schema
[tool.v1.schema.json](../pkg/tool/schema/tool.v1.schema.json)) declares what the
tool is: its name, version, class, tier, the target types it consumes, the
record types it produces, its configuration schema, its permissions (network,
credentials), its resources, its self-test fixtures and `run.argv`, the program
to start (never a shell).

A tool states which capabilities of the OpenCTEM capability taxonomy it
implements (`implements: [{capability: scan.ports@1, params: {...}}]`, see
[docs/capabilities.md in ctis](https://github.com/openctemio/ctis/blob/main/docs/capabilities.md)).
The capability carries the phase, the tier floor, the input and output types
and the required output; the tool maps the capability's standard params to its
own config keys.

The runtime trusts the **file**, never the program. Permissions are known and
enforced before any of your code runs. Your program must describe itself
exactly as the file does (the `run` section aside), or it is refused.

## Transport

- Newline-delimited JSON, UTF-8, one message per line, at most 1 MiB per line.
  Every message has `"v": 1` and a `"type"`.
- **stdout is the protocol channel only.** Anything else you print there
  breaks the protocol. Diagnostics go to **stderr**, which the runtime
  captures, redacts and caps (64 KiB kept).
- One task per process. Exit after your `result`.
- The runtime starts the program in the task's private directory (`workdir`),
  inside the sensor's sandbox.

## Conversation

```
runtime → {"v":1,"type":"hello","protocol":[1],"runtime":{...},"limits":{...},"features":[...]}
tool    → {"v":1,"type":"hello","protocol":1,"sdk":{"name":"my-tool","version":"1.0.0"}}
runtime → {"v":1,"type":"describe"}
tool    → {"v":1,"type":"manifest","manifest":{ ...tool.yaml as JSON, without run... }}
runtime → {"v":1,"type":"validate","task":{...}}          (optional)
tool    → {"v":1,"type":"validation","ok":true}
runtime → {"v":1,"type":"run","task":{"id":"...","targets":[{"ref":"t1","type":"http_service","value":"https://a.example"}],"config":{...},"workdir":"/run/task","credentials":[...]}}
tool    → {"v":1,"type":"record","kind":"finding","target":"t1","data":{ one CTIS finding }}
tool    → {"v":1,"type":"target_status","target":"t1","status":"done"}
tool    → {"v":1,"type":"result","status":"ok"}
```

Message types (runtime to tool): `hello`, `describe`, `validate`, `run`, `cancel`.
Message types (tool to runtime): `hello`, `manifest`, `validation`, `log`,
`progress`, `record`, `report_info`, `target_status`, `artifact`, `heartbeat`,
`verdict` (retest tasks), `result`.

**Ignore what you do not know.** Unknown message types and unknown members are
ignored, except during the handshake. A newer runtime may send more.

## Rules the runtime enforces whatever the tool does

- **Records** must be valid CTIS and of a type the manifest `produces`.
  Anything else is quarantined, and the task ends `partial`. Record and byte
  caps stop a flooding tool.
- **Targets:** report each target once with `target_status`
  (`done` | `failed` | `skipped`, with an error `class` and `detail` for a
  failure). A `result` of `ok` with targets never reported becomes `partial`.
- **Credentials** arrive only in the `run` message, and only those the manifest
  declares and the operator stored. They are never in the environment, argv or
  a file. Their values are masked in everything the runtime keeps.
- **Network:** a tool reaches only what its `permissions.network` class allows.
  The sandbox enforces it; do not rely on reaching anything else.
- **Errors** carry a class: `invalid_input`, `target_unreachable`,
  `refused_by_policy`, `transient`, `rate_limited`, `auth_failed`,
  `permission_denied`, `not_found`, `tool_error`. Details are capped at 256
  bytes.
- **Logs** (`{"type":"log","level":"info","msg":"...","fields":{...}}`) are
  redacted, rate-limited and capped. They go to the sensor's log and to the
  task's log on the platform. Never log a secret on purpose.
- **Capability tasks** (`task.capability` present): the runtime already
  mapped the capability's standard params onto your config keys, refused a
  value you do not support, capped your `safety.rate_param` by the sensor's
  local policy, and refused the task when your minimum tier is above the job's
  `max_tier`. Read your config as usual. After the task the output is checked
  against the capability's required output; records that miss it are kept, the
  task ends `partial` and the platform checks them again.
- **Retest tasks** (`task.retest` present, only if the manifest declares
  `retest: true`): answer one `verdict` per item (`still_present`, `fixed` or
  `unverifiable`) and emit no records. `fixed` counts only for a target you
  reported `done`.

## Time and cancel

- Send something (a `heartbeat` will do) at least every `idle_timeout`
  (default 10 minutes), or the runtime stops the tool.
- On `cancel`, stop and send your `result` (`canceled`). After a 10-second
  grace the runtime sends SIGTERM, and after twice that, SIGKILL.
- The task's `deadline` and `resources.timeout` bound the whole run.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | after `result`, or when stdin ended before a `run` (the runtime closes stdin after `describe`/`validate` when it only asked those) |
| any, without a `result` | `tool_crashed` (the runtime reports what was accepted, and the task fails) |
| `2`, `3` | conventional for usage and protocol errors in our SDKs; to the runtime they are the same as any exit without a result |

The outcome is the `result` message, not the exit code.

## Check your tool: the conformance kit

Run the same checks the runtime relies on, against your program, with no Go
code:

```sh
openctem tool test path/to/tool    # see docs/tools/cli.md
```

or from a Go test: `conformance.RunToolSuite(t, "tool.yaml", conformance.ToolSuiteOptions{})`.

| Check | What it proves |
|---|---|
| Manifest | `tool.yaml` loads strictly, validates, and has a run section |
| Handshake | answers hello with protocol 1, ignores an unknown message, and describes itself exactly as `tool.yaml` does |
| Validate | refuses a configuration with an unknown key |
| StdoutIsProtocol | writes nothing but protocol messages to stdout |
| ExitsOnEOF | exits with status 0 when its input ends |
| Cancel | after `run` and `cancel`, sends its result or exits within the grace |
| Fixtures | each `selftest` fixture (a task file and the CTIS it must produce) runs through the runtime's own host, with every runtime check, and produces exactly the expected normalized report, with no invalid message |

`-update` (or `OPENCTEM_UPDATE_GOLDEN=1`) writes the fixtures' expected reports
from what the tool produced. Review them before you commit.

## No code at all: the exec profile

A CLI needs no adapter when its output is one of:

- CTIS (`ctis`, or `jsonl-ctis` records) or SARIF (`sarif`);
- a format `ctis/importer` reads (`nuclei`, `semgrep`, `trivy`, `betterleaks`, `gitleaks`, `grype`, `zap`, `vuls`, `cyclonedx`, `spdx`, `osv`, `csaf`, `openvex`, `nessus`, `qualys`, `defectdojo`);
- any JSON document or JSON Lines, with a mapping file
  (`run.output: {format: jsonl, from: stdout, mapping: mapping.yaml}`) in the
  declarative language of `ctis/importer/mapping`.

The mapping file sits next to `tool.yaml` and is part of the contract: its
digest is recorded when the manifest is loaded, and a changed file is refused.

## Installing

An operator installs the tool's directory (its `tool.yaml` and program) in one
of the sensor's adapter directories (`SENSOR_ADAPTER_DIRS`). The directory and
files must not be writable by another user, and must not be symbolic links.
The sensor runs an operator-installed tool in its process sandbox (private
task directory, rlimits, no_new_privs, Landlock, seccomp). That sandbox does
not yet enforce the network class: the targets are admitted against the local
policy before the task starts, and the tool must keep to them. Install only
tools you trust.
