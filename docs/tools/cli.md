# `openctem tool`: scaffold, check and run a tool

```bash
go install github.com/openctemio/sdk-go/cmd/openctem@latest
```

Every command reads the tool's `tool.yaml` (a directory or the file itself). Every task runs through the sensor runtime's host (`pkg/sensorkit/toolhost`) and the same process sandbox a sensor uses (`pkg/sensorkit/executor`), so a tool behaves here as it will on a sensor. Nothing talks to a platform.

`run` and `test` take `--sandbox off|auto|required` (default `$OPENCTEM_SANDBOX`, else `auto`):
- `auto` enforces what the host supports and notes the rest; the sandbox is Linux only;
- `required` refuses to run without every control (use it in CI on Linux);
- `off` runs the tool as a plain child process.

`OPENCTEM_SANDBOX_NETWORK=auto|required|off` (default `auto`) also confines the task's network where user namespaces are available, as a sensor does. The task's only way out is then its forwarder, and `--scope` reports every destination it refused, direct connections included. On a host or container that refuses user namespaces, a note says so and the task runs unconfined.

`init` pins the scaffold to the SDK version the CLI was built from: the Go scaffold's `go.mod`, and the CLI version its CI workflow installs.

Exit status:
- `0`: the command succeeded.
- `1`: a check failed.
- `2`: a usage error.

| Command | Does |
|---|---|
| `init --kind K --capability id@major [--name n] [dir]` | Writes a new tool that implements one capability of the taxonomy (see [docs/capabilities.md in ctis](https://github.com/openctemio/ctis/blob/main/docs/capabilities.md)). The kinds are `exec-sarif`, `exec-ctis`, `exec-json`, `go` and `python`. It never overwrites a file. |
| `validate [dir]` | Loads the descriptor strictly. Errors carry a JSON pointer (`/implements/0/params/rate/max`); lint warnings follow. |
| `run [dir] --target value[@type] [--capability id@major] [--param k=json] [--config k=v] [--content slot=dir] [--format table\|ctis]` | Runs one task offline and prints the outcome or the CTIS report. `--content` hands a local directory to a content slot the tool declares, so you can test with real templates or rules. |
| `test [dir] [--update] [--capability] [--scope] [--fuzz 30s] [--timeout 30s]` | Runs the conformance kit (below). `--update` rewrites the fixtures' expected CTIS. |
| `diff <old> <new>` | Compares two versions of a descriptor and fails when the change needs a larger version bump than the one made. |
| `describe [--json] [dir]` | Prints the canonical descriptor and its digest, which is what the platform sees. |

`openctem-conformance tool <tool.yaml>` is the older name of `openctem tool test` and is kept for one minor release.

## What `init` writes

`init` fills `tool.yaml` from the capability:
- `implements`;
- the input types its ports carry (`consumes`);
- the output types (`produces`);
- its tier floor;
- one config key per standard param, mapped in `implements[].params`;
- `safety.rate_param` when the capability has a rate.

It also writes:
- a stub program that emits nothing (for `python`, a `run(ctx, task)` on the `openctem_tool.py` helper it also writes; see [adapter-protocol.md](../adapter-protocol.md));
- a self-test fixture with its expected CTIS (for tools that take URLs, services or hosts, a hermetic one: see "Hermetic fixtures");
- a `.gitignore` (`__pycache__/`, `fuzz/crashers/`, and `bin/` for `go`);
- a `Makefile` (`validate`, `test`, `conformance`);
- the CI workflow `.github/workflows/openctem-tool.yml`.

`openctem tool test` passes on the scaffold as written; for `go`, run `make build` first. `make conformance` fails until the stub is replaced by a real tool, because the stub finds nothing.

## The conformance kit (`openctem tool test`)

| Check | Proves |
|---|---|
| Manifest, Handshake, Validate, StdoutIsProtocol, ExitsOnEOF, Cancel | The adapter speaks protocol v1 and describes itself exactly as its `tool.yaml` (adapters only). |
| Fixtures | Each self-test task produces exactly its expected CTIS. |
| Lint | Warns about anything the descriptor should not leave out: no `implements`, no fixture, no engine version probe, a rate param with no rate key, deprecated keys. |
| FixtureContract | Run as a task of each implemented capability, every fixture meets the capability's required output. |
| `--capability` | Runs a suite per implemented capability, on loopback fixtures. |
| `--scope` | The tool is given target A while another loopback address B listens. It runs with its proxy variables pointing at a recording forwarder whose scope is A (`pkg/sensorkit/egress`). Any connection to B fails, and so does any request through the proxy for anything but A or the manifest's vendor hosts; the failure names the destination. A tool that ignores the proxy variables and dials elsewhere directly is caught once the sandbox confines the network (api RFC-060). |
| `--fuzz d` | Fuzzes the parser of an exec tool's output format, seeded from `fuzz/*` and a minimal document. A panic, two different results for one input, or a result above the record cap fails. The input is saved under `fuzz/crashers/`. |

The `--capability` suites:

| Capability | Fixture and check |
|---|---|
| `scan.ports@1` | Two open ports and one closed: exactly the open ones are reported. |
| `discover.hosts@1` | A loopback address answering on one port, probed on that port: exactly that address is reported live, with the probe that answered (`properties.live_by`). |
| `probe.http@1` | A page with a known title: `http_service` with status 200. |
| `vuln.templates@1` | An app exposing `/.git/config` and `/.env`: at least one finding. |
| `secrets.code@1` | A repository with fresh fake credentials: a masked value, and the raw value absent from the report and the logs. |
| `sast.code@1` | A file with `shell=True` and `eval` of input: at least one finding. |
| `sca.deps@1` | `requirements.txt` and `package.json`: at least one dependency or finding. |
| Other capabilities | The tool cannot be pointed at a local fixture for these, so they are checked through the fixtures' output only. |

Passing the kit at a capability's major is what being certified for it means.

## Hermetic fixtures

A self-test must not depend on the internet. A fixture task file (the JSON a `selftest[].task` path points to) may carry a top-level `serve` member, read only by the kit and the CLI: it is removed before the task is built, never reaches a sensor and is not part of `tool.yaml`.

```json
{"serve": {"status": 200, "headers": {"Server": "fixture"}, "body": "<html><title>ok</title></html>",
           "paths": {"/.env": {"status": 200, "body": "SECRET=x"}}},
 "id": "selftest-sample",
 "targets": [{"ref": "t1", "type": "http_service", "value": "{{fixture.url}}"}]}
```

While the fixture runs, the kit serves it on `127.0.0.1` (a random port):
- `serve` is the default response for any path: `status` (default 200, 200-599), `headers` and `body`;
- `paths` overrides it for one exact path (a status or body left out is inherited, headers are added to the default's);
- `"tls": true` serves HTTPS with a self-signed certificate. The tool must then accept it (for example through an `insecure` config key the fixture sets); a verifying client refuses it;
- limits: body 1 MiB, 32 headers, 64 paths. A header name or value with CR or LF refuses the fixture with an error.

Every target `value` may use `{{fixture.url}}` (`http://127.0.0.1:PORT`), `{{fixture.host}}` (`127.0.0.1`), `{{fixture.port}}` and `{{fixture.host_port}}`. Any other `{{fixture.*}}`, or a placeholder in a fixture without `serve`, is an error. A fixture without `serve` runs as before.

The port changes on every run, so before comparing with the expect file (and before `--update` writes it) the kit replaces `http://127.0.0.1:PORT` by `{{fixture.url}}` and `127.0.0.1:PORT` by `{{fixture.host_port}}` in every string of the produced CTIS. The expect file holds the placeholders and is the same on every run. The server is stopped when the fixture ends.

`init` writes such a fixture for tools that consume `http_service`, `website`, `web_application`, `api`, `discovered_url`, `open_port`, `service`, `host` or `ip_address`. `domain` and `subdomain` targets keep `example.com` names: the kit cannot serve a name, and the stub resolves nothing. Replace them by a served target as soon as the tool connects somewhere.

## CI

[`ci/github/openctem-tool.yml`](../../ci/github/openctem-tool.yml) and [`ci/gitlab/openctem-tool.yml`](../../ci/gitlab/openctem-tool.yml) run the same three steps, and the actions they use are pinned by commit:
1. `validate`;
2. `test --capability --scope --fuzz 30s`;
3. `diff` against the target branch's `tool.yaml`.
