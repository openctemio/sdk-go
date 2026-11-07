# `openctem tool`: scaffold, check and run a tool

## Install

Without the Go toolchain (Python or shell tools), download the binary from the [GitHub release](https://github.com/openctemio/sdk-go/releases) and verify it. Each release carries `openctem_<version>_<os>_<arch>.tar.gz` for linux and darwin and `openctem_<version>_windows_<arch>.zip` (with `openctem.exe`) for Windows, all on amd64 and arm64, a `SHA256SUMS` file that lists every archive, and its keyless cosign bundle `SHA256SUMS.sigstore.json`:

```bash
v=0.49.0   # a release version, without the leading "v"
base=https://github.com/openctemio/sdk-go/releases/download/v$v
curl -sSLO $base/openctem_${v}_linux_amd64.tar.gz
curl -sSLO $base/SHA256SUMS
curl -sSLO $base/SHA256SUMS.sigstore.json

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/openctemio/sdk-go/.github/workflows/release.yml@refs/tags/v$v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

tar -xzf openctem_${v}_linux_amd64.tar.gz openctem
```

With Go, install a released version:

```bash
go install github.com/openctemio/sdk-go/cmd/openctem@v0.49.0
```

### Windows

In PowerShell (Windows PowerShell 5.1 or PowerShell 7), as the user who runs the CLI (no administrator rights needed). This downloads the zip, checks it against `SHA256SUMS`, unpacks `openctem.exe` to `%LOCALAPPDATA%\Programs\openctem` and adds that folder to the user's `Path`:

<!-- install-openctem-windows: CI runs this block (ci.yml, windows-cli) -->
```powershell
$v = '0.49.0'   # a release version, without the leading "v"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$base = "https://github.com/openctemio/sdk-go/releases/download/v$v"
$zip = "openctem_${v}_windows_$arch.zip"
$tmp = Join-Path $env:TEMP "openctem-$v"; New-Item -ItemType Directory -Force $tmp | Out-Null
Invoke-WebRequest -UseBasicParsing "$base/$zip" -OutFile "$tmp\$zip"
Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
$want = ((Get-Content "$tmp\SHA256SUMS") | Where-Object { $_ -match "^[0-9a-f]{64}  $([regex]::Escape($zip))$" }) -replace ' .*', ''
$got = (Get-FileHash -Algorithm SHA256 "$tmp\$zip").Hash.ToLower()
if (-not $want -or $want -ne $got) { throw "SHA256 of $zip does not match SHA256SUMS: do not use it" }
Unblock-File "$tmp\$zip"
$dir = Join-Path $env:LOCALAPPDATA 'Programs\openctem'
Expand-Archive -Force "$tmp\$zip" -DestinationPath $dir
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) { [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User') }
$env:Path += ";$dir"
openctem version
```

To also check who built `SHA256SUMS` (recommended on a jump host), install [cosign](https://github.com/sigstore/cosign/releases) and run, before the checksum line above:

```powershell
Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS.sigstore.json" -OutFile "$tmp\SHA256SUMS.sigstore.json"
cosign verify-blob --bundle "$tmp\SHA256SUMS.sigstore.json" `
  --certificate-identity "https://github.com/openctemio/sdk-go/.github/workflows/release.yml@refs/tags/v$v" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$tmp\SHA256SUMS"
if ($LASTEXITCODE -ne 0) { throw 'SHA256SUMS is not signed by the sdk-go release workflow' }
```

The signature proves that `SHA256SUMS` was written by the sdk-go release workflow for that tag (a keyless certificate from GitHub's OIDC identity, logged in the public Rekor transparency log); the checksum then proves the zip is the one that workflow built.

**Unsigned binary and SmartScreen.** `openctem.exe` is not Authenticode-signed yet. Windows marks a file downloaded by a browser with the Mark-of-the-Web (an NTFS `Zone.Identifier` stream), and Expand-Archive and Explorer copy that mark onto the files they unpack; Microsoft Defender SmartScreen then warns "Windows protected your PC" when a marked, unsigned program runs. The script removes the mark with `Unblock-File` only **after** the checksum matched, so the trust decision rests on the checksum (and, with cosign, the signature) instead of a publisher certificate. `Invoke-WebRequest` and `curl.exe` themselves do not add the mark (checked on the GitHub `windows-latest` runner); `Unblock-File` is there for a zip that arrived through a browser, an e-mail client or a file share, and does nothing when there is no mark. Do not unblock a file whose checksum did not match.

**Go install avoids the prompt.** On a host with Go, `go install github.com/openctemio/sdk-go/cmd/openctem@vX.Y.Z` builds the binary locally, so it carries no Mark-of-the-Web and SmartScreen does not prompt. Its integrity comes from the Go module proxy and the checksum database (`sum.golang.org`), which every `go install` checks. CI runs this `go install` on `windows-latest` for every change.

**Hardened hosts.** A jump host with AppLocker or Windows Defender Application Control (WDAC) policies may refuse any unsigned program, whatever its checksum or mark. There the fix is a signed binary or an administrator rule that allows `openctem.exe` by path or by file hash (the SHA-256 from `SHA256SUMS`; update the rule with each release).

Package managers (winget, Scoop) are not offered yet.

`openctem version` (also `openctem --version` and `openctem tool version`) prints `openctem <version>`: the release the binary was built from, or `<sdk version>-devel` for a build from a checkout.

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
| `init --kind K --capability id@major [--name n] [dir]` | Writes a new tool that implements one capability of the taxonomy (see [docs/capabilities.md in contract](https://github.com/openctemio/contract/blob/main/docs/capabilities.md)). The kinds are `exec-sarif`, `exec-ctis`, `exec-json`, `go` and `python`. It never overwrites a file. |
| `validate [dir]` | Loads the descriptor strictly. Errors carry a JSON pointer (`/implements/0/params/rate/max`); lint warnings follow. |
| `run [dir] --target value[@type] [--capability id@major] [--param k=json] [--config k=v] [--content slot=dir] [--format table\|ctis]` | Runs one task offline and prints the outcome or the CTIS report. `--content` hands a local directory to a content slot the tool declares, so you can test with real templates or rules. |
| `test [dir] [--update] [--capability] [--scope] [--fuzz 30s] [--timeout 30s]` | Runs the conformance kit (below). `--update` rewrites the fixtures' expected CTIS. |
| `diff <old> <new>` | Compares two versions of a descriptor and fails when the change needs a larger version bump than the one made. |
| `describe [--json] [dir]` | Prints the canonical descriptor and its digest, which is what the platform sees. |
| `build [dir] (--output oci-dir \| --push repo[:tag]) [--platform p,...] [--base name@sha256:...]` | Builds the pack image of a pack directory, reproducibly and without a container daemon, and prints its digest ([tool-packs.md](../tool-packs.md#the-pack-image)). Registry credentials come from the Docker config (`docker login`). |

A directory with a `pack.yaml` is a [tool pack](../tool-packs.md): `validate`, `test` and `describe` then work on the pack and every tool it lists (`describe` prints the pack's tier, capabilities, credentials, network and engines). Name the `tool.yaml` file to work on one tool of it.

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
- a `pack.yaml` that makes the directory a pack of this one tool ([tool-packs.md](../tool-packs.md)), with the tier the tool needs and, for `python` and `go`, a base image pinned by digest;
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
| `discover.hosts@1` | A loopback address answering on one port, probed on that port: exactly that address is reported live, with the time it answered (`last_seen_at`). |
| `probe.http@1` | A page with a known title: a `web_origin` with `technical.http.status_code` 200. |
| `detect.services@1` | SSH, Redis (password required), MySQL, SMTP (hostile greeting), HTTP, HTTPS (ALPN) and LDAP fixtures as service targets, `depth: thorough`. Every fixture is a credential sentinel: an SSH user authentication, a MySQL handshake response, a Redis `AUTH`, an SMTP `AUTH` or mail transaction, an LDAP bind, an HTTP `Authorization` header or a state-changing method fails. The six are identified (TLS on HTTPS), each service keeps its input value, Redis is not reported anonymous, banners are at most 512 bytes of clean UTF-8, details at most 16 of 256 bytes. |
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
 "targets": [{"ref": "t1", "type": "web_origin", "value": "{{fixture.url}}"}]}
```

While the fixture runs, the kit serves it on `127.0.0.1` (a random port):
- `serve` is the default response for any path: `status` (default 200, 200-599), `headers` and `body`;
- `paths` overrides it for one exact path (a status or body left out is inherited, headers are added to the default's);
- `"tls": true` serves HTTPS with a self-signed certificate. The tool must then accept it (for example through an `insecure` config key the fixture sets); a verifying client refuses it;
- limits: body 1 MiB, 32 headers, 64 paths. A header name or value with CR or LF refuses the fixture with an error.

Every target `value` may use `{{fixture.url}}` (`http://127.0.0.1:PORT`), `{{fixture.host}}` (`127.0.0.1`), `{{fixture.port}}` and `{{fixture.host_port}}`. Any other `{{fixture.*}}`, or a placeholder in a fixture without `serve`, is an error. A fixture without `serve` runs as before.

The port changes on every run, so before comparing with the expect file (and before `--update` writes it) the kit replaces `http://127.0.0.1:PORT` by `{{fixture.url}}` and `127.0.0.1:PORT` by `{{fixture.host_port}}` in every string of the produced CTIS. The expect file holds the placeholders and is the same on every run. The server is stopped when the fixture ends.

`init` writes such a fixture for tools that consume `web_origin`, `web_application`, `api`, `service` (`{{fixture.host_port}}/tcp`), `host` or `ip_address`. `domain_name` targets keep `example.com` names: the kit cannot serve a name, and the stub resolves nothing. Replace them by a served target as soon as the tool connects somewhere.

## CI

[`ci/github/openctem-tool.yml`](../../ci/github/openctem-tool.yml) and [`ci/gitlab/openctem-tool.yml`](../../ci/gitlab/openctem-tool.yml) run the same three steps on every change, and on a version tag build, push and sign the pack image (`openctem tool build --push`, then a keyless `cosign sign` of the digest), and the actions they use are pinned by commit:
1. `validate`;
2. `test --capability --scope --fuzz 30s`;
3. `diff` against the target branch's `tool.yaml`.

## `openctem import`: import the output of a tool you ran

`openctem import` converts the output of a tool that the sensor does not run for you into a CTIS report on your machine, and imports it into your organization. Parsing happens locally with the same importers the platform and the sensor use (`github.com/openctemio/ctis/v2/importer`); nothing of the tool is executed.

```text
export OPENCTEM_URL=https://console.example.com
export OPENCTEM_API_KEY=...        # Update Findings, Manage Assets, Import Assets

nmap -sV -oX - 192.0.2.0/24 | openctem import --format nmap
testssl.sh --jsonfile scan.json www.example.com; openctem import --format testssl scan.json
gau example.com | openctem import --format lines --as url --tool gau
openctem import --mapping wafw00f.mapping.json --tool wafw00f waf.json
```

| Flag | Meaning |
|---|---|
| `--format` | `auto` (from the content) or a format: `nmap`, `testssl`, `lines`, `ctis`, `nuclei`, `nessus`, `sarif`, ... (`openctem import -h` lists them). `lines` is never detected |
| `--as` | `--format lines`: what each line names (`auto`, `host`, `domain`, `ip`, `url`) |
| `--tool` | the tool name to record (for `lines` and mappings) |
| `--mapping` | a declarative mapping file (`openctem.io/mapping/v2`, JSON) for any other JSON, CSV or XML |
| `--target-hint` | `type:value` of the asset for records that name none |
| `--min-severity` | leave out findings below it |
| `--dry-run` | print the CTIS report to stdout and a summary to stderr; send nothing |
| `--out` | write the report to a file readable by you only (mode 0600; on Windows a DACL for your account and SYSTEM, nothing inherited) and send nothing; upload it later with `openctem import <file>` |
| `--wait` | follow the receipt until applied (default 60s; 0: do not wait) |
| `--json` | print the platform's answer as JSON |
| `--ca-file` | a PEM file of CA certificates trusted in addition to the system's (default `$OPENCTEM_CA_FILE`) |

Files may be patterns: `openctem import scans/*.xml`, or `openctem import C:\scans\*.nessus` in cmd.exe and PowerShell, which pass the pattern on unexpanded. The CLI expands it itself (an existing file whose name holds `*`, `?` or `[` is taken as it is); a pattern that matches nothing is an error. More than 10 files are sent 10 at a time (and at most 100 MiB of reports per upload), each upload with its own receipt; the exit status is the worst of them.

What is uploaded is exactly what `--dry-run` prints (`format=ctis`). The platform validates it again, imports it as a partial upload with the API key's rights (an import never closes findings), judges every host against your scope (hosts outside it are recorded as candidates, never scanned) and answers with a receipt. Exit status: 0 imported, 1 refused or failed, 2 usage or input error, 3 still queued.

The key is read from `OPENCTEM_API_KEY` only, sent only over HTTPS (plain HTTP only to localhost) and never to a redirect target.

TLS and proxies: the console's certificate is checked against the system trust store (on Windows the certificate store, so a corporate root CA deployed by Group Policy works) plus `--ca-file`, which adds to it and never replaces it; there is no switch to skip verification. `HTTPS_PROXY` and `NO_PROXY` are honoured. The Windows system proxy (WinHTTP or Internet Options) is not read: on a host that reaches the console only through it, set `HTTPS_PROXY` to the same address (`netsh winhttp show proxy` shows it).

### On Windows

- Exports written by Windows tools read as they are: UTF-16 (little or big endian, with or without a byte order mark; Windows PowerShell 5.1 writes UTF-16 for `>` and `Out-File`), a UTF-8 byte order mark, and CRLF line ends. An XML file whose declaration says `encoding="UTF-16"` is decoded first.
- Each file is read as a stream; its size limit is 100 MiB (the console's upload limit). Split a larger export, for example one Nessus export per scan.
- Output is plain text without colour or terminal escape codes, so cmd.exe, Windows PowerShell and PowerShell 7 show it cleanly and redirect it to a file. The exit status is in `%ERRORLEVEL%` (cmd.exe) or `$LASTEXITCODE` (PowerShell).
- Environment variables are set with `$env:OPENCTEM_URL = 'https://console.example.com'` (PowerShell) or `set OPENCTEM_URL=https://console.example.com` (cmd.exe). `openctem run` drops `OPENCTEM_API_KEY` from your command's environment whatever case its name is written in.

### Give the tool its input: `openctem targets export` and `openctem run`

```text
openctem targets export --type domain > names.txt                 # in-scope names, one per line
openctem targets export --type ip --tag prod --export-format json  # {"type","value"} per line

openctem run --type ip --format nmap -- nmap -sV -iL {targets_file} -oX {output_file}
openctem run --type domain --format lines --as domain --tool puredns -- puredns resolve {targets_file} -w {output_file}
```

`targets export` reads the organization's assets through the API with the key's data scope; by default only those an active scope entry covers (`--scope in_scope`). `run` exports them to a private temporary file, runs your command (no shell) with `{targets_file}` and `{output_file}` replaced, imports what it wrote (`{output_file}`, else its standard output) with the `openctem import` flags you gave, and removes the file. Your command does not see `OPENCTEM_API_KEY`. Schedule either from cron or a CI job. The platform cannot check what your command actually scanned: results outside your scope are recorded as candidates that grant nothing, and authorisation to scan is yours.
