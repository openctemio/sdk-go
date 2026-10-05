### Added

- **Tool manifests in the sensor manifest.** A scanner ported to the tool
  contract implements `core.ToolContractProvider`; the registry reports its
  `core.ToolContract` (`tool.Manifest.Contract()`: manifest digest, version,
  class, tier, network, consumes, produces) as `tools[].contract` in the
  sensor manifest (not on the heartbeat). A platform that does not know the
  member ignores it.
- **Adapter protocol v1 and the tool host.** `pkg/tool/adapter` is the
  tool side (newline-delimited JSON on stdin/stdout, one task per process):
  `Serve(tool)` for a tool shipped as its own binary (`--describe` prints
  its manifest), `Dispatch(tools...)` for tools compiled into a sensor,
  which the runtime re-executes as `<sensor> __openctem-tool <name>`. While
  it serves, stdout is the protocol only (tool code printing goes to
  stderr) and the process is non-dumpable. `pkg/sensorkit/toolhost` (Beta)
  is the runtime side: `RunBuiltin` and `RunManifest` (adapter or the
  zero-code `exec` profile for a CLI that writes CTIS or SARIF) run one task
  in the Executor sandbox and check everything again: 1 MiB lines, an
  invalid-message budget, idle and task timeouts, `describe` equal to the
  manifest, CTIS validity, `produces` (quarantine), record and byte caps
  (the tool is stopped), control and bidi characters, artifacts confined to
  the task directory (no symlink escape, size and digest checked), a
  graceful cancel then a kill. Only declared credentials are delivered,
  inside the run message, and their values are masked in logs and stderr.
  The report gets runtime-stamped provenance. An untrusted adapter runs
  only on a backend that enforces its network class. JSON Schemas:
  `tool.AdapterProtocolJSONSchema()`.
- **Tool contract** (`pkg/tool`, docs/rfcs/sensor-sdk-v2.md): one contract
  for every workload a sensor runs. A `Manifest` (the `tool.yaml` file,
  `apiVersion: openctem.io/tool/v1`, read strictly by `LoadManifest`)
  declares the execution class (target-scan, connector, parser, enricher),
  tier, consumes/produces from the CTIS vocabulary, a configuration schema
  in the settings-schema subset (no secret fields), permissions (network,
  vendor hosts, filesystem, credentials, Linux capabilities), resources,
  self-test fixtures and, for a tool that is its own program, how to start
  it (`run.argv` with a closed set of placeholders and never a shell; the
  zero-code `exec` profile). `Manifest.Validate` enforces the cross-field
  rules (T2 only for target scans, class against network, placeholders
  against the config schema); `Digest` is over the canonical JSON;
  `ManifestJSONSchema` is the JSON Schema for editors and other languages.
  `tool.New[C]` builds a tool from a manifest and a typed run function (the
  config schema derived from C's struct tags when the manifest has none;
  `secret:"true"` refused). `Context` gives a running tool a validating
  `Emitter`, a redacting logger, progress, per-target outcomes, artifacts,
  declared credentials only (`Secret` never prints its value) and an HTTP
  client that reaches only what the network permission allows and never a
  metadata address. Errors are categorized (`ErrorClass`, `Error`,
  `Unreachable`, `Retry`, `RateLimit`, `Refused`, `Invalid`, `Failed`).
- **`pkg/testkit`**: run a tool in-process with the runtime's rules (strict
  config, declared credentials only, record checks, quarantine of
  undeclared output, caps, report assembly and provenance); `Normalize` and
  `Golden` for golden CTIS files.

- **Runner mode with CI workload identity** (api RFC-051). `sensorkit.NewCIRun`
  detects a GitHub Actions job allowed `id-token: write` or a GitLab CI job
  with an `id_tokens` variable (`OPENCTEM_ID_TOKEN` by default) when
  `OPENCTEM_TENANT_ID` is set, asks the CI provider for the job's OIDC token
  (audience `OPENCTEM_OIDC_AUDIENCE`, default `openctem:tenant:<id>`) and
  exchanges it at the first use for a run token that lives at most 15 minutes
  (`POST /api/v1/ci/oidc/exchange`); on GitHub it renews the token for the
  same run before it expires. `CIRun` is a `core.Pusher` (uploads go to
  `/api/v1/ci/runs/{id}/results`), and `BaselineDiff` and `Evaluate` ask the
  platform's gate for the verdict; `WriteVerdict` prints it. `Kit.RunOnce`
  runs the kit's scanners once, pushes through the run and returns the
  verdict. No token is printed, logged or put in an error; `CIRun.String`
  redacts it.

- `pkg/ctis` re-exports the CTIS 1.4 interoperability members (`finding.native`, `scores`, `vex`, `source_lifecycle`, `source_extra`, `vulnerability.ids`, remediation solution metadata, `asset.identity_hints`) and their normalizers (`NormalizeNativeSeverity`, `NormalizeNativeStatus`, `NormalizeVEXStatus`, `NormalizeVEXJustification`, `NormalizeVulnerabilityID`, `PreferredVulnerabilityID`, `LocationKey`, `AllScores`, `SetSourceExtra`), plus `SupportedSchemaVersions` and `IsSupportedVersion`.
- `executor.TaskSpec.Stdin`: a task can read its standard input (the
  channel of the tool adapter protocol); pass the read end of an `os.Pipe`
  so the task gets the descriptor itself. `executor.Status.NetworkEnforced`
  says whether the backend itself confines a task to its network class;
  the process backend records the class but does not enforce it, so it
  reports false (untrusted tools need a backend that reports true).
- **Per-task tool sandbox** (`pkg/sensorkit/executor`). Every tool run
  (`core.ExecuteScanner`, `StreamScanner`, `BaseScanner`) goes through one
  executor with a small backend interface (`Backend.Prepare` → `Task`:
  `Start`, `Wait`, `Kill`, `Cleanup`) over a generic `TaskSpec` (argv,
  environment, working directory, writable paths, limits, network class).
  The `process` backend runs the task through a launcher (the program's own
  binary, `executor.RunLauncherIfRequested` first in main) that, before the
  tool starts: gives it a private throwaway directory (HOME, TMPDIR, XDG_*);
  sets RLIMIT_DATA / NPROC / FSIZE / NOFILE / CORE (and CPU when asked);
  sets no_new_privs; applies Landlock (writes only under the task directory
  and the caller's `ExecConfig.WritePaths`; no read of the protected paths:
  the sensor's credentials file, outbox and its key, local policy,
  configuration); installs a seccomp filter (ptrace, mount and namespaces,
  modules and kexec, keyrings, bpf, perf, clock changes, file handles,
  userfaultfd refused; clone with namespace flags refused; other syscall
  ABIs kill the task). The sensor process makes itself non-dumpable, so a
  task under the same user cannot read its memory or environment through
  /proc. `sensorkit` turns it on by default (`SENSOR_SANDBOX=auto`;
  `required` refuses to start without every control; `off`), protects its
  own files plus `Options.ProtectedPaths`, and logs what is enforced. Each
  `ExecResult` carries the sandbox status it ran under. No Docker socket is
  ever used.

- **Preflight checks and the config report** (api RFC-033, config report;
  OpenCTEM research/26). What a sensor used to print to stderr only is now
  also a check result with a stable id, a status, a code and typed
  parameters, delivered to a platform that lists the `config_report`
  feature (`PUT /api/v2/sensor/config-report`, at most 64 KiB) and named by
  digest on every heartbeat (`config_report`); the platform asks for it
  again with the heartbeat action `send_config_report`. Reported by the kit:
  a skipped tool and why (`tool.<name>.binary`: not_installed, broken,
  check_error), a tool left out by `SENSOR_TOOLS` or the local policy
  (`tool.<name>.selection`), a tool not registered (`tool.<name>.registration`),
  no tool at all (`tools.available`), a state directory that does not
  persist (`identity.state_persistent`), key renewal off or failed to start
  (`identity.key_renewal`), scanners inheriting the proxy
  (`network.scan_proxy_inherit`), OOM protection that failed
  (`runtime.oom_protect`), legacy `AGENT_*` names (`config.alias_deprecated`),
  unknown `SENSOR_*`/`OPENCTEM_SDK_*` names with a "did you mean"
  (`config.env_unknown`, opt-in with `Options.ReportUnknownEnv`), the local
  policy and its template keys (`policy.local`, `policy.template_keys`), a
  stopped command poller (`runtime.command_poller`), and an unreadable
  `SSL_CERT_FILE`/`SSL_CERT_DIR` (`platform.tls`), which Go used to ignore
  silently (now also a start-up warning). A sensor adds its own with
  `Kit.ReportCheck`; `Kit.ConfigReport` returns the report. New checks never
  stop the sensor.
- **Settings registry** (`pkg/sensorkit/settings`): each setting declared
  once with its name, type, required, default, secret, description, docs
  link and validation. The kit registers the SDK's settings
  (`sensorkit.RegisterSDKSettings`); a sensor passes its own registry in
  `Options.Settings`. `docs/SETTINGS.md` is generated from it.
- **Secrets never leave the host.** The config report carries, per declared
  setting, only whether it is set, its source (`env`, `option`, `default`,
  `unset`), whether it is a secret and whether its value is valid: there is
  no value member. Every free text and parameter is scrubbed of the secret
  settings' values, the API key and URL credentials, control and bidi
  characters are stripped, and every field is bounded
  (`core.ConfigReport.Finalize`). The conformance fake serves the feature
  (`SetConfigReport`, `ConfigReports`).
- **Local policy schema v2; v1 frozen** (owner decision D13, api
  research/25 §3.3). `openctem.io/sensor-policy/v1` never gains a key again
  (a sensor refuses a key it does not know, so a new v1 key would stop every
  older sensor). `openctem.io/sensor-policy/v2` reads every v1 key plus
  `managed: {accept: bool}` (default true; false = the owner refuses
  platform-managed policy documents, D11; `LocalPolicy.AcceptsManagedPolicy`).
  The version is read first and the document then decoded strictly against
  that version's keys: a v1 file with a v2 key is refused. The report gains
  `schema` (the file's version) and `schemas` (the versions this SDK reads,
  `core.LocalPolicySchemas`), and the summary `managed_accept`, so the
  platform generates a recommended policy only in a version the sensor reads.
- **Local policy reload** (D10). `core.ReloadLocalPolicy(prev, opts)`; on a
  file that does not load, the result is the previous policy with the kill
  switch engaged and a warning naming the error (never the previous policy
  silently). `sensorkit.Kit.SetLocalPolicy` / `ReloadLocalPolicy` apply a
  policy to the running poller, executor and heartbeat;
  `Kit.ReloadLocalPolicyOnSIGHUP` reloads on every SIGHUP.

- **Structured policy refusals** (api research/25 §3.6, D8). A command a
  policy refused (the local policy's admission or executor checks, the kill
  switch, the platform's tool gate) is reported with
  `core.CommandResult.Refusal` (`core.Refusal{Layer, Rule, Detail}`; layers
  `builtin`, `local`, `managed`, `scope`, `platform_tool_gate`). The client
  sends it as `refusal` on v2 `POST /commands/{id}/fail` when the platform's
  hello lists the new feature `refusal` (`protov2.FeatureRefusal`), so the
  platform re-queues routed work to another sensor; the failure text is
  unchanged. `core.RefusalOf(err)` builds it; `LocalPolicyError` gains
  `Layer`. Values are bounded: unknown layers become `local`, malformed rules
  `unknown`, details lose control and bidi characters and stop at 512 bytes.

- **HTTP probe results keep what they learned about the server** (api
  research/22 E5). `core.LiveHost` gains `TLS` (`core.TLSLeaf`: the leaf
  certificate's subject, SANs, issuer, serial, validity and SHA-256
  fingerprint), `FaviconMMH3`, `JARM`, `ASN` (`core.ASN`) and `CDNType`.
  `pkg/ctis` follows ctis to the commit that adds `LiveHostInput.TLS`,
  `FaviconMMH3`, `JARM`, `ASN` and `CDNType` and emits a `certificate` asset
  per leaf (re-exported `TLSLeafInput`, `ASNInput`). The sensor maps httpx
  output onto them.
