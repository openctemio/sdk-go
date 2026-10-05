# Changelog

All notable changes to `github.com/openctemio/sdk-go`.

## Unreleased

### Upgrade notes

- **CTIS 1.4** (`pkg/ctis` follows `github.com/openctemio/ctis`): `ctis.SchemaVersion` changed from `"1.3"` to `"1.4"`, so `NewReport()` and every adapter now stamp `"version": "1.4"`. Reports declaring 1.0 to 1.3 are still accepted, decode strictly and validate. Code that compared a version against the literal `"1.3"` should use `ctis.SupportedSchemaVersions()` / `ctis.IsSupportedVersion()` (versions this SDK knows every member of) or `ctis.IsCompatibleVersion()` (any minor of major 1). The OpenCTEM API accepts the 1.4 stamp today; do not send the new 1.4 members until the API runs a ctis 1.4 build.

### Deprecated

- Packages with no importer in the sensor, the platform or the asset
  collector are marked `Deprecated:` and will be removed in a later minor
  release: `pkg/transport/grpc` and `proto/openctemio/v1` (removed in the
  next minor, which drops the `google.golang.org/grpc` dependency),
  `pkg/adapters/...`, `pkg/pipeline`, `pkg/audit`, `pkg/credentials`,
  `pkg/errors`, `pkg/health`, `pkg/metrics`, `pkg/options`,
  `pkg/enrichers/{epss,kev}`, `pkg/connectors/...`, `pkg/providers/github`
  and `pkg/scanners/tenable`. `docs/STABILITY.md` lists the replacement of
  each.

### Documentation

- `docs/rfcs/sensor-sdk-v2.md`: the accepted design for the next SDK
  generation (one tool contract with a `tool.yaml` manifest, out-of-process
  execution for every tool, adapter protocol v1 for any language, one
  runtime, stability tiers, transport v3 behind the SDK). `docs/STABILITY.md`
  now gives every package a tier (Stable, Beta, Frozen, Internal-bound,
  Deprecated). The module description no longer lists scanner wrappers
  (they moved to the sensor in v0.17.0).

### Added

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

### Changed

- The absent-policy warning says what actually happens: "jobs may enable
  out-of-band callbacks (interactsh), and custom templates run when
  SENSOR_TEMPLATE_SIGNING_KEYS is set" (it said both "are allowed").

### Fixed

- **Executor**: a task no longer fails to start ("landlock: file does not
  exist") when a file the launcher listed while granting read access
  disappears before its rule is added (another task's temporary file in
  /tmp). The vanished path is skipped; it grants nothing.
- **Cancels reach a sensor without the doorbell** (api RFC-046 §8). A
  sensor started with the doorbell off (`sensorkit.Options.DisableDoorbell`,
  `-disable-doorbell`) sent plain heartbeats and ignored the answer, so a
  scan the user canceled, a run that hit its deadline or a command handed to
  another sensor ran to the end. The plain heartbeat now reads
  `cancel_command_ids` (`client.SendHeartbeatForCancels`,
  `core.CancelPusher`) and the poller (`core.CommandCanceler`) stops and
  releases those commands, as with the doorbell. The heartbeat itself is
  unchanged: it does not announce the doorbell.
### Upgrade notes

- **`pkg/ctis` is now `github.com/openctemio/ctis`.** It re-exports the
  module (type aliases, constants and wrapper functions generated from the
  version in go.mod) instead of keeping a hand copy. Code that only uses
  the CTIS types, constants, `NewReport`, `FromSARIF`, `ConvertReconToCTIS`
  and so on builds unchanged, and `pkg/ctis` and module values are now the
  same types. `SARIFLog` and `SARIFRun` stay SDK types (the module's plus
  `versionControlProvenance` and `SARIFRun.Repository()`); the nested SARIF
  types are the module's, so one detail breaks:
  - `SARIFResult.RuleIndex` is `*int` (was `int`), so index 0 is
    distinguishable from absent.
  apidiff reports every exported signature that mentions a `pkg/ctis` type
  as changed, because the named types now live in the module; source code
  using the same names is unaffected.
  The sensor builds unchanged (`sensor-compat`).
### Added

- **Claim-N** (api RFC-046 §11, RFC-030 §5.9). Against a platform whose
  hello lists `capacity`, `GET /api/v2/sensor/commands` sends
  `X-OpenCTEM-Sensor-Features: capacity` and the platform answers with the
  commands already claimed for this sensor (acknowledged, lease set), at
  most its free slots of scans, in its fair order. `core.Command.Claimed`
  says so; the poller still acknowledges each one it runs (a replay) and
  now **releases** at once any claimed command it does not run (no free
  slot, type not allowed, expired, hosts busy, sensor paused), instead of
  leaving it to its lease. Older platforms and v1 are unchanged.
  `client.WithoutClaimOnPoll()` opts a client out (a caller that polls
  without running what it gets).

### Security

- **Secret masking reveals at most a quarter of a secret** (CTIS spec 4.8
  and 5.2). `core.MaskSecret` showed the first and last 3 characters of any
  secret over 8 characters, which is most of a 9-12 character password. It
  now shows nothing of a secret under 12 characters and at most a quarter of
  a longer one (at most 4 characters at either end), counts runes instead of
  bytes, and uses a fixed-length marker so the masked value no longer gives
  away the length. `MaskAPIKey` and the betterleaks adapter (which showed
  4+4 characters, all but one character of a 9-character secret) follow the
  same rule. `MaskSecretInText` now hides the whole text when the secret is
  not found in it. `core.GenerateSecretFingerprint` hashed the raw secret
  into the fingerprint, so a short secret could be recovered from the
  fingerprint by brute force; it now hashes the masked value.
  **Identity note:** `secret.masked_value`, and secret fingerprints built by
  these helpers, change once for every secret of 9 or more characters.
  OpenCTEM derives a secret finding's identity from `masked_value`, so the
  first scan after the upgrade reports such secrets under new identities.

- **Sensor-local policy** (api RFC-040 §5.7, owner decisions Q3 (a) and
  Q4 (a)). The network owner writes a read-only YAML file at install time
  (`SENSOR_LOCAL_POLICY`, `sensorkit.Options.LocalPolicyPath`, default
  `/etc/openctem/sensor-policy.yaml` when it exists; `apiVersion:
  openctem.io/sensor-policy/v1`): `targets.allow` / `targets.deny` (CIDRs,
  IPs, host names, `*.domain`), `targets.allow_private`, `ports.allow`,
  `tools.allow`, `checks.allow` (command types), `allow_custom_templates`,
  `allow_interactsh`, `rate.max_rps`, `rate.max_job_seconds`,
  `kill_switch` and `kill_switch_file`. Parsing fails closed: unknown keys,
  malformed entries, a second document, an empty or world-writable file, a
  configured path that does not exist, a private range without
  `allow_private`, or an always-blocked range in `targets.allow` stop the
  sensor (exit code 2). The command poller checks every job after it is
  claimed and before any executor or tool sees it
  (`LocalPolicy.AdmitCommand`): host names are resolved and every address
  must pass, so a name resolving to a denied address is refused; a job's
  `ports` setting (RFC-038) must lie inside `ports.allow`; a refused
  job is reported failed with `refused by local policy: <rule>: <detail>`.
  The executor enforces the same rules again (targets through
  `ScanTargetPolicy.Local`, templates, callbacks) and caps the rate and run
  time. The platform's tool policy, payload switches and limits cannot
  widen it. `LocalPolicy.CheckDial` / `DialContext` are the egress hook
  (RFC-034 forwarder, in-process dials): they dial the checked addresses
  only. A kill switch (policy key, or a file named by `kill_switch_file` or
  `SENSOR_KILL_SWITCH_FILE`) stops claiming, stops running jobs (reported
  failed) and makes the heartbeat say `paused by local policy`. Without a
  policy the sensor works as before and reports `local_policy: absent`
  with warnings; custom templates and interactsh stay allowed there until
  a policy sets them (they default to off in any policy).
  `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` are a shorthand policy
  without a file. Heartbeats and the manifest carry `local_policy` (state,
  digest, summary; never the ranges) only to a platform that lists the new
  hello feature `local_policy` (`protov2.FeatureLocalPolicy`). A scan's
  `timeout_seconds` is now capped at `core.MaxScanTimeout` (24h). New:
  `core.LocalPolicy`, `LoadLocalPolicy`, `ParseLocalPolicy`,
  `LocalPolicyOptions`, `LocalPolicyError`, `ErrRefusedByLocalPolicy`,
  `LocalPolicyReport`, `LocalPolicySummary`,
  `CommandPoller.SetLocalPolicy`, `DefaultCommandExecutor.SetLocalPolicy`,
  `BaseSensor.SetLocalPolicy`, `SensorStatus.LocalPolicy`,
  `Manifest.LocalPolicy`, `client.HeartbeatRequest.LocalPolicy`,
  `conformance.FakePlatform.SetLocalPolicy`.

- **v1 results name their command.** The v1 ingest path (the fallback when
  the platform has no protocol v2, `Protocol: v1`, and the outbox's v1
  delivery) now sends `X-OpenCTEM-Command-ID` with the command id from
  `core.WithCommandID` (`legacyv1.HeaderCommandID`). Without it the platform
  treated every v1 report as unsolicited and, under its `quarantine` policy,
  held it for review (api RFC-040 §5.3). When the platform answers
  `404 COMMAND_NOT_FOUND` (the command finished more than its grace period
  ago), the report is sent once more unbound, as the v2 path does. A command
  id that is not visible ASCII or is longer than 128 bytes is never put on
  the header.

### Changed

- **`pkg/ctis` imports `github.com/openctemio/ctis`** (owner decision Q3,
  research 16 G2), pinned to ctis main at `7d7d5ec` (untagged; includes
  ctis#14 secret-snippet masking in `FromSARIF`, ctis#15 recon hardening and
  ctis#16 SARIF suppressions). The hand copy had drifted and the sensor ran
  stale converters. Fixed by the switch:
  - recon reports validate: no scope type `web`, no raw recon type
    (`port`, `url_crawl`) as a capability, IPv6 addresses as `AAAA`
    records, one DNS record per value, hostname-only port results as
    `host` assets, every probe an `http_service`, stable asset IDs and order;
  - `FromSARIF` converts every run (each finding names its run's tool
    when there are several), reads `security-severity` and CVE/CWE tags,
    types Trivy CVEs as `vulnerability` (they were all misconfigurations),
    gives an unknown tool no capabilities (it got `vulnerability, secret`,
    so SAST from an unknown tool could be filed as secret), and gives the
    asset no criticality (it defaulted to `high`; spec 4.1 leaves it to the
    receiver);
  - `NewReport()` stamps schema version `1.3` (was `1.0`);
  - new from the module: `SchemaVersion`, `SchemaURL`, `ParseVersion`,
    `IsCompatibleVersion`, `(*Report).Validate`, `SARIFLogicalLocation`,
    `SARIFReportingReference`.
  The SDK keeps its asset rule on top of the module's `FromSARIF` (options,
  then branch info, then `versionControlProvenance`; results without an
  asset are `ErrNoAssetForFindings`), plus `CheckFindingAssets` and the
  `NormalizeSARIF*` helpers. `scripts/check-ctis-parity.sh` (the
  `ctis-parity` job) now regenerates the aliases and fails when they are
  stale, or when `pkg/ctis` declares a model struct of its own again.
  Bumping CTIS is `go get github.com/openctemio/ctis@<ver>` plus
  `go generate ./pkg/ctis`.
- **Every report the runtime pushes states `coverage_type`** (CTIS spec 4.5:
  an absent value is not `full`; research 16 G4, owner decision Q5). A scan
  command's report is `partial` when the scanner says the run stopped
  part-way (`ScanResult.Error`) or the report lists `failed_targets`, even if
  the parser declared `full`; otherwise a value the parser declared is kept;
  a repository scan (`metadata.branch`) is `partial`; any other completed
  run is `full`. Collector reports keep the collector's value, else
  `partial`. Daemon-mode scan and collect reports follow the same rules.
  The platform's coverage-scoped auto-resolve used to read the missing
  value as `full`; it is being changed to read it as not full, and this
  keeps completed sensor scans eligible after that change.

- `ctis.FromSARIF` carries `properties.tags` from the result and its rule
  into the finding's `tags` (they were dropped), as `github.com/openctemio/ctis`
  does (ctis#12). Tags are deduplicated ignoring case in first-seen order;
  non-string, empty and over-long (more than 128 bytes) entries are skipped; at
  most 50 are kept per finding.
- The SARIF converter keeps one secret-scanner list (gitleaks, betterleaks,
  trufflehog, detect-secrets, or any name containing `secret`) for both the
  finding type and the tool capabilities. Capabilities used to match any name
  containing `leaks`; they now match the same names as the finding type and
  as ctis.
- `scripts/check-ctis-parity.sh` also compares FromSARIF's secret-scanner
  list, tag caps, `sarifTags` / `isSecretTool` bodies and the shared
  betterleaks sample against ctis.

### Fixed

- **semgrep: a partially parsed file no longer drops every finding.**
  semgrep emits `errors[].type` as a string or an array
  (`["PartialParsing", [...]]`); `SemgrepError.Type` was a string, so
  `json.Unmarshal` failed for the whole document and the adapter returned no
  findings at all. `SemgrepError` now decodes every shape and keeps the kind
  name in `Type` (still a string, e.g. `"PartialParsing"`).

## v0.17.0 — 2026-10-03

### Upgrade notes

- **The tool wrappers are removed** (deprecated in v0.16.0). A program that
  imports `pkg/scanners`, `pkg/scanners/{nuclei,trivy,semgrep,betterleaks,codeql}`,
  `pkg/scanners/recon`, `pkg/scanners/recon/{subfinder,dnsx,httpx,naabu,katana}`,
  `pkg/handler` or `pkg/strategy` no longer builds against v0.17.0. The
  sensor has its own copies (`github.com/openctemio/sensor/internal/scanners`,
  `internal/recon`, `internal/handler`, `internal/strategy`) and builds
  unchanged; any other program should copy the v0.16.0 code or run the
  sensor. Nothing the wrappers used from the SDK goes away:
  `core.ExecuteScanner` / `StreamScanner`, the scanner environment,
  `core.ValidateExtraArgs` / `DangerousToolFlags`, `pkg/adapters`,
  `pkg/gitenv` and `pkg/scanners/tenable` stay.

### Removed

- **Breaking:** the deprecated tool wrapper packages `pkg/scanners` (the
  registry), `pkg/scanners/nuclei`, `pkg/scanners/trivy`,
  `pkg/scanners/semgrep`, `pkg/scanners/betterleaks`, `pkg/scanners/codeql`,
  `pkg/scanners/recon` and `pkg/scanners/recon/{subfinder,dnsx,httpx,naabu,katana}`
  (with their private helpers `pkg/scanners/internal/...` and
  `pkg/scanners/recon/internal/flagcheck`), the CI-mode `pkg/handler` and
  `pkg/strategy`, and the `examples/semgrep-test` program that used them.
  They live in the sensor now (see Upgrade notes). The finding-asset checks
  for what stays moved with it: `core.SARIFParser` in `pkg/core`, the Nessus
  converter in `pkg/scanners/tenable`.

### Security

- **Custom templates must be signed by the platform.** A scan command's
  custom templates are written and run only when the command carries the
  platform's signed manifest of them (`custom_templates_envelope`): a DSSE
  envelope (exact signed bytes, Ed25519 over the DSSE pre-authentication
  encoding) whose `core.TemplateManifest` names the tenant, sensor and
  command, the issue and expiry times, and the id, name, type and SHA-256 of
  every template in order. The signature is verified before the manifest is
  parsed; then a manifest for another command (or sensor, when the sensor
  knows its id), an expired one, unknown fields, or any template changed,
  added, held back or reordered fails the command. New:
  `core.TemplateVerifier`, `core.NewTemplateVerifier`,
  `core.ParseTemplateSigningKeys`, `core.TemplateKeyID`,
  `core.TemplateManifest`, `core.ManifestTemplate`, `core.SignedEnvelope`,
  `core.EnvelopeSignature`, `core.DSSEPreAuthEncoding`,
  `core.TemplateBinding`, `ScanCommandPayload.CustomTemplatesEnvelope`,
  `DefaultCommandExecutor.SetTemplateVerifier` / `SetSensorID`,
  `core.ErrNoTemplateKeys`, `core.ErrTemplatesUnsigned`. sensorkit reads the
  keys from `SENSOR_TEMPLATE_SIGNING_KEYS` (`Options.TemplateSigningKeys`; a
  malformed value stops the sensor with exit code 2) and binds manifests to
  `SENSOR_ID` when it is set. **Breaking for sensors that run custom
  templates:** without a pinned key, or for unsigned or altered templates,
  the command fails before any scanner runs. Pin the tenant's key from the
  platform (`GET /api/v1/scanner-templates/signing-key`).
- **More nuclei flags refused in extra args** (`core.DangerousToolFlags`,
  checked against nuclei v3.11.1 `-h`): template types the sensor never
  enables (`-file`, `-esc`, `-egm`, `-headless`, `-ho`, `-cdpe`, `-sc`,
  `-dast`, `-fuzz`; `-code` was already refused), the signature switch
  (`-dut` / `-disable-unsigned-templates`, so `-dut=false` cannot turn it
  off) and `-sign`, template sources by their real short names (`-turl`,
  `-wurl`, `-ai`, `-tp`, `-it`, `-vfp`), target sources that skip target
  validation (`-targets-inline`, `-uncover`/`-uq`/`-ue`, `-sa`, `-resume`),
  the short proxy flag `-p` and `-pi`, client TLS files (`-cc`, `-ck`,
  `-ca`), cloud upload (`-pd`, `-pdu`, `-auth`, `-tid`, `-sid`), listeners
  (`-dts`, `-hae`, `-ep`), engine/template updates and resets (`-up`,
  `-ut`, `-ud`, `-reset`) and more file writers (`-pe`, `-project-path`,
  `-profile-mem`).
- **Rate-limit flags refused in extra args** (`core.RateLimitToolFlags`:
  `-rate-limit`/`-rl`, `-bulk-size`/`-bs`, `-concurrency`,
  `-per-host-rate-limit`, `-rlm`, `-hbs`, `-headc`, `-jsc`, `-pc`, `-prc`,
  naabu `-rate`, `-threads`, ...): a free-form flag would get around the
  sensor's ceiling.

### Added

- `ScanOptions.RateLimit`, `BulkSize` and `Concurrency`: a scan command's
  config keys `rate_limit`, `bulk_size` and `concurrency` (whole numbers
  from 1 to `core.MaxScanLimit`; anything else fails the command) ask the
  scanner for gentler limits. `core.CapScanLimit` applies them under the
  ceiling the sensor's operator configured.

### Fixed

- **A scan command's config reaches the scanner as typed settings** (api
  RFC-038). `ScanOptions.Settings` existed but nothing filled it: the
  command executor read only `allow_interactsh` and `exclude` from the
  command's `config` and dropped every other key, so a platform pipeline
  step with `ports: "80"` ran naabu on its default ports. The executor now
  resolves the config keys that the scanner's settings schema declares, at
  scan level (only `x-octm-scope: "scan"` keys), into
  `ScanOptions.Settings`. An invalid value (wrong type, out of range,
  pattern mismatch, a sensor-only key) fails the command before the
  scanner runs; values never become free-form arguments. Keys the scanner
  does not declare are listed in the result's `ignored_config_keys`
  metadata instead of vanishing; `settings_applied` and
  `settings_schema_digest` say what was applied. A command that sets no
  declared key leaves `Settings` nil, as before.
- `core.SettingsSchemaProvider`: a scanner declares its schema with
  `SettingsSchema()`. `ToolRegistry.RegisterScanner` takes it into the
  tool's `ToolSpec.Settings` (manifest digest), and sensorkit's alias for a
  scanner configured under another name forwards it.

## v0.16.0 — 2026-10-03

### Added

- **Tool settings schemas** (api RFC-038). A tool declares what an
  administrator may configure as a `core.SettingsSchema`: a closed subset of
  JSON Schema 2020-12 (types, enum/const, numeric and length bounds, RE2
  `pattern`, `hostname`/`uri`/`duration` formats, arrays of scalars, one
  level of groups, `additionalProperties: false` everywhere) plus
  `x-octm-*` annotations (`schema-version`, `scope`, `tier`, `sensitive`,
  `restart`, `group`, `order`, `widget`). `$ref`, `oneOf`, conditionals,
  unknown keywords, duplicate members and schemas over 32 KiB or 64
  properties are refused.
  - `ParseSettingsSchema` / `MustParseSettingsSchema`, `Validate` /
    `ValidateJSON` (unknown keys rejected, sensitive keys never accepted as
    plain values; every problem as `SettingsErrors` with JSON-pointer
    paths), `Defaults`, `Digest` (`sha256:` over canonical JSON),
    `Property`, `ManifestSettings`; `core.SettingsDigest` for any document.
  - `Resolve(layers...)`: defaults, then sensor, profile and scan layers;
    a profile or scan layer may set only `scope: "scan"` keys. The result,
    `*core.ToolSettings` (`Int`, `Float`, `Bool`, `String`, `Duration`,
    `Strings`, `Source`, `Keys`; `Secret` reports nothing until secret
    settings are delivered), reaches a tool as `ScanOptions.Settings` (nil:
    the tool's defaults, as before).
  - Registration: `ToolSpec.Settings`; `ToolRegistry.SettingsSchema` /
    `SettingsSchemas`. The manifest names each tool's schema by version and
    digest only (`ManifestTool.Settings`, `core.ManifestToolSettings`);
    heartbeats are unchanged.
  - The sensor's stored settings document: `core.SensorSettings` (kind
    `openctem.sensor.settings/v1`, `Check`, `ValidateAgainst`),
    `core.SettingsStore`, `core.NewFileSettingsStore` (0600 file in a 0700
    directory, temporary file + fsync + rename; a version not above the
    stored one is refused with `ErrSettingsVersionNotNewer`).
  - `protov2.FeatureToolSettings` (`"tool_settings"`), for
    `Client.PlatformSupports`.
  - Golden vectors in `pkg/core/testdata/settings-vectors`: the platform's
    validator copy must give the same verdicts, error paths, defaults and
    digests for every file.
- **`docs/STABILITY.md`**: the stable surface, how tools, flags, formats and
  platform features are added without an SDK release, protocol
  compatibility (unknown members ignored on the control plane; CTIS is
  strict and receiver-first), the versioning and deprecation policy with a
  path to v1.0.0, the safety every sensor gets, and conformance.
- `Client.PlatformSupports(ctx, feature)`: whether the platform's hello lists
  a feature, including names newer than this SDK. False against a platform
  without protocol v2, one that cannot be asked right now, or with protocol
  v1 set. A sensor gates an optional behavior on it.
- **Recon tools as scanners** (api RFC-036 P0). `pkg/scanners/recon`
  runs subfinder, dnsx, naabu, httpx and katana as `core.Scanner` (and
  `core.MultiTargetScanner`): `recon.New(name)` runs the tool on each target,
  converts the results with `ctis.ConvertReconToCTIS` and returns the CTIS
  report as raw output, which the generic CTIS parser reads, so discovered
  hosts, IPs, services and URLs reach the platform as assets through normal
  ingest. It advertises the platform catalog's capabilities for each tool
  (`recon.Capabilities`). A target the tool fails on (exits non-zero) is
  listed in the report's `failed_targets` property while the other targets'
  results are kept; a job where every target failed fails instead of
  reporting 0 assets.

- **Command lease epoch** (api RFC-035 D6). Protocol v2 commands carry
  `lease_epoch` and `lease_expires_at` (`protov2.Command.LeaseEpoch`,
  `LeaseExpiresAt`; `client.Command` and `core.Command` have them too, as of
  the poll). The client keeps the epoch of the latest claim or start answer
  of each command it holds and sends it in `X-OpenCTEM-Lease-Epoch`
  (`protov2.HeaderLeaseEpoch`) on complete and fail, so a sensor whose
  command was re-queued and claimed again cannot finish the new holder's
  run. No header when the epoch is unknown (a platform from before leases,
  or a result delivered by the outbox after a restart): the platform then
  fences by sensor and state as before. Never sent on protocol v1. A refusal
  still reads as a gone command (`client.IsCommandGone`) and is dropped as
  before; its error now says that the lease was lost.
- The conformance fake platform (`pkg/conformance`) numbers claims, returns
  the epoch on commands and refuses a complete or fail under another epoch
  with `invalid-transition`, as the platform does. `FakePlatform.ReclaimCommand`
  simulates a lease loss; `FakePlatform.LeaseEpoch` reads a command's epoch.
- **Sensor conformance suite for any sensor** (`conformance.RunSensorSuite`).
  A sensor built on the SDK (or any sensor that speaks the protocol) runs it
  from its own tests with a function that starts it against a
  `SensorEndpoint`. Each check gets a fresh fake platform: the sensor
  heartbeats and names its SDK; it registers its manifest when asked; a
  command of a type it does not handle is left pending for another sensor
  (or failed), never claimed and abandoned; it keeps working when every
  answer carries a JSON member no SDK knows (forward compatibility); and,
  given `SuiteOptions.ScanPayload`, its command completes with every
  report committed first. The kit passes it (`pkg/sensorkit` test).
- `FakePlatform.QueueCommandPayload` queues a command with its own type and
  payload. `FakePlatform.FutureFields` / `SetFutureFields` make every JSON
  answer (problem documents included) carry `FutureMember`, as a newer
  platform's would.

### Deprecated

- **The tool wrappers moved to the sensor** (owner decision 2026-10-02:
  sdk-go is the shared interfaces, runtime and safety layer). These packages
  are deprecated and are removed in v0.17.0; their code now lives in
  `github.com/openctemio/sensor/internal/...`:
  `pkg/scanners` (the registry) and `pkg/scanners/{nuclei,trivy,semgrep,betterleaks,codeql}`
  in `internal/scanners/...`, `pkg/scanners/recon` and
  `pkg/scanners/recon/{subfinder,dnsx,httpx,naabu,katana}` in `internal/recon/...`,
  and the CI-mode `pkg/handler` and `pkg/strategy` in `internal/handler` and
  `internal/strategy`. They are unchanged and
  still work until then. What the wrappers use stays here and is not
  deprecated: `core.ExecuteScanner` / `StreamScanner`, the scanner
  environment, `core.ValidateExtraArgs` / `DangerousToolFlags`,
  `pkg/gitenv`, `pkg/adapters` and `pkg/scanners/tenable`. A program that
  embeds a wrapper should copy it or move to the sensor.

### Fixed

- Recon tool command lines, checked against each tool's own `-h` output
  (vendored in `pkg/scanners/recon/testdata`; a test fails on any flag the
  pinned version does not define): **dnsx** used `-d` (its brute-force input,
  which exits "missing wordlist") for a single target and the undefined
  `-rw`; it now uses `-l` and `-auto-wildcard`. **naabu** passed the scan
  type as a bare `-c`/`-s`; `-c` is the worker count and took `-silent` as
  its value, so every default naabu run failed; it is now `-s c`, and
  `-sv` is `-sV`. **katana** passed the undefined `-output-all` on every run
  (every run failed), the dn/rdn/fqdn scope as the regex flag `-cs` instead
  of `-fs`, `-form-fill` instead of `-aff`, and `-rd` in milliseconds where
  katana reads seconds. **httpx** passed the undefined
  `-no-follow-redirects`. Every tool now gets `-duc`, so no run calls
  ProjectDiscovery's update check.
- httpx results were all dropped: `a` and `cname` are arrays in httpx's
  JSON and decoding them into strings failed every line, which the parser
  skipped as "not JSON". The JARM and TLS fields used names httpx does not
  write (`jarm_hash`, `subject_an`, `subject_cn`, `issuer_cn`). The arrays are `HTTPXOutput.A`/`AAAA`/`CNAMEs` and
  `HostIP`; the string fields `IP` and `CNAME` are kept, deprecated, and
  filled from them.
- katana results were garbage: `request` is an object, so every line was
  taken for a plain URL holding the whole JSON text. `KatanaOutput` gains
  `Request`/`Response`/`Error`; its flat fields (`URL`, `Endpoint`, `Method`,
  `Source`, `Tag`, `Depth`, `Status`) are kept, deprecated, and filled by
  `Flatten`. Requests that got no
  response are no longer reported as discovered URLs. katana 1.7's version
  ("Current version:") parses.
- The subfinder parser typed every host as `domain`; a host below its root
  is now `subdomain`, as `ctis.ConvertReconToCTIS` types it.
- **SARIF `kind` and `baselineState` reach the platform in the CTIS
  vocabulary.** The SARIF adapter copied `result.kind` verbatim, so a sensor
  sent SARIF's `notApplicable`, which the CTIS schema and the platform's
  `findings.kind` check reject (the platform only kept it because its ingest
  normalizes). `pkg/ctis.FromSARIF` dropped both fields. Both paths now send
  `not_applicable`, `pass`, `fail`, `review`, `open` or `informational`, and
  `new`, `unchanged`, `updated` or `absent`, matched case-insensitively; a value
  outside SARIF's set is left unset and an absent `kind` is not defaulted to
  `fail`. New `ctis.NormalizeSARIFKind` and `ctis.NormalizeSARIFBaselineState`;
  `ctis.SARIFResult` gains `Kind` and `BaselineState`. Mirrors
  openctemio/ctis#10 (same sample, `pkg/ctis/testdata/sarif/kinds.sarif`).

### Security

- **nuclei: Interactsh (out-of-band callbacks) is off by default.** Every
  nuclei scan now runs with `-ni` unless something opts in, so a scan no
  longer makes targets call out to the public `oast.*` servers, and no scan
  data leaves through them, without anyone choosing that. Opting in:
  `nuclei.Scanner.AllowInteractsh` (new; also `NucleiOptions.AllowInteractsh`),
  an operator-run `InteractshServer`, or per scan the new
  `core.ScanOptions.AllowInteractsh`, which the command executor sets only
  when the platform's scan command carries `config.allow_interactsh: true`
  (a JSON boolean; meant for approved intrusive runs). `NoInteractsh` still
  forces it off, and `InteractshToken` is passed only when it is on. The new
  `Scanner.InteractshEnabled(opts)` reports the decision. Templates that need
  OAST (tag `oast`, e.g. in `NewDAST`) are skipped by nuclei while it is off:
  that is the intended trade.

- `strategy.GetChangedFiles` ran `git diff` in the scanned repository with
  the sensor's whole environment (its API key included). It now gets the
  scanner environment (`core.ScannerEnviron`) plus the git variables that
  locate the repository. Tests now prove that no SDK-started process
  (scanners, version probes, content downloads, git) sees `API_KEY`,
  `SENSOR_*` keys, the outbox key, tokens or passwords.

## v0.15.0 — 2026-10-02

### Added

- **Sensor control plane under load** (api RFC-035 Phase 1). A sensor whose
  scanners saturate the machine keeps heartbeating, and the kernel kills a
  scanner, not the sensor, when memory runs out.
  - **Control channel.** Heartbeats use their own HTTP client: a clone of
    the API client's transport (same proxy, TLS settings and dial guard)
    with its own connection pool. Each request is bounded by the new
    `Config.ControlTimeout` (default `client.DefaultControlTimeout`, 15s;
    never above `Timeout`) and retried at most once. A failed heartbeat is
    not retried with its stale report: the next one follows after
    `core.HeartbeatRetryDelay` (10s ± 20%, never above the interval). The
    manifest exchange before a heartbeat is bounded by 15s.
  - **Version probes off the heartbeat.** `ToolRegistry.SetBackgroundRefresh`
    reports a stale probe as it is and probes again in the background (the
    first probe and the one after `Refresh` stay in the report). sensorkit
    turns it on. Under load the inline probes delayed a heartbeat by 4s.
  - **`control` on every heartbeat** (`core.ControlStats`,
    `SensorStatus.Control`): the interval followed, the gap since the
    previous delivered heartbeat, how late the timer fired (CPU wait), the
    time spent building the report, the previous round trip, and the
    failures since. Additive; a platform that does not know it ignores it.
  - **Scanner priority** (`core.ScannerPriority`, `SetScannerPriority`,
    `ApplyScannerPriority`; Linux). Every scanner process group the SDK's
    exec helpers start runs at nice +10 and best-effort I/O level 7, with
    `oom_score_adj` 500 (`core.DefaultScannerPriority`). The change is best
    effort and is skipped where refused. It is off by default in `core`.
    sensorkit turns it on unless `SENSOR_SCANNER_PRIORITY=normal`
    (`Options.ScannerPriority`, `ResolveScannerPriority`).
  - **Memory headroom.** The slots leave memory free for the sensor itself
    (`resource.ManagerConfig.ReservedMemBytes`). The default
    (`resource.DefaultReservedMem`) is a tenth of the memory the sensor may
    use, between 256 MiB and 1 GiB.

- **Proxy settings per outbound path** (api RFC-034 Phase 0).
  - **Two new sensorkit settings:**
    - `SENSOR_CONTROL_PROXY` covers every request to the platform.
    - `SENSOR_CONTENT_PROXY` covers scanner content and public feeds.
  - **Values.** Each takes a proxy URL (`http`, `https`, `socks5`,
    `socks5h`, user:password allowed) or `direct`. With a URL, `NO_PROXY`
    is the bypass list.
  - **Precedence.** An option comes first, then the setting. After that,
    control falls back to `HTTP(S)_PROXY`, and content follows the control
    setting.
  - **API.**
    - sensorkit: `ResolveProxies`, `Proxies`, `ProxyOptions`, and
      `Options.ControlProxy` / `ContentProxy` / `ScanProxy`.
    - httpsec: `ProxySetting` (with `ParseProxySetting`),
      `SetAPIProxy` / `APIProxy`, `SetContentProxy` / `ContentProxy`, and
      `ProxyFunc`.

    The API client's transport (`NewAPIClient`) uses `APIProxy`. A
    dedicated platform client can install `httpsec.APIProxy().Func()` as
    its `Transport.Proxy`.
  - **CA file.** `SENSOR_CA_CERT_FILE` is now also trusted for content
    downloads (`SetContentRootCAs`), so a TLS-inspecting egress proxy works
    for both paths.
- **Scanner proxy mode** (api RFC-034 G1, owner decision O2).
  - **Setting.** `SENSOR_SCAN_PROXY` (or `OPENCTEM_SDK_SCANNER_PROXY`):
    - `inherit` (default, unchanged behavior): scanner processes get the
      sensor's `HTTP(S)_PROXY` / `ALL_PROXY` / `NO_PROXY`;
    - `direct`: they get none, apart from variables a caller passes
      explicitly.
  - **Start-up log.** The kit logs one line with the three paths. While
    scanners inherit proxy variables that the operator did not choose
    explicitly, it also warns, naming the variables with credentials
    removed.
  - **Content tools.** `core.ContentEnviron` builds the environment of a
    content tool (trivy's DB download, template updates). It follows the
    content proxy.
  - **API.** `core.ScannerProxyMode`, `ParseScannerProxyMode`,
    `SetScannerProxyMode`, `ScannerProxy` and `ScannerProxySummary`.
- **`httpsec.TrustUpstreamHosts`.** It registers host names the program
  hard-codes. When local DNS cannot resolve such a name, it may still go
  through a proxy, which resolves it. The KEV and EPSS enrichers register
  their default hosts.

- **Platform policy and slim heartbeats** (api RFC-033 §6.12, owner decisions
  O2 and O3).
  - **Manifest answer.** It now carries the platform's policy (allowed
    tools, capabilities and capacity, after the administrator's narrowing)
    and `heartbeat.omit_inventory`.
  - **Policy refresh.** The `BaseSensor` keeps the policy
    (`BaseSensor.ManifestPolicy`). It re-reads it with
    `GET /api/v2/sensor/manifest` (`client.GetManifestState`) when the
    heartbeat's `config_version` moves.
  - **Command refusal.** `BaseSensor.CommandToolGate` refuses a command
    whose tool (payload `scanner`, else `preferred_tool`, canonical) is
    outside the policy. sensorkit wires it with the new
    `CommandPoller.SetCommandGate`. The command is reported failed with
    `ErrToolNotAllowed` and is never run.
  - **Slim heartbeats.** While a heartbeat echoes a digest the platform
    acknowledged with `omit_inventory`, it leaves `tools`, `capabilities`
    and `max_concurrent_jobs` out. It carries each tool's content freshness
    as `content` (`core.ToolContent`, `SensorStatus.Content`).
  - **Compatibility.** A platform that does not say `omit_inventory`
    (before Phase 2, or with its kill switch) keeps getting full
    heartbeats.
  - **New API.** `core.ManifestPolicy`, `core.ManifestStateReader`,
    `core.ErrManifestNotRegistered`, `core.ErrToolNotAllowed`, and
    `ManifestAck.Policy` / `OmitInventory`. In `sensorproto/v2`:
    `ManifestPolicy`, `ManifestHeartbeat`, `ManifestStateResponse` and
    `ProblemManifestNotFound`.
  - **Conformance fake.** New `SetManifestPolicy`; `GET /manifest` is now
    served.
- **Sensor OOM protection** (api RFC-035 §5.3, opt-in). A new sensorkit
  setting `SENSOR_PROTECT_FROM_OOM=true` (`Options.ProtectFromOOM`,
  `ResolveProtectFromOOM`; default off) makes `Run` set the sensor's own
  `oom_score_adj` to `sensorkit.SensorOOMScoreAdj` (-500), so the kernel
  kills almost anything else before the sensor when memory runs out. Linux
  only. Lowering the score needs `CAP_SYS_RESOURCE`, which Docker does not
  grant by default (`docker run --cap-add SYS_RESOURCE`; root under
  systemd has it). Without it the sensor prints one warning and runs
  unprotected; startup never fails for it. The banner shows the outcome.
  - **Scanners never inherit the protection.** A child inherits
    `oom_score_adj` at fork. `core.ApplyScannerPriority` now raises a
    scanner whose sensor has a negative score to at least 0, also with
    `SENSOR_SCANNER_PRIORITY=normal` (the low priority already sets 500).
    This also covers a sensor protected by systemd's `OOMScoreAdjust`.

### Changed

- **`httpsec.SafeHTTPClient` now uses a proxy** (api RFC-034 G2).
  - **Which proxy.** It uses the content proxy setting, by default the
    environment's `HTTP(S)_PROXY` / `NO_PROXY`. It used to ignore every
    proxy, so upstream content, KEV/EPSS and collectors could not connect
    on a network whose only way out is a proxy.
  - **Target check moved.** With a proxy, the transport dials the proxy,
    so the SSRF check now runs on the request's own target before the
    proxy is used: blocked names, blocked IP literals and every resolved
    address. This covers redirects too. A name that does not resolve
    locally is refused (`ErrProxiedTargetBlocked`) unless it was
    registered with `TrustUpstreamHosts`.
  - **The proxy itself.** It is dialed under the operator-destination
    policy: private addresses are allowed; link-local, multicast and
    reserved addresses are refused.
  - **Opting out.** `SENSOR_CONTENT_PROXY=direct` (or
    `SetContentProxy(direct)`) restores direct connections.

### Fixed

- The doorbell logged `send_manifest` (api RFC-033) as an unknown heartbeat
  action, although the BaseSensor acts on it.
- Protocol v2 results: a 413 without a problem document (a reverse proxy's
  body limit, such as ingress-nginx's 1 MiB default in front of the
  platform's 16 MiB) now splits the report into smaller segments, as the
  platform's own 413 does. Before, the report was refused for good and the
  outbox moved it to the dead-letter folder.
- Outbox: when the byte or age cap evicts a result of a command (or the
  result becomes unreadable), the command's result now reports the command
  `failed` ("results of the command were lost before delivery: ...")
  instead of `completed`. Before, the platform saw a clean, complete run
  that was missing its findings. The mark is persisted in the command
  result's state (`outbox.State.LostResults`), so it survives a restart.
- Outbox: the byte cap evicts command results after every other pending
  item. A command result is a few hundred bytes, and evicting it left its
  command running on the platform until the command timed out.
- **Scanner output is bounded.** `ExecuteScanner`, `StreamScanner` and
  `BaseScanner.Scan` kept all of a scanner's stdout and stderr in memory,
  however much it wrote; a scanner pointed at a hostile target, or one that
  loops, could exhaust the sensor's memory. Stdout is now bounded (512 MiB by
  default, `ExecConfig.MaxOutputBytes` / `BaseScannerConfig.MaxOutputBytes`
  to change it): past the bound the scanner's process group is killed and
  the call returns `ErrScannerOutputTooLarge`, so the scan fails visibly
  instead of reporting partial results. Stderr keeps its first 4 MiB and is
  marked as cut.
- **`StreamScanner` stalled on long lines.** It read with `bufio.Scanner`,
  whose 64 KiB line limit stopped the reader at the first longer line (a
  nuclei finding carrying a response body): the scanner then blocked on a
  full pipe until its timeout and the rest of its output was lost. Lines of
  any length are now delivered.
- **The outbox no longer replaces a missing key while sealed items exist.**
  When the key file was missing (a secret that failed to mount, a key
  deleted by hand) `outbox.Open` created a new key, and every pending result
  and dead letter, sealed with the old key, was quarantined: lost. `Open` now
  refuses with `outbox.ErrKeyMissing`; the error names the key path and the
  number of sealed items, and says how to recover (restore the key, or move
  `pending/` and `dead/` aside to start fresh). An empty outbox still gets a
  new key. The sensor exits with that message instead of starting. The
  outbox status command (`sensorkit.OutboxCommand`) never creates a key: it
  reports the same error, or an empty outbox. New: `outbox.ErrKeyMissing`,
  `outbox.CheckKey`, `outbox.SealedItems`, `outbox.DefaultKeyFile`.

### Security

- **Scanner extra args are checked in the SDK** (`core.ValidateExtraArgs`,
  `core.DangerousToolFlags`). Every scanner that appends
  `ScanOptions.ExtraArgs` / `ReconOptions.ExtraArgs` (base scanner, nuclei
  `Scan` and `ScanTargets`, semgrep, subfinder, httpx, dnsx, naabu, katana)
  now refuses a scan whose extra args contain a flag that redirects output,
  sets a proxy, names targets or target files, loads templates or rules, sets
  an interaction server, enables a headless browser, sets DNS resolvers, or
  picks an interface or source address, runs a command (naabu
  `-nmap-cli`), exports files, or loads remote templates, workflows or the
  code protocol, bare or as `flag=value`, with any number of leading dashes
  (Go's flag package treats `-proxy` and `--proxy` alike). The sensor
  enforced this set in its platform-mode executor until that mode was removed
  (sensor#107); without this, nothing guarded extra args.
- `httpsec` always blocks the cloud metadata service over IPv6 (AWS
  `fd00:ec2::254`, GCP `fd20:ce::254`), as it already did `169.254.169.254`.
  Both sit inside `fc00::/7`, so allowing private ranges
  (`OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE`, `SENSOR_ALLOW_PRIVATE_TARGETS`) used
  to open them. The scan-target policy (`core.ScanTargetPolicy`) applies
  the same hard block.
- `core.WebhookCollector` enforces its `Secret` (sent as
  `Authorization: Bearer <secret>` or `X-Webhook-Secret`; without it a
  delivery is refused with 401) and bounds the request body (413 past the
  limit), which it used to read without a limit.

## v0.14.0 — 2026-10-02

### Added

- **Sensor manifest** (api RFC-033). A `BaseSensor` builds its manifest from
  the capability report: build, platform, resources, the operator's ceiling,
  the sensor-wide capabilities, and each tool's kind, version, capabilities
  and content versions. On a platform that lists `manifest` on hello, the
  sensor registers the manifest before its first heartbeat, again when its
  own digest changes, and again when a heartbeat answer carries
  `send_manifest`. Every heartbeat then sends `manifest_digest`, the digest
  the platform returned.
  - A platform without the feature changes nothing: heartbeats still carry
    the full inventory, as before.
  - A failed registration retries after a minute and never fails the
    heartbeat.
  - The ignored items the platform reports are logged.
  - New API:
    - `core.Manifest`, `core.BuildManifest`, `Manifest.Digest` (the
      platform's canonical form, pinned by a test on both sides)
    - `core.ManifestPusher`, `core.ManifestAck`, `core.ErrManifestUnsupported`,
      `core.HeartbeatActionSendManifest`
    - `client.(*Client).PutManifest`, `SensorStatus.ManifestDigest`
    - `sensorproto/v2`: `ManifestPath`, `FeatureManifest`,
      `ManifestResponse`, and the two manifest problem types
  - `conformance.FakePlatform`: `SetManifest`, `Manifests`, `ForgetManifest`.

## v0.13.0 — 2026-10-02

### Upgrade notes

Only additions. A heartbeat's `max_concurrent_jobs` is now only the
operator's ceiling (`SENSOR_MAX_JOBS`, `ToolRegistry.SetMaxConcurrentJobs`,
`resource.ManagerConfig.Cap`): a sensor with resource-sized slots and no cap
no longer reports the resource manager's safety bound (64) there. What it
can run now is `capacity.slots_total`, as before. Platforms from before
api RFC-033 then fall back to the administrator's limit, still bounded by
the free slots the sensor reports.

### Added

- **Each heartbeat tool carries its capabilities** (`core.ToolInfo.Capabilities`,
  `"capabilities"` on the wire): the tool registry reports which tool serves
  what (`nuclei` → `dast`, `validate:nuclei`; `semgrep` → `sast`) instead of
  only the sensor's flat list. Platforms that do not know it ignore it.
- `core.VersionOutput`: a tool's whole version output, read from stderr
  when stdout is empty, with ANSI colors removed; `core.StripANSI`,
  `core.VersionAfterLabel`. `resource.(*Manager).Cap`: the operator's cap.

### Fixed

- **nuclei's version was never reported.** nuclei v3 prints its version
  banner (`[INF] Nuclei Engine Version: v3.11.1`, in color) only to stderr;
  `CheckBinaryInstalled` read stdout, so nuclei was installed with no
  version. It now falls back to stderr and strips colors, and nuclei,
  subfinder, dnsx, httpx, katana and naabu parse their whole banner
  (`Engine Version:` / `Current Version:`).
- **A sensor without `SENSOR_MAX_JOBS` reported `max_concurrent_jobs: 64`**
  (the resource manager's upper bound) next to `slots_total: 4` on a 4-core
  machine, and the platform took 64 as its capacity. The ceiling is now
  reported only when the operator set one (see Upgrade notes).

## v0.12.0 — 2026-10-02

### Upgrade notes

Only additions (checked by `api-compat` against v0.11.0). Every heartbeat
now carries `instance_id` (a random id per process); platforms that do not
know it ignore it.

### Added

- **`pkg/sensorkit`: everything a sensor needs to work with the platform, in
  one call.** A sensor implements its tools; `sensorkit.New(Options)` +
  `kit.AddScanner(...)` + `kit.Run(ctx)` does the rest: standard settings
  (`API_URL`, `API_KEY`, `SENSOR_*`, pre-rename `AGENT_*` migrated with a
  warning) with clear errors and exit codes (`ExitCode`, `Exit`: 2 for a
  missing or out-of-range setting), protocol v2 negotiation with v1
  fallback, the first heartbeat before the first poll and a wait while the
  key is rejected, the tool registry on every heartbeat (with optional
  scanner content, `Options.Content`), the heartbeat doorbell, API-key
  auto-renewal (`PLATFORM_KEY_AUTORENEW`), the command poller with
  resource-sized slots (`SENSOR_MAX_JOBS` cap), the durable outbox
  (`SENSOR_OUTBOX*`), the `SENSOR_TOOLS` allowlist and a SIGINT/SIGTERM
  drain (`SENSOR_DRAIN_GRACE`; a second signal exits 130). Extension points:
  `AddCollector`, `AddParser`, `HandleCommand`, `UseCommandMiddleware`,
  `Tools`, `Options.ScanTargetPolicy`, `AssetResolver`,
  `UnavailableReason`. The resolvers are exported for sensors with their own
  flags or configuration file (`ResolveMaxJobs`, `ResolveOutbox`,
  `ResolveProtocol`, `ResolveDrainGrace`, `CheckCredentials`,
  `MigrateSettings`, `OutboxCommand`, `FlushOutbox`, `SignalContext`).
  README "Build a sensor in 30 lines" and `examples/minimal-sensor`. The
  official sensor's daemon runs on it with its wire unchanged.
- `SENSOR_CA_CERT_FILE` (`sensorkit.Options.CACertFile`): a PEM file with the
  platform's private CA, trusted for platform requests besides the system
  roots. `httpsec.SetAPIRootCAs`, `httpsec.LoadCAFile`: the roots every
  `httpsec.NewAPIClient` created afterwards trusts.
- `legacyv1.SensorRenamedEnv`, `SensorRenamedFlags`, `ApplyRenamedEnv`,
  `ApplyRenamedFlags`: the sensor binary's renamed settings, migrated in one
  place (moved from the sensor).
- **Per-process instance id on every heartbeat** (api RFC-032 Phase 0):
  `core.ProcessInstanceID()` (32 hex characters, stable for the life of
  the process), `core.SensorStatus.InstanceID` and
  `client.HeartbeatRequest.InstanceID` (`instance_id`, defaulting to the
  process id). A restart changes it once; one key running in two places
  makes two ids alternate, which the platform flags as a cloned identity.
- **The renewed API key survives a restart** (api RFC-032 Phase 0). A key
  renewal retires the key a sensor was installed with, so a recreated
  container must find the renewed key again. In `pkg/platform`:
  - `ResolveStateDir(explicit)`: `explicit`, `$SENSOR_STATE_DIR`,
    `DefaultStateDir` (`/var/lib/openctem/state`) when writable, else
    `~/.openctem`.
  - `ResolveStateCredentialsFile(explicit, stateDir)`: the credentials file
    in the state directory (`StateCredentialsFile`), moving one an earlier
    version kept in `~/.openctem` there first.
  - `ChooseAPIKey(store, configuredKey, sensorID)`: the renewed key from
    the file wins over the configured one, unless the configured key is
    not the one it was renewed from (an administrator regenerated the key
    and the operator configured the new one).
  - `RotatedKeySaver(store, configuredKey, sensorID)`: a
    `KeyRenewConfig.OnRotated` that saves each renewed key atomically, 0600
    (directory 0700), with its expiry, whether it never expires
    (`SensorCredentials.NeverExpires`) and the fingerprint of the
    configured key (`SensorCredentials.ConfiguredKeyFingerprint`, a salted
    PBKDF2-SHA256 fingerprint, never the key itself).
  - `KeyFingerprint(key)` / `KeyFingerprintMatches(fp, key)`: that
    fingerprint (`pbkdf2-sha256$<iterations>$<salt>$<hash>`) and its
    constant-time check.
  - `CheckStatePersistence(dir)` and `DecideKeyAutoRenew(setting, p)`:
    renew automatically only when the state survives the container being
    recreated (outside a container, always; inside, only on a mounted
    volume that is not a tmpfs), unless the setting forces it on or off.

- **`sensorkit` keeps the renewed key in the state directory** (api RFC-032
  Phase 0), through the `pkg/platform` functions above:
  `Options.StateDir` / `SENSOR_STATE_DIR` default to
  `/var/lib/openctem/state` when writable (else `~/.openctem`) and hold the
  renewed key and the tool cost history; the key is chosen with
  `ChooseAPIKey` on every start (renewal on or not), saved with
  `RotatedKeySaver`, and a `~/.openctem` file is moved in. Key renewal is
  on when the state directory persists, off otherwise;
  `Options.KeyAutoRenew` / `NoKeyAutoRenew` or `PLATFORM_KEY_AUTORENEW=true|false`
  force it. The kit's heartbeats carry `instance_id`.

### Changed

- `sensorkit.ResolveStateDir(explicit)` resolves the state directory
  (`platform.ResolveStateDir`) instead of using the outbox directory's
  parent; the tool cost history moves with it.
- `platform.Bootstrapper` and `platform.EnsureRegistered` document that no
  OpenCTEM API serves `POST /api/v1/platform/register` (bootstrap tokens
  were never built; enrollment tokens replace them in api RFC-032 Phase 2).
  Nothing is removed.

## v0.11.0 — 2026-10-02

### Upgrade notes

Only additions (checked by `api-compat` against v0.10.0). One behavior
change: **a `BaseSensor` now reports the scanners and collectors it was
given** (`AddScanner`, `AddCollector`) on every heartbeat, probed with each
scanner's `IsInstalled`, unless `SetCapabilityReporter` is set (that
reporter still wins). A sensor that adds nothing still reports nothing. The
platform then dispatches by those tools; to keep sending nothing, set
`s.SetCapabilityReporter(core.StaticCapabilities(core.CapabilityReport{}))`.

### Added

- **Tool registry: a sensor registers its tools, the SDK reports them**
  (api RFC-029 §4.3.1). Only the sensor knows which tools it has, so the
  platform no longer needs them declared. `core.ToolRegistry` is the
  default source of the heartbeat's `tools`, `capabilities` and
  `max_concurrent_jobs`; no hand-written `CapabilityReporter` is needed.
  - `BaseSensor.Tools()` returns the sensor's registry. `AddScanner` /
    `AddCollector` register into it and `RemoveScanner` /
    `RemoveCollector` take the tool out.
  - `ToolRegistry.Register(core.ToolSpec{Name, Kind, Version,
    Capabilities, Probe, Cost})` registers any tool. `RegisterScanner(s,
    extraCaps...)` and `RegisterCollector(c, caps...)` register a
    scanner or a collector.
  - `Probe` (the `Scanner.IsInstalled` signature) says whether the tool is
    usable here and its version. A tool without a probe runs in process
    and is always usable. Results are reused for 10 minutes
    (`SetProbeTTL`, `Refresh`), and each probe is bounded by 30 s
    (`SetProbeTimeout`). A tool that is missing, fails its probe or times
    out is reported with `installed: false` and serves nothing.
  - Capabilities: an installed tool serves its name and its capabilities.
    A scanner's descriptive words are mapped to the platform's capability
    registry (`secret_detection` becomes `secrets`), and words the platform
    does not know are left out. Explicit capabilities are kept as given.
    `AddCapabilities` adds what the sensor serves whatever its tools
    (`validate`), and `SetMaxConcurrentJobs` sets its cap.
  - Two registrations of one name (two modes of one tool) merge their
    capabilities. Names are validated (lowercase `[a-z0-9._-]`, at most 64
    characters).
  - `Limit(names...)` is an operator allowlist: only those tools are
    reported and served, and no names lifts it. A limit that leaves no tool
    reports an empty inventory ("none"), not "nothing reported".
  - `DefaultCommandExecutor.SetToolRegistry(s.Tools())` registers the
    executor's scanners and collectors too, for a sensor that runs its
    tools only through the command executor.
  - Heartbeat tools carry `kind` (`scanner` or `collector`; the
    `ToolInfo.Kind` field, additive and ignored by older platforms).
- **Per-tool cost hints:** `ToolSpec.Cost` (`resource.ToolCostHint`:
  cores, memory, seconds per target) is used as the slot sizer's prior for
  a tool without history: `resource.ManagerConfig.CostHints`
  (`registry.CostHints()`) and `CostBook.SetPrior`. The learned history
  still replaces it.

### Fixed

- `TestQueue_DrainReleasesUnfinished` no longer races the poller's claim
  of the next command (test only; #100).

## v0.10.0 — 2026-10-02

### Upgrade notes

None. Only additions (checked by `api-compat` against v0.9.0). A sensor that
does nothing keeps behaving as before, except that its heartbeat now carries
`os` and `arch`. To let the platform dispatch by what the sensor really has,
give the `BaseSensor` a reporter:

```go
s := core.NewBaseSensor(cfg, apiClient)
s.SetCapabilityReporter(core.CapabilityReporterFunc(func(ctx context.Context) core.CapabilityReport {
	return core.CapabilityReport{
		Tools:             []core.ToolInfo{{Name: "semgrep", Version: "1.90.0", Installed: true}},
		Capabilities:      []string{"semgrep", "sast", "validate"},
		MaxConcurrentJobs: 5,
	}
}))
```

The reporter is called on every heartbeat: cache tool probes. A sensor that
sends its own heartbeats sets the same fields on `core.SensorStatus`.

### Added

- **Every heartbeat names the SDK and the sensor** (v1 and v2, no sensor
  code change needed): `"sdk": {"name": "openctem-sdk-go", "version": "<v>"}`
  and `"sensor": {"name", "version", "commit"?, "build_time"?}`. The SDK
  version comes from the binary's build info, so a release tag sets it
  (`useragent.SDKVersion`); the new `pkg/sdk` holds `sdk.Name` and
  `sdk.Version`, the fallback for a binary without build info (a build from
  a local checkout reports `<sdk.Version>-devel`; it was `devel`). A release
  PR bumps `sdk.Version`; a test fails when it is older than the newest
  release in this file. The sensor block comes from `BaseSensorConfig`
  (`Version` and the new optional `ProductName`, `Commit`, `BuildTime`
  (RFC 3339)); the name defaults to the product given to
  `useragent.SetProduct`, then to the executable's name. New:
  `core.SDKInfo`, `core.SensorBuild`, `core.CurrentSDKInfo`,
  `core.NewSensorBuild`, `useragent.ProductName`, `SensorStatus.SDK` /
  `.Sensor`, `client.HeartbeatRequest.SDK` / `.Sensor`,
  `conformance.FakePlatform.HeartbeatBuilds`.

- **Sensor-reported capabilities** (api RFC-029 §4.3.1). The heartbeat (v1 and
  v2) carries the sensor's tool inventory (`tools`: name, version,
  installed), the capabilities it serves (`capabilities`), its concurrency
  (`max_concurrent_jobs`) and its platform (`os`, `arch`). The platform
  dispatches by what the sensor reports, and its administrator can only
  narrow it. All members are optional: a platform that does not know them
  ignores them, and a sensor that reports nothing keeps the administrator's
  settings. `tools: []` (reported, nothing available) differs from no
  `tools` member (not reported).
- `core.ToolInfo`, `core.CapabilityReport`, `core.CapabilityReporter`,
  `core.CapabilityReporterFunc`, `core.StaticCapabilities`, `core.HostOS`,
  `core.HostArch`, `(*core.BaseSensor).SetCapabilityReporter`; the fields
  `Tools`, `Capabilities`, `MaxConcurrentJobs`, `OS`, `Arch` on
  `core.SensorStatus` and `client.HeartbeatRequest`.
- `pkg/conformance`: `FakePlatform.Heartbeats()` returns the heartbeat
  bodies received, and the suite checks the report on v1 and v2.
- **Scanner content versions** (api RFC-031). `core.ToolInfo.Content` lists
  the content a tool scans with (`core.ContentInfo`: name, version,
  `updated_at`, `fetched_at`, source, digest, managed, last refresh error):
  the trivy database, the nuclei templates, the semgrep rules. The platform
  shows it per sensor and reports stale content. The member is absent when
  a tool reports none.
  `ContentInfo.CheckedAt` is when the sensor last confirmed the content is
  still the newest (or pinned) version, and `ContentInfo.Stale(now, maxAge)`
  is the shared staleness rule: older than the limit **and** not confirmed
  current within it, so a template set whose newest release is weeks old is
  not reported stale while the sensor keeps checking.
- The `refresh_content` command (`core.CommandTypeRefreshContent`): its
  payload `core.RefreshContentRequest` (content names, force, and the
  tenant's `core.ContentPolicy`: refresh interval, and per content a maximum
  age, a pinned version, semgrep rulesets) is decoded and checked by
  `core.ParseRefreshContentRequest`. The policy never names a content
  source: registries, mirrors and local directories stay the sensor host's
  configuration. Content names: `core.ContentTrivyDB`,
  `core.ContentTrivyJavaDB`, `core.ContentNucleiTemplates`,
  `core.ContentSemgrepRules`.
- `nuclei.Scanner.DisableUpdateCheck` (`-disable-update-check`) and
  `nuclei.Scanner.DisableUnsignedTemplates` (`-disable-unsigned-templates`,
  not applied to a scan with platform-provided templates), for scans that
  run a managed template set; `nuclei.ValidateOptions.TemplatesDir` makes a
  re-verification look its template up in that set.
- **Load on the heartbeat** (api RFC-030 Phase 0). `core.LoadReporter`
  (implemented by `*core.CommandPoller`) and
  `(*core.BaseSensor).SetLoadReporter`: every heartbeat carries the
  commands the sensor holds now (`active_jobs`, sent also when 0, via
  `core.SensorStatus.ActiveJobsReported` / `client.HeartbeatRequest.ActiveJobsReported`)
  and, when the capability report does not set it, `max_concurrent_jobs`.
- `core.LimitedCommandClient` and `(*client.Client).GetCommandsLimit`; the
  constant `client.DefaultCommandPollLimit` (10, what `GetCommands` asks
  for).

- **Resource-aware slots** (api RFC-030). Package `resource`: `Prober`
  (CPU cores, CPU use, memory total/available, load1, disk free; cgroup v2
  and v1 aware: `cpu.max`/`cfs_quota_us`, cpuset, `memory.max`/
  `limit_in_bytes`, reclaimable page cache, throttling and OOM-kill
  counters), `CostBook` (per-tool CPU-seconds, peak memory and wall time
  per target learned from finished jobs, persisted to a JSON file),
  `ComputeSlots`, `AIMD`, `Manager`, `Capacity`, `HostResources`,
  `ToolEstimate`, `JobSample`. `(*core.CommandPoller).SetResourceManager`
  makes the poller's slots dynamic (at most the cap).
- **SDK-owned local queue** in `core.CommandPoller`: local order by class
  then priority, per-host politeness (`limits.per_host_concurrency`,
  default 1; `core.HostKey`), cancellation from the heartbeat
  (`cancel_command_ids`, `core.HeartbeatActionCancel`,
  `HeartbeatHints.CancelCommandIDs`, `(*CommandPoller).CancelCommands`),
  graceful drain (`CommandPollerConfig.DrainGrace`, default 30 s) that
  **releases** unstarted and aborted commands. `core.ReleasingCommandClient`,
  `(*client.Client).ReleaseCommand` (v2 `POST /commands/{id}/release`
  `{"reason"}`; fails the command with "released: <reason>" where the
  platform has no release), `protov2.ReleaseAction`, `protov2.ReleaseRequest`.
- **Heartbeat** (v1 and v2, all optional): `resources`
  `{cpu_cores, cpu_used_pct, mem_total_bytes, mem_available_bytes, load1,
  disk_free_bytes}`, `capacity` `{slots_total, slots_free, active_jobs,
  per_tool: {<tool>: {est_cpu_s, est_mem_bytes, throughput_targets_per_min}}}`,
  `queue` `{claimed, running, queued_local, oldest_age_seconds}`, and
  `running` (the held command ids, for leases). `core.StatusReporter`,
  `core.QueueStats`, `core.RecordProcessState`; the SDK exec helpers
  record their processes' CPU time and peak memory.
- `pkg/conformance`: the fake platform serves `release` and lists
  `Releases()`.

### Fixed

- **No more claimed-but-waiting commands, no duplicate scans** (api RFC-030
  B6). The `CommandPoller` takes a free slot *before* it claims a command,
  polls with `limit` = its free slots (with a client that implements
  `LimitedCommandClient`), does not poll at all while every slot is busy
  (a doorbell ring then waits for a slot), and polls again as soon as a
  slot frees when the platform may hold more. Before, it polled `limit=10`
  and acknowledged every command first, so with 5 slots busy it held up to
  10 acknowledged commands; the platform re-queued those after 10 minutes
  and another sensor ran them while this one still would.
- **A canceled or finished scan leaves no processes behind** (api RFC-030
  §5.4). The SDK's exec helpers (`ExecuteScanner`, `StreamScanner`,
  `BaseScanner`) run each scanner in its own process group: cancellation
  (drain, platform cancel, timeout) kills the whole group, not only the
  direct child, so a wrapper script's children die too; background
  children left by a finished scanner are reaped; on Linux a scanner is
  killed if the sensor dies. `core.ConfigureScannerProcess` and
  `core.ReapScannerProcess` do the same for executors that start
  processes themselves.
- **A command's slot is reused only after its result reached the
  platform.** With the outbox (the daemon default) `ReportCommandResult`
  returned once the result was on disk, so the poller freed the slot and
  polled while the platform still counted the command as held: the poll
  was refused (no free capacity) or, before the platform knew the
  sensor's capacity, one command too many was handed out. It now waits
  for the delivery (up to `OutboxConfig.SyncWait`; not while the platform
  is unreachable).
- **A refused start is not executed.** When the platform does not accept a
  command's `start` (409: re-queued, reassigned or canceled; or any other
  error) the poller releases the slot and does not run it. Before, a
  failed start was only logged and the scan ran anyway.

## v0.9.0 — 2026-10-02

### Upgrade notes

None. No exported identifier was removed, renamed or changed signature
(checked by the new `api-compat` CI job against v0.8.1). Bump the module
version: a sensor gets protocol v2 for everything the platform offers with no
code change.

### Changed

- **Protocol v2 for the whole sensor surface** (api RFC-029). The client asks
  the platform once (`GET /api/v2/sensor/hello`, cached for an hour) and uses
  protocol v2 for every feature it lists, protocol v1 for the rest:
  heartbeat (`POST /api/v2/sensor/heartbeat`), command poll and transitions
  (`GET /api/v2/sensor/commands`, `POST …/commands/{id}/claim|start|complete|fail`),
  suppressions (`GET /api/v2/sensor/suppressions`, revalidated with its
  ETag), fingerprint queries (`POST /api/v2/sensor/fingerprints/check` and
  `/baseline-diff`, split at the platform's limit) and key renewal
  (`platform.PlatformClient.RenewKey`: `POST /api/v2/sensor/keys`, v1 only when
  the platform does not serve it). Results keep using v2 as since v0.8.0.
  Against api v0.8 (results only on v2) the other calls stay on v1; against an
  older platform everything is v1, as before.
- **No `X-Agent-ID` on protocol v2.** The platform identifies a sensor by its
  key; the header is still sent on v1 requests, byte for byte as before.
- Command transitions on v2 are idempotent: a completion whose answer was
  lost is retried and answered `200` (v1 answered `400`). A command that
  another sensor claimed, or that was canceled, expired or already finished,
  is reported as such: `client.IsCommandGone(err)`.
- A disabled sensor's v2 heartbeat is answered `200` with the `pause` action.
  `SendHeartbeatWithHints` returns it; `SendHeartbeat` and `TestConnection`
  (which do not act on hints) return a 401-classified error, as v1 did.
- `SENSOR_PROTOCOL` / `Config.Protocol` keep their meaning: `v1` never
  touches `/api/v2` and is byte-identical to v0.7; `v2` requires v2 for
  results (other features use v2 when offered); `auto` is the default.
- A v1 answer carrying `Deprecation` (api v0.9 deprecates v1) logs one
  warning per process.
- `pkg/retry`'s removal moves to v0.10.0, so this release removes nothing.

### Added

- `client.Client.ProtocolFeatures()`: the features negotiated on v2.
- `client.IsCommandGone(err)`.
- `platform.RenewError` (the refused-renewal error; its message is unchanged).
- `pkg/sensorproto/v2`: the control-plane vocabulary (paths, features, the
  RFC-029 problem types under `https://openctem.io/problems/sensor/`, request
  and response types, `Hello.Supports`, `Hello.Deprecations`,
  `Problem.State`, the control-plane limits).
- `pkg/conformance`: the fake platform serves the RFC-029 control plane
  (`Control`, `SetControl`, `QueueCommand`, `SetPaused`, `CommandResult`), and
  the suite proves a sensor speaks only `/api/v2/sensor/*` without
  `X-Agent-ID` on a full v2 platform, falls back per feature on api v0.8 and
  on older platforms, and replays lost transitions.
- CI: `api-compat` (apidiff against the latest release; incompatible changes
  need the `breaking-change` label and upgrade notes) and `sensor-compat`
  (`openctemio/sensor` `main` builds and vets against the change).

### Fixed

- **Sensors report their version and hostname.** `HeartbeatRequest` declared
  `version` and `hostname` but the client never set them, so the platform
  showed "No host info" for every sensor. `core.SensorStatus` now carries
  `Version` and `Hostname` (filled by `NewBaseSensor` from the config and
  `os.Hostname()`), and every heartbeat sends them.

### Added

- `outbox.Inspect(dir, keyFile)` reads an outbox directory without taking its
  lock or changing anything (pending count, bytes, oldest age, dead letters
  with their reasons), so an operator can look at the outbox of a running
  sensor. `Open` refuses a locked directory, so the sensor's
  `-outbox-status` could not run next to its daemon.

### Fixed

- **`PushFindings` no longer stalls while the platform is unreachable.** With
  an outbox it waited up to `SyncWait` (30 s) for a delivery even when the
  circuit was open or delivery was paused on a rejected key, so a daemon's
  scheduled scans took 30 s per report during an outage. It now answers
  `Queued` at once in those states.
- A daemon's scheduled scan logged "Pushed N findings (0 created, 0
  updated)" for results it had only queued; it now says they were queued in
  the outbox, with the report id.

## v0.8.0 — 2026-10-01

### Changed (breaking)

- **Betterleaks replaces gitleaks as the secret scanner.**
  [Betterleaks](https://github.com/betterleaks/betterleaks) is the successor
  to gitleaks, maintained by gitleaks' original author (MIT). Its v1 line
  keeps the gitleaks CLI flags, config format (`.gitleaks.toml` still loads)
  and JSON report, and adds BPE-token filtering, rule filters and
  validation in Expr, recursive decoding and archive scanning (on by default,
  depth 8).
  - `pkg/scanners/gitleaks` is now `pkg/scanners/betterleaks` and
    `pkg/adapters/gitleaks` is `pkg/adapters/betterleaks`.
    `scanners.Gitleaks`, `GitleaksWithConfig`, `GitleaksOptions` and
    `GitleaksScanner` are now `Betterleaks`, `BetterleaksWithConfig`,
    `BetterleaksOptions` and `BetterleaksScanner`. The scanner runs the
    `betterleaks` binary and reports `tool.name = "betterleaks"`.
  - Use betterleaks **v1.x** (tested with 1.9.0). v2 (release candidate)
    wraps the report in an envelope and drops SARIF and the `GITLEAKS_*`
    variables; the parser refuses it with `betterleaks.ErrV2Report` instead
    of reporting zero findings.
  - Fingerprints do not change: betterleaks v1 builds the native fingerprint
    (`file:rule:line`) exactly as gitleaks did, and the parser masks the
    secret the same way, so a secret both tools report is the same finding.
    Rule sets differ: for example betterleaks reports an AWS access key ID
    only together with its secret key (`aws-access-token` with an
    `aws-secret-access-key` component), where gitleaks reported the secret
    key alone as `generic-api-key`.
  - `core.CanonicalScannerName` is the SDK's single mapping of retired
    scanner names (`gitleaks` -> `betterleaks`). The command executor, the
    custom-template validator and the template cache use it, so a platform
    that still dispatches `gitleaks` scans or templates runs them on
    betterleaks.
  - The `gitleaks` SARIF preset is now `betterleaks` (`dir <target>`; the
    deprecated `detect --source` form is gone). `BETTERLEAKS_*` is added to
    the scanner environment allowlist (`GITLEAKS_*` stays: betterleaks v1
    still reads `GITLEAKS_CONFIG`).
- **The durable outbox replaces `pkg/retry` and the SQLite chunk store.**
  `retry.FileRetryQueue`, `retry.RetryWorker` and the `retry.RetryQueue`
  interface are removed; `pkg/retry` keeps only the types the deprecated
  client wrappers return and is deprecated (removal planned for v0.9.0).
  `chunk.Storage` (SQLite) is removed, and with it the `modernc.org/sqlite`
  dependency tree: `chunk.Manager` keeps its API but stores chunks in an
  outbox (`Config.OutboxDir`, default `chunk-outbox` next to the old
  `DatabasePath`; a leftover `chunks.db` is reported, not read).
  The client's retry-queue methods (`EnableRetryQueue`, `StartRetryWorker`,
  `ProcessRetryQueueNow`, `GetRetryQueueStats`, ...) and
  `Config.EnableRetryQueue` still work as deprecated wrappers around the
  outbox; reports a pre-outbox SDK left in its retry-queue directory are
  imported on first start.
- **Results use protocol v2 when the platform offers it** (`Config.Protocol`,
  default `auto`). Against a v2 platform `PushFindings`/`PushAssets` send
  `PUT /api/v2/sensor/results/{report_id}`; v2 requires `report.tool.name`
  (`client.ErrV2NoTool`) and rejects findings without an asset in the same
  document. `Protocol: "v1"` keeps every request byte-identical to v0.7.x.
- `core.PushResult` gains `Queued` and `ReportID`; with an outbox,
  `PushFindings` returns `Queued: true` instead of an error when the platform
  cannot be reached, and a `*client.RefusedError` when it refused the report.

### Fixed

- **The retry queue was never on.** `client.New` ignored
  `Config.EnableRetryQueue`, so the sensor's `-retry-queue` flag and
  `RETRY_QUEUE=true` created nothing and `StartRetryWorker` failed with
  "retry queue not enabled" (logged only as a warning). And when it was on
  (`EnableRetryQueue` called directly), a report was queued only AFTER a
  failed push, without fsync, with a count cap: a crash during the push lost
  it. `Config.EnableRetryQueue` now enables the outbox, which writes every
  result before the first send.
- **A command was reported complete before its results arrived.** The
  executor's push failed or was queued and the command was completed anyway.
  With the outbox, the command result waits behind its results and becomes
  "failed" when the platform refused them.

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
  regenerate a key under Settings → Sensors, set `API_KEY`, restart). A 401
  "API key required" although a key was sent says instead that the key never
  reached the API: `API_URL` points at the web UI or at a proxy that strips
  `Authorization` (`core.AuthFailureAdvice`). Network
  failures are logged at 1, 2, 4, 8, ... consecutive attempts, and recovery
  is logged too.
- **One heartbeat at daemon start, not two.** `BaseSensor.FirstHeartbeat`
  sends the first heartbeat (through the doorbell and the `AuthGate`) before
  `Start`, which then waits the advised interval instead of sending another.
  A daemon uses it as its connection check in place of
  `Pusher.TestConnection` (a plain heartbeat followed at once by the loop's
  first one).
- **The plain-http warning is printed once per process per base URL**,
  shared by `pkg/client` and `pkg/platform` (`httpsec.FirstWarning`).
- **The security gate gets the platform's suppression rules.**
  `client.GetSuppressions` called the user route `/api/v1/suppressions/active`
  with the sensor key; the API always refused it (401) and the SDK swallowed
  the error, so the gate counted findings the platform had suppressed. It now
  calls the sensor route `GET /api/v1/agent/suppressions` (an additive
  protocol-v1 route, `legacyv1.PathSuppressions`; needs an API that serves it)
  and falls back once to the old route on a 404. A failure is now returned
  instead of an empty rule list, so callers can tell the operator that the
  gate ran without suppressions.
- **Secret values no longer reach the sensor log.** In verbose mode the
  scanner passed `--verbose` to the tool, which prints every finding with its
  raw secret to stdout, and a verbose sensor logged it. The tool now always
  runs without it (`--redact` is not an option: it also redacts the report,
  which would change fingerprints).
- **Secret scans with exclusions no longer fail.** The scanner passed
  `--exclude-path` and `--no-git`, which no `dir` command (gitleaks or
  betterleaks) accepts, so any scan with `Exclude` set failed with
  `unknown flag`. Exclusions are now applied to the report (path globs, base
  names and directory prefixes; an archive member matches its archive).
- **The repository's own secret scan had no rules.** `.gitleaks.toml` set
  only an allowlist and no `[extend] useDefault = true`, so it loaded zero
  rules and always passed. It is now `.betterleaks.toml` with the default
  rules, and the Security workflow runs betterleaks over the git history on
  every pull request and push and uploads SARIF to code scanning (the old
  gitleaks-action job was opt-in behind a licence and never ran).

- **Scanners no longer write their report into the scanned tree.** gitleaks,
  semgrep and CodeQL joined their default (relative) report file, and CodeQL
  its database, onto the target directory. A read-only target (a `:ro`
  volume, the usual Kubernetes and compose mount) failed with
  `Report path is not writable` / `failed to read gitleaks output`; two scans
  of one tree could overwrite each other's report; and an interrupted scan
  left the file in the user's repository. A relative `OutputFile` (the
  default) is now written, under its base name, into a private temporary
  directory that is removed after the scan; so is a CodeQL database built
  for the run. An absolute `OutputFile` or `DatabasePath` is used as before.
- **The vuls adapter's output is deterministic.** It ranged over the
  packages map, so the same input produced its dependencies in a different
  order on every run; they are now in package-name order.

### Added

- **Durable outbox (`pkg/outbox`, `Client.EnableOutbox`).** Every report
  and command result is written to disk before the first send and deleted
  only after the platform acknowledged it, so a crash, `kill -9` or restart
  loses nothing. One file per item, written crash-safely (temporary file,
  fsync, rename, directory fsync), 0600 in a 0700 directory, an exclusive
  `flock`, sealed with AES-256-GCM under a 0600 key file created on first
  use; a torn or corrupted file is quarantined in `corrupt/`. A byte cap
  (default 1 GiB, at most half of the usable space) and an age cap (default
  7 days) evict the oldest entries first, with a log line, a metric and the
  heartbeat's `evicted_count`. Network errors, 5xx and 429/503 back off with
  jitter behind a circuit breaker (honouring `Retry-After`); 401 pauses
  delivery until a heartbeat is accepted or `SetAPIKey` is called; 400, 409,
  413, 415, 422 go to `dead/` with the problem document. Delivery is oldest
  first, one or two at a time, and drains at once when a heartbeat is
  accepted. `outbox.NewCollector` exposes the state as Prometheus metrics;
  the heartbeat carries `outbox: {pending_count, pending_bytes,
  oldest_age_seconds, dead_letter_count, evicted_count}` (api#651 stores
  and shows it).
- **Protocol v2 results client (RFC-026 WP-S1).** `pkg/sensorproto/v2`
  (wire vocabulary), `Client.PushResultsV2` (stable UUIDv7 `report_id`,
  zstd, RFC 9530 `Content-Digest`, RFC 9457 problems, the §3.8 retry table,
  segments sized from `GET /api/v2/sensor/hello` plus a commit, resumable
  through `V2Progress`), `Client.Hello`, `Client.GetReportStatus`,
  `Client.AbandonReport`, `Client.ResultsProtocol`, `client.WithProtocol`.
  `chunk.SplitSegments` makes every segment a complete CTIS document (tool,
  metadata and the assets its findings reference); `chunk.BindFindingAssets`
  binds findings to a report's only asset before splitting. Discovery: the
  heartbeat announces `results-v2` and reads `X-OpenCTEM-Protocol: 2`.
- **Conformance suite (`pkg/conformance`, RFC-026 WP-S3).** `FakePlatform`
  implements the v2 contract strictly and records requests; the SDK's tests
  check headers and digest, that only 429/5xx/network are retried (with the
  same `report_id`), 413 splits, a partially accepted report is never
  resent, a lost answer is replayed as a no-op, and the outbox scenarios
  (platform down, restart, poison item, 401, command ordering). The live
  half runs the contract against a real API:
  `OPENCTEM_CONFORMANCE_URL=… OPENCTEM_CONFORMANCE_KEY=… go test ./pkg/conformance -run Live`.
- `core.AuthGate`, `core.AuthFailureStatus`, `core.APIKeyHint`,
  `core.APIKeyHinter`, `core.AuthFailureAdvice`, `BaseSensor.AuthGate`/`SetAuthGate`/`FirstHeartbeat`,
  `CommandPoller.SetAuthGate`, `client.HTTPError.HTTPStatusCode`,
  `client.Client.APIKeyHint`, `httpsec.FirstWarning`.
- **A User-Agent that says who is calling.** Every SDK request to the
  platform (`pkg/client`, and `pkg/platform` lease, poll, job, bootstrap and
  key renewal, which used to send Go's default) and the collectors' requests
  now carry `[<product>/<version> ]openctem-sdk-go/<sdk version>` instead of
  the fixed `sdk/1.0`. The SDK version comes from the binary's build info.
  The embedding binary names itself with `useragent.SetProduct(name,
  version)` (process-wide) or, per client, `client.Config.UserAgent` /
  `client.WithUserAgent`, for example
  `openctemio-sensor/0.3.1 openctem-sdk-go/0.7.4`. Product tokens are
  sanitized (HTTP token characters only, bounded length). Operators can now
  tell old agents from new sensors in proxy and API logs.
- **`ctis.CheckFindingAssets(r *ctis.Report) error`**, the protocol v2
  ingest rule as a client-side check (RFC-026 WP-S2): a finding resolves when
  its `asset_ref` names an asset `id` of the same report, or when it has no
  `asset_ref` and the report has exactly one asset; the asset must have a
  value. It returns a `*ctis.FindingAssetError` (count, total and the first
  five finding indices, never finding content) that matches
  `ctis.ErrNoAssetForFindings` with `errors.Is`. `ctis.SARIFRun` reads
  `versionControlProvenance`.

### Changed

- **Every converter files every finding on an asset of its own report**
  (RFC-026 WP-S2; protocol v2 rejects any other finding as
  `asset_unresolved`, with no fallback asset). Each finding now carries an
  explicit `asset_ref`:
  - SARIF (`adapters/sarif`, `ctis.FromSARIF`, `core.SARIFParser`,
    `scanners/codeql`), semgrep, betterleaks (adapters and scanner parsers):
    the repository from the options (`AssetValue`/`AssetType`,
    `BranchInfo.RepositoryURL`, `AdapterOptions.Repository`), else the
    SARIF log's `versionControlProvenance`, else the repository of the CI
    job (`pkg/gitenv`: GitHub Actions, GitLab CI). With none of these, a
    report with findings is an error matching `ctis.ErrNoAssetForFindings`.
    The adapters used to emit findings with no asset at all, and the scanner
    parsers did so whenever the caller passed no repository.
  - trivy: the options, else the image of an image scan or the remote
    repository of a repository scan, else CI, else the same error. The local
    path of a filesystem scan (`.`, `/scan`) is no longer turned into a
    repository asset, and the scanner parser's findings now reference the
    artifact asset it emits (they pointed at `asset-1`, which did not exist).
  - nuclei: one domain/IP asset per matched host (the adapter set only
    `asset_value`, which v1 ingest turned into a repository named after the
    URL); the scanner parser no longer emits a value-less asset for a result
    without a host, uses the scan target the caller passed, and
    `ReportParser.Parse` / `ParseToCTIS` fail when a finding still has no
    asset.
  - vuls and tenable: a scanned host with findings but no name or address
    is an error instead of a value-less asset.
  - `core.JSONParser` links findings to the asset it creates from
    `AssetValue` even when `AssetID` is empty.

  Callers that converted code-scan output without naming the repository
  (outside CI) now get the error: pass the scanned repository.

## v0.7.3 — 2026-10-01

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
([RFC-023 §9.5](https://github.com/openctemio/openctem/blob/main/api/docs/rfcs/RFC-023-scan-zones-and-scanners.md)).
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
