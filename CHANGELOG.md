# Changelog

All notable changes to `github.com/openctemio/sdk-go`.

Unreleased changes are kept one file per change in
[`changelog.d/`](changelog.d/README.md) and folded in here by the release
(Release Prepare).

## Unreleased

## v0.44.0 — 2026-10-31

### Added: `targets.allow: ["*"]` in local policy schema v2

- A single `"*"` entry (schema v2 and later) means every target the platform signs, still inside the built-in deny list, `targets.deny` and the private-range rules. Mixed with other entries it is refused; schema v1 stays frozen and refuses it. The reported policy summary gains `mode` (`allow_all`, `allow_list`, `platform_scope`) and `policy validate` says "everything the platform signs".

### Added: SENSOR_CA_SHA256 makes a sensor trust a private platform CA by itself

- With `SENSOR_CA_SHA256=<root sha256>` (comma separated for rotation) a sensor whose platform certificate comes from a private CA fetches the platform's public CA bundle and trusts only a certificate that matches the pin and signs the chain the server presents; it keeps it in its state directory. Without a pin nothing is trusted automatically. `SENSOR_CA_CERT_FILE` still works for air-gapped hosts.

### Changed: clearer untrusted-certificate errors

- The error lists every certificate the platform presented (name and SHA-256) and names the root authority the top one needs (the platform does not send it). A `SENSOR_CA_CERT_FILE` that cannot be read or is not PEM is refused with its path, and one that holds only an intermediate is called out.

## v0.43.0 — 2026-10-31

### Behaviour change: the sensor-local policy is optional and narrow-only

- With no local policy file a sensor follows the platform's signed scope: it runs any job whose scope statement the platform signed (signature verification, the built-in deny list and the kill switch are unchanged). A local policy written by the host owner narrows that scope (intersection), never widens it; an explicit `targets: {allow: []}` still allows nothing. The platform never writes the file.
- Pairing no longer writes `require_local_policy: true` into the identity. The stored field of existing identity files is still decoded but ignored. `SENSOR_REQUIRE_LOCAL_POLICY=true` is the only way to fail closed without a file (rule `no_local_policy`); unset or `false` follows the platform's scope.
- The start log, `Describe()`, the doctor setting and the `policy.local` check no longer present a missing policy as something to fix. The report keeps its shape (`absent` with `required: false`, `absent` with `required: true`, `enforced` with `targets_allow` -1 for no allow list and 0 for an explicit empty list).
- Upgrade: sensors paired by the earlier fail-closed releases that have no policy file now follow the platform's signed scope. Set `SENSOR_REQUIRE_LOCAL_POLICY=true` to keep fail closed.
- Threat model: without a local policy a compromised platform could sign a wide scope. Host owners who do not trust the platform install a narrowing policy or set `SENSOR_REQUIRE_LOCAL_POLICY=true`.

### Added: the sensor prints the link to approve it on

- When the platform sends it (`verification_uri_complete`), `identity.Pair` prints `Pair this sensor: open <console>/activate?code=XXXX-XXXX` with the code and the fingerprint, whether the sensor started with a code or without one. A started-with-code sensor shows the same code the console's command carried. The link is printed only when it is an absolute http(s) URL of printable characters (no terminal control sequence from the platform reaches the operator's screen), and a resumed request prints it again.
- The output asks the operator to pick this fingerprint in the console (the console now offers three and the platform checks the pick).

### Changed: ctis v1.6.6 (more edge protection signatures)

- Sensors recognise block and challenge pages of three more bot-management and WAF edges, including challenges answered with status 200, so a scan they stop is reported as a coverage gap with the edge and its vendor, never as no findings. Weak signs count only on a small page.

### Fixed: an untrusted platform certificate is explained once instead of retried silently

- A TLS chain signed by an authority the host does not trust (a private CA, or TLS interception) stops the retry loop with one sentence naming the presented authority's SHA-256 fingerprint and the fix (the console's command installs the CA, or `SENSOR_CA_CERT_FILE`), then waits like any other refusal (`UntrustedTLSError`).
- A refused request now says it may have been closed by a wrong fingerprint pick, and the spent-code message points to the new link instead of console menu names.

## v0.42.2 — 2026-10-31

### Changed: pairing retries use full jitter and no longer exit on an unknown 4xx

- Every pairing backoff is a random delay between half of the base and the base (5 seconds doubling to 5 minutes); `Retry-After` (1 to 300 seconds, plus jitter) is honoured on any answer, including the new `pairing-key-busy` problem. Retried: network errors, HTTP 408, 425, 429, 500, 502, 503, 504, clock skew.
- Any other HTTP answer in daemon mode is no longer an exit into a supervisor restart loop: the problem's title and detail are printed once and the sensor tries again no sooner than 5 minutes later. `pair` still exits, now printing the title and detail (the raw answer when it is not a problem document).
- `sensorproto/v2` names the problem types `pairing-not-found`, `pairing-key-registered` and `pairing-key-busy`.

### Fixed: pairing resumes after a restart and a re-pair no longer destroys the working identity

- The pairing request in flight is kept in `identity/pairing.json` (0600). After a restart the sensor polls it first: an approved request is confirmed (no new request, no ghost registration), a pending one shows the fingerprint again, and an expired, refused or unknown one is replaced by a new request.
- `Store.RotateKey` (`pair -repair`) now stages the new key in `signing.key.next`; `signing.key` and `identity.json` are replaced together only after the platform confirmed (`Store.SaveAndPromote`). An interrupted, refused or expired re-pair leaves the working identity untouched, and a later re-pair reuses the staged key. `Store.Load` finishes a promotion that crashed half-way. `Store.Check` covers the two new files.
- A pairing code is single use: the sensor never resends the code of a request that expired or was refused. The daemon continues with a request without a code and prints why; `pair` exits with the same explanation.
- A key the platform reports as already registered (`pairing-key-registered`) with no confirmed identity on this host is replaced once. With an identity the sensor stops (the daemon waits) and asks for a restore or an administrator's Re-pair.

### Documentation: SENSOR_PAIRING_CODE names the console action "Create a pairing code first"

- The settings registry description (shown in the console's Setup & health section and in docs/SETTINGS.md), the README and code comments said the code comes from "expect a sensor", a console action that is now called "Create a pairing code first" under Sensors > Add sensor. Text only.

## v0.42.1 — 2026-10-31

### Fixed: pairing explains a key the platform registered before

- A pairing start the platform refuses with `pairing-key-registered` (the key
  was approved once; a key pairs only once) returns `identity.ErrKeyRegistered`
  at once, with the identity directory and the fix in the message, instead of
  a raw `HTTP 409`. A `pairing-key-busy` answer (another open request holds the
  key) is retried with backoff like other transient refusals.
- New problem types `protov2.ProblemPairingKeyRegistered` and
  `protov2.ProblemPairingKeyBusy`.

## v0.42.0 — 2026-10-31

### Added: web content captures on a live host

- `core.LiveHost.WebContent` (`core.WebCapture`) carries the result of a web content fetch (capability `monitor.web_content`): URL, final URL, status, content type, size, SHA-256 and a capped text body. It is passed through to `ctis.LiveHostInput.WebContent`, which bounds it again. Absent unless a probe fills it, so existing reports do not change.
- Re-pinned `github.com/openctemio/ctis` for `monitor.web_content@1` and `WebCaptureInput`; the `pkg/ctis` aliases are regenerated.

### Documentation: a quickstart for writing a tool, with a runnable example

- `docs/tool-quickstart.md` walks a third-party author from install to a tenant approving the tool: manifest, the two-method contract and builder, local runs, the conformance harness and `FakePlatform`, results, egress and scope, packaging and compatibility.
- `examples/hello-tool` is the tool the page builds. Its test runs it in-process, through `conformance.RunToolSuite` on the built program, and into a `FakePlatform`, so the quickstart cannot drift from the SDK.

## v0.41.0 — 2026-10-31

### Security: ports.allow now applies to a capability job's standard params

- A job's standard `params` become the tool's config at run time, but the local policy checked only `config` and `scanner_config`, so a sensor with `ports.allow` still ran a job that sent `params.ports` outside the list, or `params.top_n` / `params.top_ports` (the tool picks the ports). The policy now refuses both: a port-list param (by the capability's catalog type, or named `ports`) must lie inside `ports.allow`, and a top-N param is refused while `ports.allow` is set, as it already is in `config`. A null value is no request; without `ports.allow` nothing changes.

### Security: a top-N port job no longer bypasses the local policy's ports.allow

- With `ports.allow` set, a scan job whose settings ask the tool for its own port list (`top_ports`, `top_n`, in `config` or `scanner_config`) is refused with rule `ports.allow`: the sdk cannot prove the tool's list lies inside the allow-list. Before, only the `ports` setting was checked, so the platform's default top-1000 port set ran outside the allow-list. Name the ports in the job's `ports` setting, or leave `ports.allow` unset for a sensor that may scan any port. Jobs on a sensor without `ports.allow` are unchanged. `ports` values `full`/`top-N` were already refused; `scanner_config` is now checked as well.

### Behaviour change: a scan that finds nothing still pushes a report

- A scan command whose scanner produced no output now pushes one empty report bound to the command (tool name and version, no assets, no findings), instead of pushing nothing. The report's `coverage_type` follows the same rules as a report with findings: `full` only when every target was covered, `partial` when the run stopped, a host was a coverage gap or a target was unreached. Which targets were covered is in the command result's `target_outcomes`. Without this report the platform could not tell "looked and found nothing" from "never looked", so findings the scan no longer saw stayed open. The report travels through the same authenticated, command-bound push as any other; a platform that does not use it ignores it (no asset is created).

### Behaviour change: a scan job whose every target does not resolve completes per target

- At the sensor-local policy's admission, a scan job whose every refused target is a name that does not resolve now completes without running, with each name in `metadata.refused_targets` (reason `unresolvable`, `dns` `name_gone` or `resolver_failed`) and one outcome per name, instead of failing as a whole. The platform can then settle each name on its own. No tool sees any of the names; a job with any other refusal still fails.

### Added: lookup-only DNS jobs report a name without an answer instead of refusing it

- A job naming the lookup-only capability `resolve.dns` checks a name that does not resolve against the domain deny list and, with `targets.allow` set, the allowed domains only, and reports it per target as `unresolvable`; a name outside the allowed domains is refused as `denied_by_policy`. Every capability that connects to its targets keeps refusing a name whose addresses cannot be checked. See `docs/SECURITY.md`.

### Added: commit manifest and resume from held segments

- `PushResultsV2` sends the commit manifest of a segmented report to a platform that lists `results_manifest` on hello: each segment's SHA-256 over its bytes before Content-Encoding, its size and its asset and finding counts, the totals and the report hash (`protov2.ReportRoot`: SHA-256 over the segment hashes in order). The platform compares every value with what it received; a report it cannot verify is not used to close findings by absence. Older platforms get the plain commit.
- A push resumed from `V2Progress` (the outbox's next delivery after a restart) asks the platform which segments of the report it already holds (`segments.held` on the status) and does not send those again.
- `protov2`: `CommitRequest.Segments/Totals/ReportSHA256`, `SegmentManifest`, `Status.HeldSegments`, `Status.Integrity`, `FeatureResultsManifest`, `ReportRoot`. The conformance fake verifies the manifest when `SetResultsManifest(true)`.

## v0.40.0 — 2026-10-28

### Added: an eval harness for AI playbooks, and `openctem playbook init|test`

- `pkg/harness/eval` runs a playbook over a golden set and scores it: agreement with the expected answers, precision of risk-lowering verdicts (a wrong false positive hides a real issue), and injection cases, which pass only when no risk-lowering output comes out and no tool outside the grant ran. Offline runs replay recorded model turns and tool outputs, so they are deterministic and need no network. A live provider can answer instead, while tools still return the recorded outputs, so an eval never reaches a target.
- `openctem playbook init [--kind triage.v1] <dir>` scaffolds a playbook and one golden case. `openctem playbook test [dir]` validates the playbook and runs its golden set with the default gate: injection cases all pass, agreement at least 0.9, risk-lowering precision 1. It exits 1 when the gate fails, so it works as a CI step.
- `examples/playbooks/web-vuln-triage/golden` holds four cases: confirmed, false positive, unreachable host, and instructions planted in evidence.

### Added: the analyst harness core (`pkg/analyst`)

- `pkg/analyst` is the loop an analyst worker runs for one `openctem.analyze/v1` job: a provider interface (one adapter per model API), a tool registry that offers only the tools the signed grant and the playbook allow, a grant policy that checks every tool call before it runs (granted tool, input schema, target placeholders bound in the grant, tier ceiling; intrusive tools always need a person), pre and post tool hooks that can only deny or redact, budgets on steps, tool calls, tokens, wall time and cost with one final answer after a budget stop, parallel tool calls with a limit, untrusted text fenced with a per-run nonce, a closed output schema with evidence that must resolve and one repair turn, and an append-only run record whose digest binds the result. A `Replay` provider replays a recorded run deterministically and plays scripted models in tests.
- `pkg/analyst/contract` carries byte-identical, digest-pinned copies of the platform's `openctem.analyze/v1` JSON Schemas and validates jobs, results and model output against them.
- `pkg/analyst/playbook` is the playbook format `openctem.io/playbook/v1` (versioned YAML: kind, output schema, model tier, tools that narrow the grant, steps, required evidence, rules, budgets), with strict loading and a digest; `examples/playbooks/web-vuln-triage` is a sample.
- New dependency: `github.com/santhosh-tekuri/jsonschema/v6` (Apache-2.0), the validator the platform already uses for the same schemas.

### Added: provider state and a fallback signal in `pkg/harness`

- `Message.ProviderState` is an opaque, provider-owned field (thinking blocks, signatures) that the harness copies into the run record and a resume (`Run.Resume`). The harness stamps it with the producing provider's name (`Message.StateProvider`), sends it only to that provider and drops it when the provider changes, for example after a fallback. It is capped per message (`Run.MaxProviderStateBytes`, default 64 KiB); state over the cap or not valid JSON is dropped. It is part of the request and record digests, and a replay stays deterministic because it returns the recorded state.
- `Result.FallbackEligible` is true when an answer failed schema or evidence validation and the one repair turn on the same provider and model failed too. A model refusal, a verifier refusal marked `VerifyError.Policy`, a provider error, a budget stop and the deadline never set it. The provider layer reacts by running the job again on the next chain target.

### Added: host pressure governs tool launches; a starved start is retried instead of reported as a crash

- The SDK reads Linux pressure stall information (CPU, memory, I/O), CPU quota throttling, load per CPU, available memory and open descriptors, and rates the host `ok`, `elevated` or `overloaded` with hysteresis. Elevated halves the job slots; overloaded leaves no free slot while a job runs. Tool launches wait while the host is overloaded (one tool always runs). The heartbeat reports `resources.pressure` (level, reasons, readings, `noisy_neighbor`) and `capacity.launches_held`, `tools_running` and `transient` counters. All new fields are optional for the platform.
- The start handshake timeout grows with the measured stall (30 s up to 120 s). A tool that is alive but got almost no CPU is a slow start, not a crash. One automatic retry for transient start failures (slow start; no handshake or an OOM kill under host pressure; a refused fork); never for policy refusals, protocol or manifest mismatches, a tool's own memory limit, or after results. The outcome carries `Attempts` and `Transient`.
- A start that fails again under pressure is reported as `infra.resource.host_pressure` with `attempts` and `pressure` in the evidence, only to a platform that lists the new `host_pressure` feature; older platforms receive `infra.tool_crashed` as before.
- Tool contract: `resources.profile` (`light`, `standard`, `heavy`) sizes each task's envelope; `resources.cpu` and `resources.memory` now apply. Where the sensor's cgroup v2 is delegated and holds the sensor alone, each task runs in a cgroup of its own (`cpu.max`, `cpu.weight`, `memory.max`, `pids.max`, created with `CLONE_INTO_CGROUP`); elsewhere rlimits. `SENSOR_TOOL_CGROUPS=off` turns cgroups off. The sandbox status reports `envelope`.
- With one free slot, a command of a type the sensor does not run at the head of the queue no longer hides the sensor's own work: the next poll asks for more.
- New `scripts/fault-injection.sh` runs CPU-hog, memory-pressure and cgroup-envelope tests in throwaway containers. See `docs/resource-governance.md`.

### Added: `openctem tool build` makes the pack image; CI templates publish and sign it

- `openctem tool build <pack> (--output <oci-dir> | --push <repo[:tag]>)` builds a multi-platform OCI image of a tool pack without a container daemon: the base image pinned by digest plus one reproducible layer holding the pack at `/opt/openctem/pack`, per-architecture files from `.build/<os>-<arch>/`, no entrypoint, user 65532, no timestamps, and the labels `io.openctem.pack.{name,version,publisher,tier,digest}`. The same pack and base give the same digest; the command prints it.
- Symbolic links and special files are never packed (the build fails), nor are `.git`, `.build` and `__pycache__`; a pack that does not validate is not built.
- The GitHub and GitLab CI templates gain a publish job: on a tag equal to the pack version, build, push and sign the image digest keylessly with cosign.

### Added: tool packs (pack.yaml) and pack support in `openctem tool`

- `pkg/tool/pack` reads `pack.yaml` (`openctem.io/pack/v1`, JSON Schema `pkg/tool/schema/pack.v1.schema.json`): the unit in which tools are versioned, built, signed and delivered. It lists the pack's tools, the third-party engines they bundle (version, license, a sha256 per platform), the platforms, the SDK and protocol the pack needs, and the base image of a pack image (pinned by digest).
- The pack's tier is checked, not trusted: it must equal the highest minimum tier of its tools (declared tier, capability tier floors, side effects), so a pack cannot label an active tool passive. Unlisted tools, unlisted engines, tool paths that leave the pack or pass through a symbolic link, and an SDK requirement below a tool's `sdk.min` are refused.
- `openctem tool validate|test|describe` work on a pack directory (every tool it lists); `openctem tool init` writes a one-tool `pack.yaml` next to the new tool.
- `examples/packs/http-title`: a Python pack for `probe.http@1`, tested in CI with the capability suite and the scope check.
- Spec: `docs/tool-packs.md`.

### Changed: `pkg/analyst` is now `pkg/harness`

- The AI runtime package is renamed to `pkg/harness` (with `pkg/harness/contract` and `pkg/harness/playbook`), because later AI roles (remediation, reports, hunting) run on the same loop. The package is Experimental, so there is no alias: change the import path.

### Changed: a scan whose every target does not resolve completes with each target skipped

- When every target of a scan job is a name that does not resolve, the command now completes (partial) with the refused-target list (reason `unresolvable`, `refused_targets_total`) instead of failing with "invalid scan target: N of N targets refused". Mixed refusals (a denied or invalid target among them) still fail. The platform already handles the old failed form, so sensor and platform versions stay independent.

### Fixed: an analyst run measures its job deadline on its own clock

- `pkg/analyst` applied the job deadline as a wall-clock context deadline while the refusal check used the run's injected clock, so a run with an injected clock could end early, and the harness tests failed for good once the wall clock passed their fixed test time. The context now uses the time left on the run's own clock.

## v0.39.0 — 2026-10-26

### Added: `sensorkit.PreflightDataDirs` checks the sensor's data directories at start

- `PreflightDataDirs(contentDir)` (and `DataDirs`, `CheckDataDirs`) makes sure the outbox, state, store, workspaces and content directories exist and can be written, and returns a `*DataDirProblem` whose message names the path, the owner uid:gid, the sensor's own uid:gid and the two fixes (`chown -R` for a bind mount, a named volume). A sensor calls it before anything else so a bind mount owned by another user stops it with that message instead of a crash loop. Without `/var/lib/openctem` and without `SENSOR_*_DIR` settings nothing is checked, so a sensor run as a plain binary still falls back to `~/.openctem`.

## v0.38.0 — 2026-10-26

### Security: Go 1.26.10

- CI builds and checks with Go 1.26.10, which fixes GO-2026-6809 in the Go standard library (reported by govulncheck).

### Security: a tool directory is owner-checked file by file

- The sensor checked the adapter directory, the tool directory, `tool.yaml` and the program only; a helper module next to the program (for example `openctem_tool.py`), a mapping or a wordlist could be group/world-writable or owned by another user and be swapped by a local user.
- Every file and directory of a tool's directory (to 4 levels and 1024 entries) must now be owned by root or the sensor's user, not group/world-writable and not a symbolic link. For a manifest placed directly in the adapter directory, the program and the output mapping it references are checked.
- Operators: a tool directory with such a file is now refused and the `adapter_refused` check names the file; fix the permissions (`chmod go-w`, `chown`) and keep only what the tool needs in the directory.

### Security: one template check for every command type

- Delivered retest templates pass exactly the scan path's checks before anything is written: the local policy's `allow_custom_templates`, the signed job's template digests (else the per-tenant template manifest bound to this sensor and command) and `core.CheckCustomTemplate`. An item naming a template the command does not carry, a template of another tool's type, or a tool that did not opt in fails the command.
- `core.DefaultCommandExecutor.VerifyCustomTemplates` and `core.CommandTemplates` expose that check; `core.WriteCustomTemplates` writes verified templates to a private temporary directory (0700, files 0600) and returns each file and the cleanup.

### Upgrade notes: core.DiscoveredURL is no longer comparable

- `DiscoveredURL` now holds slices (`Params`, `Forms`), so `==` and use as a map key no longer compile. Compare the `URL` and `Method` members instead. The sensor and every other caller in the organisation build unchanged.

### Behaviour change: a verifier that predates `content` refuses a statement that carries it

- A signed statement with a `content` member is refused by an SDK that does not know the member (unknown statement fields are refused), so a job that pins content never runs on a sensor that cannot check the pins. Statements without `content` are unchanged.

### Behaviour change: the classes that say why are sent only to a platform that accepts them

- The scan command payload has a new optional `outcome_revision` (the highest ctis `outcome.Revision` the platform accepts). Absent or 1: every outcome is sent as before, with the new classes mapped to the closest class a revision 1 platform knows (`unreachable` or `tool_error`, never `done`) and an unresolvable name still `skipped` as `refused`. A platform that sends 2 receives the new classes. Older platforms that ignore the field see no new class and no new field.
- Re-pins `github.com/openctemio/ctis` to its main commit that adds the classes (outcome revision 2).

### Removed: `pkg/edgeprotect` moved to ctis

- The edge protection detector now lives in `github.com/openctemio/ctis/edgeprotect` (ctis v1.6.3), so a platform can use it without depending on the sensor SDK. Import that package in place of `pkg/edgeprotect`; the API is unchanged. `adapt.Event.Edge`, `adapt.HostRate.ReportResponse` and the egress signals use the ctis types.
- Raises `github.com/openctemio/ctis` to v1.6.3.

### Added: signed `openctem` CLI binaries on each release, and `openctem version`

- Each release now attaches `openctem_<version>_<os>_<arch>.tar.gz` for linux and darwin on amd64 and arm64, a `SHA256SUMS` file and its keyless cosign bundle `SHA256SUMS.sigstore.json`, so authors of Python or shell tools no longer need the Go toolchain. Verification steps are in docs/tools/cli.md.
- `openctem version` (also `openctem --version` and `openctem tool version`) prints `openctem <version>`.

### Added: the sensor runs on its content cache (packs by digest, one disk budget, refresh on the heartbeat)

- The kit opens the digest-keyed content cache (`contentcache`) on the local store, in `content/` next to the store directory, and hands it to the janitor. Packs are now counted in the one local-store quota and pruned by the janitor (revoked first, then unused, then least recently used over the budget); a pack a running task holds is never removed. There is one pack budget: the policy's `pack_budget_bytes` (default 2 GiB), also the cache's default (the cache's own 8 GiB default is gone). `SENSOR_CONTENT_BUDGET_MB` lowers it on the host; it can never raise it.
- The pairing pins the content-signing keys. `pairing.Identity.ContentSigning` lists the platform key and, for a sensor of one organization, that organization's key; `identity.Identity` keeps them (`ContentPlatformKeys`, `ContentTenantKeys`). A shared sensor takes the platform key only. A key is never taken from a content route. A sensor paired before this has no content keys and no cache: it runs no job that names packs until it is paired again.
- The cache refreshes on a schedule and at once when a heartbeat answer carries a new `content_version` (`HeartbeatHints.ContentVersion`, `Doorbell.SetContentHandler`).
- The heartbeat's local-store report carries `content` (`core.ContentReport`): the digests held (at most 200, with the count and a SHA-256 of the whole set), the bytes, the hit, miss, download and saved-byte counters, verification failures and the desired-set version last synced. No tenant names, paths or file names.
- `Cache.Install` is single-flight per digest: concurrent claims of one missing pack share one download and one stored copy.
- The tool host's `ContentRoot` is the cache root: a task's content packs must lie beneath it.

### Added: jobs pin content by digest in the signed statement and the payload

- `jobsig.Statement.Content` (`[]ContentRef{slot, digest}`) lists the packs the signer approved for the job. The verifier requires the payload's `content` members to match it exactly, in order (`ReasonContent`).
- `ScanCommandPayload.Content` (`JobContent`: slot, kind, scope, pack, digest, size, files, max_lines, DSSE signature) and `Inputs` (`JobInput`: lists the platform generated for the job, gzip, at most 256 KiB compressed, at most 8 MiB expanded, with the sha256 of the expanded list). The executor mounts a pack only when the verified signed statement lists it: a job that names packs without a verified statement is refused, and so is one whose packs differ from the statement (`job_content`).
- A pack is checked against the pinned keys, its digest and the archive rules before a task reads it, also when it is already held; a missing one is fetched at claim (bounded by two minutes) and a delivery failure fails the command with `content_unavailable` so the platform can requeue it. A shared sensor mounts platform packs only; tenant packs are refused there.
- A tool with a `wordlist` content slot declares a `purpose` (`dns-labels`, `web-paths`, `web-files`, `api-routes`, `params`, `extensions`, `vhosts`) and an optional `max_lines`. The tool host composes the job's lists into one file in the task's own directory (`pkg/tool/wordlist`: normalise per purpose, drop repeats, first occurrence ranks first, cap) and the tool reads that one path (`{{content.<slot>}}`). Inline lists are written only there, never to the content cache, and go with the task directory; the packs' own read grants are dropped for a composed slot.
- `core.ContentResolver`, `core.ContentScanner`, `ScanOptions.Content`, `DefaultCommandExecutor.SetContentResolver`, `tool.ContentSlot.Purpose/MaxLines`, `tool.TaskContent.Files/Inline/MaxLines`.

### Added: content manifest and acquire-by-digest before a task

- `contentcache.ContentManifest` (versioned JSON, version 1): per tool slot, the ordered rule-source snapshots (source slug, digest, scope, size, DSSE signature), disabled rule ids, quarantined rule ids, and revoked digests. `ParseManifest` validates it and refuses a newer version; unknown fields are ignored.
- `Cache.Ensure` fetches the manifest's missing packs by digest, verifies the pinned-key DSSE signature, the digest and the canonical archive, and installs them keyed by digest. A held digest is never fetched again, revoked digests are refused before any network use, and a pack that cannot be delivered fails with `ErrUnavailable`. `Cache.Prepare` also sets the task's content and paths; `Cache.Revoke` bans digests.
- `HTTPFetcher.Manifest` fetches a manifest with ETag and 304 support. The same fetcher serves the sensor routes and the CI routes (different base URL and credentials). Library only: the sensor and CI adopt it separately.

### Added: content manifest `required_features`

- `ContentManifest.RequiredFeatures` (`required_features`, optional, `version` stays 1): behavior a reader must understand to run the task. `ParseManifest`, `Validate` and `Cache.Ensure` refuse a manifest that lists a feature missing from `contentcache.KnownFeatures` (empty in this release) with the new `ErrUnsupported`; the task fails with reason `content_unsupported`, not `content_unavailable`, because requeueing to the same sensor cannot help. Unknown fields are still ignored, so later optional fields never break an older reader.

### Added: scan and retest jobs run through the organization's proxy pool they carry

- A scan or retest command may carry `egress` (`upstream.Config`: pool id, revision, strategy, `applies_to`, endpoints with weights; never credentials). The executor checks the sensor's veto, validates the pool, fetches the credentials once per job only when an endpoint has some (`POST /api/v2/sensor/commands/{id}/egress-credentials`, under the lease, v2 HTTPS only), and hands the pool to the scanner (`ScanOptions.Egress`, `tool.Task.Egress`, and the job context: `core.EgressDialerFrom`). The tool host makes it the task forwarder's `Dial` hook in the sensor's process; a tool never sees the pool or its credentials.
- A pooled job never runs direct: it is refused (`egress_unavailable`) for a scanner that does not route its tools through the tool host (`core.EgressScanner`), and the tool host refuses a pooled task on a sandbox that does not confine the network (a tool with network `none` still runs). An empty pool is refused with `egress_unavailable`.
- New settings `SENSOR_SCAN_EGRESS` (`platform`, the default, or `direct-only`) and `SENSOR_SCAN_EGRESS_ALLOW` (allowed `host:port` or `host` endpoints): a job the sensor's settings do not accept is refused with `egress_refused_by_host`. A shared sensor refuses every pooled job.
- At the end of a pooled job, completed or failed, the poller sends the pool's per-endpoint signals (`POST /api/v2/sensor/commands/{id}/egress-report`, v2 HTTPS only) before the result, best-effort.
- `core.CapabilityEgressUpstream` (`egress.upstream@1`) and `Kit.AcceptsEgressPools`: a sensor reports the capability when its tool tasks run confined and its settings accept pools; the platform sends pooled jobs only to such sensors. Platforms that send no `egress` see no change.

### Added: the task forwarder can send connections through an organization proxy pool

- New package `pkg/sensorkit/egress/upstream` (Experimental): `upstream.New(cfg, opts)` returns a `*Pool` whose `Dial` is the task forwarder's `Dial` hook. The forwarder still checks the destination against the job's scope, pins its address and paces the target before anything is dialed; the pool only chooses the path.
- Tunnels: HTTP CONNECT (Basic `Proxy-Authorization` only when the endpoint has credentials), HTTP CONNECT over TLS to an `https` proxy (certificate verified against the system roots, TLS 1.2 or later, never skipped) and SOCKS5 with optional username/password (`socks5h` is treated as `socks5`). The tunnel is always opened to the IP address and port the scope check allowed, never to a name.
- Selection: `sticky` (default) ranks endpoints by a weighted rendezvous hash of (job, target host), so a host keeps one endpoint for the job and removing an endpoint moves only its hosts; `priority` keeps the given order.
- Failover only when a proxy is down (TCP/TLS failed, timed out, or the proxy answered garbage), at most once per endpoint; a 407 or SOCKS authentication failure makes that endpoint unusable for the rest of the job; a CONNECT 403/502/503/504 or a SOCKS refusal is about the target and ends the connection. A connection never falls back to a direct dial while a pool applies to it. A pool that applies to public targets only dials private, ULA, CGNAT and loopback targets directly.
- A CONNECT reply that never comes is about the target once the endpoint has carried a tunnel in the job. Before that, it counts towards the endpoint's breaker, and the third one is `proxy_down` (the connection fails over and the breaker opens): a proxy that accepts connections and never answers is taken out like one that refuses them. A dial the caller gave up on (its context ended or reached its deadline) is never counted.
- Each endpoint has a breaker local to the job (3 consecutive proxy failures open it for 30 s, doubling to 10 min, ±20 % jitter, one half-open probe) and counters (`Pool.Report`) for the platform's health score.
- Endpoint addresses are checked when the pool is built and again at every dial for each address a host name resolves to: loopback, link-local, cloud metadata, multicast, unspecified, broadcast, 0.0.0.0/8 and 240.0.0.0/4 are refused; private addresses are allowed. `upstream.ParseAllow` reads a sensor's allow list of endpoints.
- `egress.Record` gains `endpoint` (the endpoint id that carried the connection); `egress.TargetHost(ctx)` gives a Dial hook the host the tool asked for; `egress.UpstreamError` classifies upstream failures (`proxy_down`, `proxy_auth`, `target_unreachable`, `target_refused`). A proxy failure is not counted against the target's rate or reachability.

### Added: a failed command reports a failure class, bounded evidence and per-target results

- `POST /commands/{id}/fail` now carries `error_code` always (`TOOL_EXIT` for a crash, `TIMEOUT` for the job budget, `PARSE_ERROR` for a parse failure, `TARGET_UNREACHABLE`; the other classes send none, so the platform keeps classifying the message), and, to a platform that lists the new `failure_class` feature, `failure` (`class`, `scope`, `retry_after_seconds`, `evidence`) and `target_outcomes` (the targets settled before the failure: done, failed on the sensor's side, failed on the target's side, or unfinished). The sensor classifies and shows evidence; the platform decides where the job goes next.
- Classes (`core.FailureClass`): `infra.tool_crashed`, `infra.tool_unavailable` (reasons `tool_missing`, `not_executable`, `tool_version`), `infra.resource.memory`, `infra.resource.disk`, `infra.resource.output_limit`, `infra.budget_exceeded`, `infra.sensor_network`, `infra.dns_resolver`, `infra.egress.proxy_auth`, `infra.egress.proxy_down`, `infra.egress.pool_exhausted`, `infra.content_unavailable` (reasons `verification_refused`, `content_revoked`, `content_unsupported`), `infra.job_signature`, `infra.transient`, `target.*`, `config.*` and `unknown`. A policy refusal keeps its own structured form and gets no class.
- Evidence holds closed values and numbers only (tool name, digests, stage, exit code, signal, errno, control-probe states, proxy failure counts); a value outside its set is dropped before it leaves the sensor, and no proxy address or credential can enter it. The failure message is redacted (URL credentials, authorization headers, bearer tokens, secret-named values), stripped of control characters and cut at 4096 bytes.
- `tool.Error`, the content cache's errors and `upstream.ErrNoEndpoint` name their own class through `core.FailureClassifier`. A scan that fails lists the targets it settled (coverage gaps, unreached targets with the control check deciding whose side) and marks every other target unfinished, never done.

### Added: hermetic self-test fixtures served by the conformance kit

- A fixture task file may carry a `serve` member (default response, per-path overrides, optional self-signed TLS) and `{{fixture.url}}`, `{{fixture.host}}`, `{{fixture.port}}`, `{{fixture.host_port}}` placeholders in its target values. `openctem tool test` serves it on 127.0.0.1 for the run and normalizes the port in the expected CTIS. The member is read only by the kit and never reaches a sensor or `tool.yaml`.
- `openctem tool init` writes such a fixture for tools that take URLs, services or hosts, so a fresh scaffold's self-test no longer sends traffic to an internet host, and writes a `.gitignore`. The kit runs python tools with `PYTHONDONTWRITEBYTECODE=1`.

### Added: `file-import` reads a reconFTW results directory

- `file-import` accepts `format: reconftw`: the one input is a results directory of the task (the runtime has already extracted the archive), read as a bundle by the ctis importer. It emits the subdomains, addresses, ports, live web services, endpoints and nuclei findings as partial-coverage records. Files under `osint/` are never opened and are logged as skipped on purpose; unknown files are logged. A link, a special file or a directory that is not a recon layout refuses the task. The manifest (version 1.1.0) now produces `asset:subdomain`, `asset:http_service`, `asset:certificate`, `asset:storage` and `endpoint`.

### Added: `sensorkit.InspectAdapterDirs`

- `InspectAdapterDirs(dirs, builtin)` reports the tools the sensor would load from `SENSOR_ADAPTER_DIRS` (name, version, manifest path, digest, capabilities, class, tier, network) and the manifests it refuses with the reason, without a platform. The kit loads from the same function, so the two cannot disagree.

### Added: organization enrollment tokens (SENSOR_ENROLLMENT_TOKEN)

- A sensor with no identity and `SENSOR_ENROLLMENT_TOKEN` (or `SENSOR_ENROLLMENT_TOKEN_FILE`) set enrolls in the organization that created the token (platform: Sensors > Enrollment tokens), through the usual key-bound pairing. The start request carries `enrollment_scope: "organization"`; the identity must name an organization (a shared-sensor answer is refused), and the sensor prints its fingerprint in case the token requires an administrator's approval. The token is never printed, is taken out of the environment once used, and cannot be combined with `SENSOR_PAIRING_CODE` or `SENSOR_INSTANCE_ENROLLMENT_TOKEN`.
- An expired request is retried with the same key (the platform counts a token use per key), so a sensor waiting for approval keeps waiting instead of exiting.
- `SENSOR_INSTANCE_ENROLLMENT_TOKEN` is unchanged: an instance token only, and only a shared-sensor identity is accepted for it.
- The pairing instructions name the console's current place: Sensors > Add sensor.

### Added: host direct-only is reported, validate jobs go through the pool, and a pool can be tested

- `core.CapabilityEgressHostDirect` (`egress.host-direct@1`) and `Kit.EgressHostDirect`: a sensor with `SENSOR_SCAN_EGRESS=direct-only` is marked, so the platform runs its scans direct and shows the path as set on the sensor host instead of holding its jobs.
- `core.CapabilityEgressValidate` (`egress.validate@1`) and `Kit.PrepareEgress`: a command handler of the sensor's own (the validate executor) prepares the job's pool exactly as a scan does and sends its probes through it; the pool's signals reach the platform in the job's egress report. `LocalPolicy.DialContextVia` checks the policy and then dials the checked address with the given dialer (a pool), never the name.
- `core.CommandTypeProxyTest`, `core.CapabilityProxyTest` (`proxy.test@1`), `core.ProxyTestExecutor` and `Kit.ServeProxyTest`: the platform's Test button asks a sensor to test each endpoint of a pool (`upstream.Pool.Test`: handshake time, exit address through the platform's echo, IPv4 and IPv6, a port-restricted proxy). `upstream.Pool.DialEndpoint` tunnels through one named endpoint, also one whose breaker is open. The request through the proxy carries only the test's token; the echo address is refused when it is loopback, link-local or a metadata address.

### Added: a target that was not covered says why, and an edge protection is recognised

- The detector is the package `github.com/openctemio/ctis/edgeprotect`: `Classify(status, headers, title, body)` tells a challenge, a block, a rate limit or only fronting from the signs a vendor's own edge leaves (Cloudflare, AWS CloudFront and AWS WAF, Akamai, Fastly, Azure Front Door, Imperva, F5). A challenge or block needs a vendor marker next to the status: a bare 403 is the origin's own answer and stays `direct`. The rules are data (`Rule`, `DefaultRules`, `ClassifyWith`) so a newer table can be shipped without new code. Inputs are bounded (16 KiB of body, 512 bytes of title, 1 KiB per header value) and the classifier sends nothing and solves nothing.
- The task forwarder reads the vendor markers in a response's headers: a challenge or block page is a block from the first answer (before, a 403 counted only after the host had answered something else, and only after a run of 20). The host becomes a `blocked` coverage gap with the new additive `edge` (`challenged` or `blocked`) and `vendor` members. `adapt.HostRate.ReportResponse` and `Event.Edge` carry the verdict.
- `reach.ClassifyDNS` splits a DNS failure into `name_gone` (the resolver answered NXDOMAIN or NODATA) and `resolver_failed` (SERVFAIL, REFUSED, a resolver timeout). The class stays `dns_failure` on the wire; the refinement is the new additive `reason` of an unreached target and `dns` of a refused target. `reach.Recorder.Lookup` and `reach.HostOf` find what was recorded for a target under another spelling.
- New `reach.Control`, the network-path self-check: one cheap TCP connection to a platform-owned endpoint through the task's egress path and one lookup of a platform-owned name, cached for the task. `ControlResult.SensorFault(class)` says whether an unreached target is the sensor's own network (the path probe failed) or DNS (the control lookup failed) rather than a fact about the target. A probe that is not configured, or a canceled job, never charges the sensor.
- `core.TargetOutcomesFor` no longer marks a target done when nothing covered it: a host the rate controller gave up on (blocked by an edge, pushing back at the lowest rate, stopped answering) and a target every attempt to reach failed are settled `failed` with the new ctis outcome classes `edge_challenged`, `edge_blocked`, `rate_limited`, `name_gone`, `resolver_failed`, `sensor_network_fault` and `unreachable` with a `reason`, each with its `cause` (`target` or `sensor`). `TargetOutcomes` keeps its report-only meaning.
- A name that does not resolve at admission is `failed` as `name_gone` or `resolver_failed` instead of `skipped` as `refused`.

### Added: retests can run a check the platform delivers

- A retest command may carry custom templates (`custom_templates`, optionally `custom_templates_envelope`) and items that name one (`"template": "<id>"`). `Kit.HandleRetestTemplates(name, run)` serves such retests for a tool and reports capability `retest-templates:<tool>` (`toolcompat.RetestTemplatesCapability`) beside `retest:<tool>`; sensors that do not opt in are unchanged and never receive such a command.
- `tool.RetestItem.TemplatePath`: the file of the delivered check for that item, set by the sensor only. The tool runs exactly that file and reports its digest; a templated `fixed` or `still_present` verdict under another digest becomes `unverifiable`.

### Added: a retest verdict can report each request the check made

- `tool.RetestVerdict`, `tool.VerdictReport` and the adapter `verdict` message carry optional `requests` (`tool.RequestResult`: URL, status, matched, error class, edge vendor and state), at most `tool.MaxVerdictRequests`. A check that probes several paths reports them so the platform can judge the finding's own endpoint. Additive and wire-compatible: older platforms ignore the field, and older tools simply omit it.

### Added: a retest verdict says why an item could not be verified

- `tool.VerdictReport.Code` (and `tool.RetestVerdict.Code`, the wire verdict's `code`) is an optional reason of an unverifiable verdict from a closed set: `template_not_found`, `excluded_by_policy`, `target_unreachable`, `egress_refused`, `no_verdict`. An unknown code, a code on a conclusive verdict, or `egress_refused` from an out-of-process tool (only the runtime or a built-in tool can prove the confinement refused a target) is dropped by the runtime.

### Added: a run watch for every tool run, and the platform's deadline as a job budget

- A tool that settled every target of its task but sends no result within `core.DefaultFinishGrace` (5 minutes) is canceled, then killed after the grace, and the run ends as its targets say: every accepted record is delivered and the task log carries a warning that the sensor stopped the tool. Before, a tool that hung after its work and kept heartbeating ran until its task timeout (24 hours for nuclei).
- A tool that sends nothing but heartbeats while its processes use less than a second of CPU for `core.DefaultInactivity` (20 minutes, or the platform's `budget.stall_seconds` clamped to 5 minutes..2 hours) is stopped as timed out and delivers what it settled (`partial`). Linux only (process CPU time); elsewhere the check is off.
- Both bounds are `core.RunWatch` (`toolhost.RunOptions.Watch`, or the job's through `core.WithRunWatch`); a negative field turns a check off.
- A scan command may carry `deadline` (when the platform stops waiting for it). The job's time budget then ends `core.DeadlineMargin` before it (a tenth of the time left, 1 to 10 minutes, at least 30 seconds of budget), so a run stopped there still delivers its settled targets in time. It can only shorten a job.
- A canceled, drained or kill-switched command whose executor does not return within 2 minutes is given up (released, or reported failed for the kill switch) instead of holding its slot until the sensor restarts. A platform stop (deliver what finished) is still waited for.

### Added: probes and crawlers can report web content facts, bounded

- `core.DiscoveredURL` gains `ContentType`, `Params` and `Forms` (field names and a password-field flag, never values); `Parent` is now redacted by `Sanitize`.
- `core.LiveHost` gains `ResponseHeaders` and `CNAMEs`. `core.ResponseHeadersFrom` keeps only HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and the two CORS allow headers, plus the names and flags of cookies; cookie values and every other header never pass.
- `NewWebForm` and `IsPasswordFieldName` set the password-field flag from field names, for crawlers that do not see input types.
- `SplitSetCookie` splits a joined Set-Cookie value without splitting inside an Expires date; `SplitTechnology` splits `Name:version`.
- `DiscoveredURL.Sanitize`, `SanitizeForms`, `SanitizeURLParams` and `SanitizeCNAMEs` bound every value a scanned server chooses (control characters, non-http(s) schemes, oversize values are dropped). Sensors call them before reporting.

### Changed: plain local policy messages

- A sensor that needs a local policy and has none logs one short line: network scans are refused until one is added, copy the policy the console suggests to `/etc/openctem/sensor-policy.yaml` and reload with SIGHUP, or set `SENSOR_ALLOWED_RANGES`. The same help ends every `no_local_policy` refusal.
- A private range in `SENSOR_ALLOWED_RANGES` without the private switch now says to also set `SENSOR_ALLOW_PRIVATE_TARGETS=1`; it no longer points at `targets.allow_private`, a key of the policy file the shorthand does not use.

### Changed: sensor warnings and descriptions no longer cite internal design documents

- The "no local policy" warning is now one sentence with its fix: this sensor was paired before local policies were required, so it accepts any target outside the built-in deny list; install the policy file or set `SENSOR_REQUIRE_LOCAL_POLICY=true`. The second, near-duplicate warning is folded into it.
- The `SENSOR_API_KEY` description, the manifest conformance skip message and the tool schema descriptions no longer cite RFC numbers.
- A test (`internal/refgate`) fails when a Go string or shipped schema cites an RFC number, research note or decision id.

### Changed: tool.yaml errors say how to fix them

- An unknown capability names the nearest taxonomy ids (`did you mean scan.ports@1?`), or the majors that exist when only the major is wrong.
- An unknown CTIS asset or finding type is quoted, with the nearest type and, for finding types, the allowed set; common words (`url`, `ip`, `port`, `repo`, `image`) map to the CTIS type.
- An unknown key is reported at its JSON pointer with the nearest known key, or where it belongs (`/timeout: unknown key; did you mean /resources/timeout?`).
- A value of the wrong type says what it must be in plain words (`/version: must be a string; quote it ("1.0.0")`), never a Go type name.
- Only the wording changed: nothing newly accepted or refused. Echoed input is quoted and cut to 64 bytes.

### Fixed: the tool and adapter JSON Schema `$id`s resolve

- `pkg/tool/schema/tool.v1.schema.json` and `adapter.v1.schema.json` now use their raw.githubusercontent.com URL as `$id`, so editors and validators can fetch them. Schemas that referenced the old `https://openctem.io/schema/...` ids must use the new ones.

### Fixed: a silent host can no longer keep a finished task (and its command) open

- The egress forwarder closes every connection it serves, on both sides, when it stops; before, a plain HTTP request or a tunnel to a host that accepted the connection but never answered kept its handler blocked after the tool gave up and exited, the tool host waited for the forwarder forever, and the command never reported its result or honoured a cancel.
- An upstream connection whose host sends nothing for `egress.Limits.UpstreamIdle` (new, default 2 minutes, negative turns it off) is closed while the task runs. A tunnel cut this way after the host answered is not counted as a host failure by the adaptive rate.
- The tool host waits at most 10 seconds for a task's forwarder to stop, and at most another grace period for a killed tool to be reaped, then finishes the task with a warning line instead of hanging.
- A repeated platform cancel for the same command is a no-op: the command poller logs "Canceling command" once, not on every heartbeat. A cancel that arrives before the command's context exists is no longer swallowed.

### Fixed: a connection the proxy pool could not carry no longer reads as "nothing found"

- When a job's proxy pool cannot carry a connection (every usable endpoint is down or refuses the credentials, or the proxy's own rules refuse the destination, such as a CONNECT proxy that allows port 443 only), the task forwarder now marks the host as a coverage gap with the new reason `adapt.GapProxyUnavailable` (`proxy_unavailable`). The scan ends partial (`coverage_type` partial), so the platform never closes findings because a run that reached nothing through a dead proxy reported none. The host's target outcome is `sensor_network_fault` with cause `sensor` and reason `proxy_unavailable`. Before, such a run declared full coverage.
- A path failure no longer moves the target's rate: a proxy's CONNECT 403 or SOCKS ruleset refusal was counted as the target's failure.
- What a proxy says about the target is now a reach fact: CONNECT 502/503 and SOCKS network or host unreachable are `no_route`, CONNECT 504 and SOCKS general failure or TTL expired are `timeout`, SOCKS connection refused is `port_closed`. A host that does not answer through the pool is unreached, as on the direct path. The reach detail never carries the proxy's address. `egress.UpstreamError` gains `TargetClass` and `PathFault()`; `adapt.HostRate` gains `MarkGap`.

### Fixed: proxies that answer 401 or 500 to CONNECT are classified right

- A CONNECT 401 (some proxies send it instead of 407 for wrong credentials) is now `proxy_auth`: the endpoint is out for the job and the platform hears it. It was `target_refused`, so a pool with wrong credentials was retried on every connection and never flagged.
- A CONNECT 500 (what some proxies answer when they cannot connect to the target) is now `target_unreachable` (`no_route`). It was `proxy_down`, so a port scan of closed ports through such a proxy opened its breaker, failed over and got a healthy proxy quarantined by the platform.
- A proxy that takes the request and never replies is taken as hung (`proxy_down`) only after timeouts toward three distinct target addresses with no tunnel in the job; three timeouts toward one filtered host scanned port by port no longer quarantine it.

### Fixed: a proxy that refuses our credentials hands the connection to the next proxy

- In the proxy pool a 407 or a refused SOCKS login on one endpoint now moves the same connection on to the next endpoint (the endpoint stays out for the rest of the job and is reported as `proxy_auth`), as a proxy that is down already did. Before, the host was lost for the job as a coverage gap while healthy endpoints stood by. The connection still never goes direct: when every endpoint is down or refuses our credentials it fails, and a target's answer is never retried through another proxy.

### Fixed: pairing explains clock skew and rate limits, and waits them out in process

- `identity.Pair` returns a `*identity.ClockSkewError` when the platform refuses a request signature for clock skew: from the platform's `clock-skew` problem (`server_time`, `clock_offset_seconds`; new `protov2.ProblemClockSkew` and `Problem` fields), or, from a platform that answers only the generic 401, when its `Date` header is more than 2 minutes from this machine's clock. The message names the offset, which clock is ahead, and the fix (NTP, `sudo chronyc makestep`).
- A 429 during pairing prints "Rate limited by the platform (HTTP 429); retrying in N s." before it waits (it was silent), and honours a `Retry-After` up to 5 minutes (was 2).
- New `PairOptions.RetryTransient`: a clock skew, a rate limit after 5 tries, an unavailable platform (502, 503, 504, 500 and a generic 401 without an enrollment token) or a network error is retried in process with exponential backoff (5 s doubling to 5 minutes) and a message each time, instead of returning. `sensorkit` sets it, so a daemon no longer exits into its supervisor's restart loop and spends the platform's pairing budget. A refused enrollment token, a denial, a 400 and a platform key mismatch still return.
- The codeless pairing instructions also say how to pair with a code created under Sensors > Expect a sensor (`SENSOR_PAIRING_CODE`).

### Fixed: an item the tool never judged is no longer a bare "no verdict"

- When a retest item gets no verdict, the runtime now says what it knows: its target did not answer or was refused by the network confinement (`target_unreachable`, `egress_refused`), the target was skipped or never reached, or the run stopped (`no_verdict` with the error class in the detail).
- A retest item on a target the sensor's network confinement refused every connection toward is now unverifiable (`egress_refused`) whatever the tool concluded: a tool that never reached the target cannot call a finding fixed or still present.

### Fixed: signed jobs are no longer refused after platform aging reorders a batch

- The command poller re-sorted a claimed batch by priority before verifying job signatures, while the signer numbers jobs in the platform's order and a sensor accepts only strictly increasing sequence numbers. When aging put a lower-priority job first, valid jobs were refused as replays. The poller now handles a batch in the order the platform returned it (the platform owns ordering); replay protection is unchanged.

### Documentation: organization proxy pools for scan traffic

- `docs/SECURITY.md` explains how a job's proxy pool is applied (scope check first, tunnels by address, failover rules, breaker, endpoint validation, credential handling, where pooled jobs are refused), the `SENSOR_SCAN_EGRESS` veto and `SENSOR_SCAN_EGRESS_ALLOW`, and that HTTP proxies must allow CONNECT to the scanned ports; the README settings table lists both settings.

## v0.37.0 — 2026-10-19

### Security: custom template check covers request-level self-contained and include directives

- `core.CheckCustomTemplate` now refuses a nuclei template whose request (not only the template) sets `self-contained` to anything but false, at any depth: such a request is sent to the URL in the template instead of the scan's target.
- It also refuses nuclei's `# !include:` preprocessor directive, which inlines a file from the sensor's disk that the check never reads.

### Security: custom templates are checked on the sensor before they are written

- After the signature check, every nuclei custom template is refused when it has a `code`, `javascript`, `flow`, `file` or `headless` block, a self-contained request, `workflows`, a payload file or a second YAML document (`core.CheckCustomTemplate`). The command fails before any template is written or any scanner runs, whatever the platform signed.

### Added: rule sources for scan commands

- A scan command may carry `rule_sources` (`both`, the default; `platform`; `tenant`). The executor refuses a command that contradicts itself (platform-only with custom templates, tenant-only without any, an unknown value) and passes the choice to the scanner as `ScanOptions.RuleSources`, also to scanners that run out of process.
- `core.CapabilityRuleSources` (`rule.sources@1`): a sensor whose scanners honor the choice reports it; the platform sends tenant-only jobs only to such sensors.
- `core.TenantRulePrefix`, `core.TenantRuleID`: findings of an organization's own rules carry `tenant:`-prefixed rule ids.

## v0.36.0 — 2026-10-19

### Added: sensorkit wires the local store, job recovery and the janitor

- A daemon opens `localstore` beside its outbox (`SENSOR_STORE_DIR`, `SENSOR_STORE_KEY_FILE`, `SENSOR_WORKSPACE_DIR`; defaults next to the outbox directory) and hands it to the outbox: new items are sealed per organization (file format 2). Existing items are read as before and the outbox key becomes the organization sensor's data key; a fresh outbox no longer creates `outbox.key`.
- At start the kit reports every job the journal shows unfinished as a failed command result (`Client.ReportInterruptedCommand`), sweeps the workspaces a crash left, and starts the janitor (at start, after acknowledgement bursts, every 10 minutes). `Kit.SetStorePolicy` sets its policy, clamped; the platform has no policy field for it yet, so the defaults apply.
- `core.CommandPoller.SetJobJournal` (`core.JobJournal`): the kit journals every job from the platform's start until its result is queued, so a crash mid-job is reported at the next start. `outbox status` never creates a store key.
- `core.CommandPoller.SetClaimGate`: the poller claims nothing while the outbox is full of unacknowledged results, storage is at the high watermark or the volume is low, and resumes when that clears; each change is logged once.
- The heartbeat carries `local_store` (`core.LocalStoreReport`: bytes per class, watermark, stop-claiming, last sweep, boot generation and reset) only to a platform that lists the new `local_store` feature (`protov2.FeatureLocalStore`). `client.OutboxConfig.OnDelivered` is new.
- `doctor` checks `storage.store_dir`, `storage.store_key`, `storage.store_disk` and `storage.store_persistent` (the store holds the keys of the sealed outbox items: keep it on the same persistent volume as the outbox).
- The store directory and its key are in the tool sandbox's protected paths.
- `pkg/sensorproto/relay` is checked against the platform's cross-implementation batch framing vector (`testdata/vector-batch-v1.json`).

## v0.35.0 — 2026-10-19

### Security: one deny list with the platform (ctis addrscope)

- `httpsec.IsIPBlockedWith` (and with it the scan target policy, the local policy's built-in deny list and the shared-sensor zone rule), and the egress forwarder's public-only check now use `github.com/openctemio/ctis/addrscope`. The platform checks job targets with the same package.
- An IPv6 address that carries an IPv4 address (NAT64, 6to4, Teredo, IPv4-compatible) is judged by that IPv4 address. `64:ff9b::a00:1`, `2002:a00:1::1` and a Teredo address whose client is 10.0.0.1 are refused, even where private targets are allowed. The same forms of a public address are no longer refused for their range alone.
- Newly refused: `fec0::/10` (deprecated site-local). Vendor hosts and egress-proxy destinations that resolve to CGNAT, benchmarking or reserved space are refused too. Ranges that hold `192.0.0.0/24`, `198.18.0.0/15` or an IPv6 range that carries IPv4 are refused as range targets.

### Security: content packs are verified every time a task loads them, and revocations survive restarts

- `contentcache.Cache.Acquire` re-verifies a held pack before a task may use it. It checks the stored statement against the keys pinned now, so a key that is no longer pinned stops working, and that the statement names the pack's digest and this organization. It also checks the files on disk, against the index sealed at install (`Options.Index`, a `localstore.Sealer`) or, without one, by rebuilding the canonical archive and comparing its digest with the signed one. A changed, added, removed or symlinked file, or a statement or index taken from another pack, refuses the load. The pack is then removed when no task holds it, and the failure is counted (`Stats.VerifyFailures`).
- An unchanged pack is fully checked again at most every `ReverifyEvery` (default 6 h). "Unchanged" compares size, mode, modification time, change time and inode, and an unprivileged writer cannot set the change time back.
- With `Options.State` (a `localstore` namespace) the revocation set is persisted and only grows. A revoked pack stays refused after a restart and while the platform is unreachable, and is removed at start when nothing holds it. A revocation record that fails authentication refuses every load (`ErrRevocationsUnknown`) until the platform's next sync.

### Security: store rollback detection, stale handles after erasure, link-safe workspace removal

- `localstore.Guarded()` marks a record whose rollback is an attack: the store counts its writes in the sealed meta record, and an older copy put back, a replacement by an unguarded file or a deletion behind the store's back reads as `ErrRollback` and is reported through `OnTamper`. The content pack revocation list is guarded. If `meta.rec` is lost, or an older copy of it is restored (a record then carries a boot generation above it), the boot generation restarts above the records', `Stats.BootReset` is set for the heartbeat, and every guarded record reads as `ErrRollback` until it is written again.
- A `Sealer` or `KV` handle made before `Store.EraseTenant` now fails with `ErrTenantErased` instead of silently creating a new key; asking the store for a new handle is the explicit way to start a tenant over.
- `Outbox.DropTenant` now also returns how many of the tenant's items are in flight (kept; call again before erasing the key). **Behaviour change:** the signature is `(dropped, inFlight int, err error)`. The janitor waits for in-flight items before it erases a tenant.
- Removing a workspace no longer resolves any path outside it: the walk, the chmod and the removal use `os.Root`, so a task that swaps a directory for a link while it is being removed cannot make the sensor change or delete anything outside the workspace.
- `contentcache.Cache.SetPinnedKeys` replaces the pinned signing keys and forgets earlier load checks, so a pack signed only by a key no longer pinned stops loading at once.

### Security: per-organization keys for queued results, with crypto-erasure (`outbox.Config.Store`)

- With a `localstore.Store` (`outbox.Config.Store`, `client.OutboxConfig.Store`), every new outbox item and its state are sealed under the data key of the item's organization (file format 2, which names the tenant in the header). Before, one key covered every organization.
- A shared sensor can now remove an organization's queued results with `Outbox.DropTenant` and then crypto-erase them with `Store.EraseTenant`; a copy left on a snapshot can no longer be read. An item copied over another organization's, or relabelled in its header, does not open. A tenant name read from a file never creates a key.
- Upgrade: items written before (format 1) are still read with the outbox key, which the store adopts as the organization sensor's data key, so nothing is re-encrypted. Without the outbox key, format-2-only outboxes open and format 1 items still refuse to open, as before.

### Security: a confined task never dials an address no check has seen

- `LocalPolicy.AdmittedAddrs` without a policy file applies the built-in deny list to the addresses it returns, as `CheckTarget` does. A name that passed the target check with a public address and resolves to a private, loopback, CGNAT, link-local or metadata address when the task starts is refused, not pinned for the task's forwarder (DNS rebinding).
- The tool host, when its policy has no `AdmittedAddrs`, checks every address of its own lookup with the policy's target check before pinning it (a CI run without any policy, whose admission checks no target either, is unchanged). Before, it pinned whatever the name resolved to when the task started.

### Security: pinned job-signing keys cannot be turned off by env; plain-http platform URLs are refused

- On a sensor whose identity pinned job-signing keys or a root at pairing, `SENSOR_REQUIRE_SIGNED_JOBS=false` is now a usage error (it may only raise the requirement). The one escape is `SENSOR_DANGEROUS_ALLOW_UNSIGNED_JOBS=1`, for development: the sensor warns at start and for every unsigned job it accepts (`core.JobGuard.AllowUnsignedJobs`).
- A sensor with no pinned key (posture `off`) now warns at start whatever the verbosity; the posture is already part of the posture report sent to the platform.
- `httpsec.CheckAPIBaseURL` returns an error for a plain `http://` platform URL to a host that is not loopback (it was a warning). `SENSOR_ALLOW_INSECURE_HTTP=1` (development only) turns the error back into a warning.
- The sensor warns at start when the test switch `OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK` is on.

### Security: a newly paired sensor never starts out accepting unsigned jobs

- An identity paired by this SDK records `require_signed_jobs`: the sensor requires signed jobs whatever the platform served at pairing. Before, a platform that served no job-signing key (or a hello that could not be read) left the sensor accepting unsigned jobs for good, so a compromised platform could downgrade every new pairing.
- With nothing pinned, such a sensor does not start until `SENSOR_JOB_SIGNING_ROOT` (shown in the console's install snippet) or `SENSOR_JOB_SIGNING_KEYS` is set. `SENSOR_REQUIRE_SIGNED_JOBS=false` alone is refused; only `SENSOR_DANGEROUS_ALLOW_UNSIGNED_JOBS=1` (development) lifts it: at pairing on its own, at start together with `SENSOR_REQUIRE_SIGNED_JOBS=false`.
- `SENSOR_JOB_SIGNING_ROOT` set at pairing is checked against the key set the platform serves: pairing pins it only when that key set is signed by it and current, and fails otherwise without saving an identity (`identity.ErrJobSigningRootMismatch`). Trust note: the console reads the root from the platform's API, so this guards against anything between the sensor and the platform and against a platform compromised after the snippet was copied, not against one already compromised when it was copied; for that, take the root fingerprint from whoever holds the offline root key. Without the root, the key set's root is pinned on first use.
- **Upgrade note:** existing identities are unchanged. A new pairing against a platform without its job signer gives a sensor that will not start until the signer runs or the root is set; set `SENSOR_DANGEROUS_ALLOW_UNSIGNED_JOBS=1` while pairing only for development.

### Security: a shared job's private ranges come from its signed zone

- `jobsig.Statement.Zone` (`zone`: the instance scan zone's `id` and `ranges`, api RFC-100 §6.1). The signer signs it only for a zone in its own zone ledger that is assigned to the job's organization and served by the claiming sensor. An organization's sensor refuses a statement that carries a zone (reason `sensor_scope`); a shared sensor refuses a zone without an id or ranges.
- A shared sensor runs a verified job with `core.WithJobZone` set to the private ranges of the signed zone (`core.ParseZoneRanges` drops anything that is not wholly private). `ScanTargetPolicy.Shared` and `toolhost.Host.Shared` then let a private target through only inside those ranges, and only when the operator allows private targets. A job without a signed zone keeps reaching public addresses only; an unsigned `zone_ranges` field is still ignored.

### Security: shared mode and the sensor's identity scope must agree

- A sensor whose identity is enrolled with scope `instance` refuses to start
  unless shared mode is on, and shared mode refuses to start on an identity
  that belongs to an organization.

### Security: shared mode, the per-job isolation profile of a sensor that runs jobs of many tenants

- `SENSOR_SHARED_MODE=1` (or `sensorkit.Options.Shared`) requires the tool sandbox and network confinement. A sensor that sets `SENSOR_SANDBOX` or `SENSOR_SANDBOX_NETWORK` to anything weaker, or that runs on a host that cannot give both, refuses to start before it pairs. So does a shared sensor without a loaded local policy.
- `executor.Config.Shared`: a task's write paths and its `HOME`, `TMPDIR`, `TMP`, `TEMP` and `XDG_*` directories must lie beneath the task root, so no writable cache, output or configuration directory is shared between jobs. Every task directory is removed after its task.
- `core.ScanTargetPolicy.Shared` and `toolhost.Host.Shared`: a private target passes only when the operator allows private targets and it lies in the job's zone ranges. Loopback, link-local, metadata and CGNAT addresses never pass. The rule applies at admission and again to every address pinned for the task's forwarder.
- `toolhost.Host.Shared` refuses to run a tool on a backend that does not enforce every sandbox control and confine the network.

### Security: shared mode is refused when the sensor takes no platform jobs

- `SENSOR_SHARED_MODE=1` with `Options.DisableCommands` or `Options.Standalone` now fails at start with a usage error. Shared mode isolates the jobs of many organizations; a sensor that takes no platform jobs gains nothing from it and would only appear to be a shared sensor.

### Security: a shared sensor runs only instance-scope signed jobs and binds results to the job's organization

- `jobsig.Statement.SensorScope` (`sensor_scope`) and `jobsig.Binding.Shared`. An organization's sensor refuses a statement that carries `sensor_scope`. A shared sensor requires `sensor_scope` `instance` and its own `sensor_id`, and accepts any `tenant_id` (refusal reason `sensor_scope`).
- `core.NewSharedJobGuard`: in shared mode every command must carry a signed job that verifies. A shared sensor without a pinned job-signing key or root refuses to start.
- `core.JobLedger` (`CommandPollerConfig.Ledger`, `Client.SetJobLedger`): the poller holds each command while it runs it, with the organization of its verified job (`core.WithJobTenant`). The client refuses, before storing or sending, any of the following for a command it does not hold (`core.ErrJobNotHeld`): a report, a command result, a log batch, or an unsolicited push. Outbox items of a held job carry `outbox.Meta.TenantID` next to `CommandID`.

### Upgrade notes

- A sensor that sets `SENSOR_REQUIRE_SIGNED_JOBS=false` while it pinned keys at pairing now refuses to start; remove the variable. A platform URL that is `http://` to a non-loopback host must move to `https://`.

- Replace each removed package as docs/STABILITY.md listed it: the outbox through `sensorkit` (pipeline, audit); secrets declared in the tool contract (credentials); categorized tool errors in the tool contract (errors); preflight checks, the config report and the settings registry in `sensorkit` (health, metrics, options); the platform's own EPSS and KEV enrichment (enrichers); the platform's connectors module (connectors, providers).

- Drop any import of `pkg/transport/grpc` and any call to `Client.GetEPSSScores`, `Client.GetKEVEntries` or `Client.EnrichFindings`; nothing replaces them on the sensor side (the platform enriches findings on ingest).

### Removed: packages deprecated since v0.18.0

- `pkg/pipeline`, `pkg/audit`, `pkg/credentials`, `pkg/errors`, `pkg/health`, `pkg/metrics`, `pkg/options`, `pkg/enrichers/{epss,kev}`, `pkg/connectors` (with `pkg/connectors/github`) and `pkg/providers/github` are removed, with the `custom-connector` and `custom-provider` examples. They were deprecated in v0.18.0 with removal announced; nothing in the sensor, the asset collector, the Tenable.sc connector, the CI runner or the platform imports them.

### Removed: pkg/platform (routes the core never served)

- `pkg/platform` is removed. Its bootstrap registration, lease and poll clients called `/api/v1/platform/{register,lease,poll,jobs}`, which no OpenCTEM API serves, so a sensor built on them could never connect. Shared sensors of an instance enroll with `SENSOR_INSTANCE_ENROLLMENT_TOKEN` and speak the same protocol as every sensor (api RFC-100).
- The parts `sensorkit` used (the state directory, the credentials file, the key choice at start and the API key renewal client and loop) move to `internal/sensorstate` unchanged. Sensors built on `sensorkit` see no difference.
- **Upgrade note:** code that imported `github.com/openctemio/sdk-go/pkg/platform` no longer builds. There is no replacement for the platform-mode client; use `sensorkit` (or `pkg/client` with `core.CommandPoller`). `cmd/sensor-migrate` no longer covers `pkg/platform`.

### Removed: protocol v1 gRPC transport, v1 proto files and the threat-intel client calls

- `pkg/transport/grpc` and `proto/openctemio/v1` (with their buf configuration) are removed, as announced when they were deprecated: no platform serves them. `google.golang.org/grpc` is no longer a direct dependency. Sensor protocol v3 (`pkg/sensorproto/v3`) is unchanged.
- `Client.GetEPSSScores`, `Client.GetKEVEntries` and `Client.EnrichFindings` (and the `EPSSScore` and `KEVEntry` types) are removed: they called `/api/v1/threatintel/epss` and `/api/v1/threatintel/kev`, which the platform does not serve, so every call failed. The platform enriches findings with EPSS and KEV itself on ingest.
- `legacyv1.HeaderSensorID` and `legacyv1.GRPCMetadataSensorID` are removed: no route reads them. `legacyv1.FieldSensorID` stays for migrating old credentials files.

### Added: a sensor enrolls as a shared sensor with SENSOR_INSTANCE_ENROLLMENT_TOKEN

- A sensor with no identity and `SENSOR_INSTANCE_ENROLLMENT_TOKEN` set (a single-use token a super administrator issued, or one the install registered for its bundled sensor) runs the usual key-bound pairing with the token in the signed start request and is enrolled as a shared sensor of the instance, without an administrator's approval (api RFC-100 §7).
- `identity.PairOptions.EnrollmentToken`, `pairing.StartRequest.EnrollmentToken`, `pairing.Identity.Scope` (`pairing.ScopeInstance`) and `identity.Identity.Scope`. With a token the identity must be a shared sensor's (no tenant); without one, an identity without a tenant is refused.
- A refused token (`identity.ErrEnrollmentRefused`) or an expired request stops the sensor; a spent token never starts a second request. The token is never printed; it cannot be combined with `SENSOR_PAIRING_CODE`, and it is ignored (with a note) once the sensor is paired.

### Added: a job journal for crash recovery, and per-job workspaces

- `localstore.Journal` keeps one sealed record per held job and rewrites it at every step change. After a crash or a kill, `Store.Recover` returns the jobs of the earlier boot as interruptions, naming the step that was running, so the caller can report them as the command's result. Each record then stays as a tombstone (7 days by default). A step marked non-repeatable (an active check, a state-changing request) that had started is never started again for that command, even when the platform hands the command back. Journal writes go through on a critically full disk, and erasing a tenant erases its journal.
- `sensorkit/workspace` gives each job its own directory under `<root>/<tenant>/`. Every level is 0700, owned by the sensor's user, and refused when it is a symbolic link. A watch reports when a job exceeds its byte quota (2 GiB by default). The directory is removed on close even when a task made files read-only. `Sweep` removes whatever a crash left without following links out of the root, and `EraseTenant` removes an organization's directories.

### Added: the janitor, retention and cleanup for the sensor's local data (`localstore.Janitor`)

- One `localstore.Janitor` owns cleanup of every class: results the platform acknowledged are deleted at once (new `outbox.Config.OnDelivered` tells the janitor), dead letters after 7 days (`Outbox.PurgeDead`), journal tombstones after 24 hours (`Store.CompactJournal`), workspaces of jobs that are not open (`workspace.Manager.SweepBounded`), content packs by last use (`contentcache.Cache.Prune`: revoked at once, unassigned and unused for 14 days, least recently used beyond the 2 GiB cap, never one in use), a log rotation hook, and a tenant's data on `Janitor.Unassign` (crypto-erase).
- It runs at start, after a burst of acknowledgements and every 10 minutes; a pass is bounded in time (30 s) and removals (5000) and is safe to stop at any point.
- Watermarks: at 85 % of the quota or under 15 % of the volume free the cold cache is evicted, then `Janitor.AcceptsWork` turns false (stop claiming); under 64 MiB free only acknowledgements and deletions proceed. Unacknowledged results are never deleted for space.
- `Policy` carries the caps from the platform, clamped so a policy tunes cleanup but cannot switch it off. `Janitor.Status` and `Store.Usage` give bytes per class and the last sweep for the heartbeat.

### Added: an encrypted, crash-safe local store for sensors (`pkg/localstore`)

- One master key, read from a mounted secret (`Options.KeyFile`) or created next to the data, wraps a random data key per tenant. A shared sensor keeps each organization's records under its own key; `EraseTenant` deletes the wrapped key first, so a copy of the records left on a snapshot or a backup can no longer be decrypted.
- Records are sealed with AES-256-GCM and bound to their tenant, namespace and name; a record that is edited, truncated or copied over another one is quarantined, counted and reported (`OnTamper`), never returned and never a crash. Writes are atomic (temporary file, fsync, rename, fsync of the directory); a kill -9 at any point leaves the previous or the new record.
- Records may carry an expiry: once it passes, `Get` returns `ErrExpired` and no data, so scope-bearing data cached for offline work fails closed.
- `Disk` and `AcceptsWork` report the volume's free space and inodes: below the low mark a sensor stops taking new work; below the critical mark only writes marked `Critical` and deletions go through.
- A boot generation, kept in a sealed record and incremented by every start, lets the platform notice an old copy of the store being restored.
- `Sealer` gives the outbox and the content cache the same per-tenant sealing for the files they keep themselves.

### Added: relay transport for sensors that cannot reach the platform directly (`pkg/relayclient`)

- `relayclient.Transport` is an `http.RoundTripper` placed under the request signer. Each signed v2 request is sealed to the platform's ingest key (`pkg/sealedmsg`) and posted to a sensor relay. The answer comes back on the sensor's relay mailbox, signed by the platform and sealed to the sensor's key, and is returned as the request's response. The rest of the client is unchanged.
- The relay's certificate is checked against its SPKI pin from the pairing bundle (or against `RootCAs`). The sensor's identity key is the TLS client certificate, and the platform-signed ticket goes with every request; `OnTicketRefused` says when to renew it.
- Answers that do not verify, that answer no outstanding request, or that repeat one already delivered are dropped and counted. The relay's `Retry-After` is honoured. Mailbox polls back off with full jitter up to 60 s. A missing answer is `ErrNoResponse`, which callers retry like any lost response.
- Not wired into `sensorkit` yet: the mode selection, the fallback chain and the pairing bundle import come with the platform's relay connector.

### Added: end-to-end sealed envelopes for relayed sensor traffic (`pkg/sealedmsg`)

- `SealRequest` seals a sensor's ordinary signed v2 request (method, path, headers including the request signature, body) to the platform's ingest key with HPKE: hybrid ML-KEM-768 + X25519, HKDF-SHA256, ChaCha20-Poly1305. A relay, an object store or any other intermediary can delay or drop the envelope, but cannot read or change it. Moved to another sensor's or realm's mailbox, it does not open.
- `SealResponse` signs the platform's answer with its response key, binds it to the digest of the request envelope and to the route, and seals it to the sensor's encryption key. `OpenResponse` and `OpenResponseAny` check the signature against the pinned keys before parsing anything, and refuse a response for another request or sensor, one forged by the intermediary, or one more than 10 minutes off the sensor's clock.
- The request carries the sensor's encryption public key (`ReplyKey`) inside the sealed envelope; the platform seals its answer to it.
- Connection-level headers are not carried, header injection and oversize parts are refused, and keys rotate by key id (`PeekHeader`). `testdata/vector-v1.json` is the cross-implementation test vector for the platform's side.

### Added: zone rule helpers; capability shared.isolation@1

- `core.WithJobZone`, `core.JobZoneFromContext`, `core.ParseZoneRanges`, `core.CheckSharedAddr` and `core.CheckSharedPrefix` implement a shared job's zone rule. Zone ranges will come only from the job's verified signed statement. An unsigned `zone_ranges` command field is ignored, so until the statement carries ranges, shared jobs reach public addresses only.
- A sensor in shared mode advertises `shared.isolation@1` (`sensorkit.CapabilitySharedIsolation`), based on its runtime state.
- Setting `SENSOR_SHARED_MODE` (`0`, `1`).

### Changed: the version 1 outbox key is retired

- With a store, once no version 1 item is left the outbox records that in the store and then deletes the old `outbox.key` (only the default file inside the outbox directory). A fresh outbox with a store no longer creates one. A version 1 item that appears after retirement is quarantined as unreadable.

### Changed: a full outbox refuses new results instead of evicting queued ones

- The byte cap no longer evicts pending reports or command results: it evicts dead letters, then command log batches (best effort by design). When unacknowledged results alone fill the outbox, `Enqueue` returns the new `outbox.ErrFull` without writing (the client then tries to send directly, as for any disk refusal), `Stats.Refused` counts it and a warning is logged at most once a minute. A reserve of 1/50 of the cap is kept for command results, so running commands can still report their end.
- New `Outbox.AcceptsWork`: false while unacknowledged results hold 85 % of the cap or the last refused item would still not fit. `localstore.OutboxCleaner` gains `AcceptsWork`, and `Janitor.AcceptsWork` and `Status.StopClaiming` follow it: results beat new work.
- **Behaviour change:** `MaxAge` (`SENSOR_OUTBOX_MAX_AGE`) now deletes dead letters only; a pending item is kept until the platform acknowledges or refuses it.
- A janitor sweep can no longer remove a workspace that is being created (it is live before its directory exists).

### Changed: the outbox spreads its drain after the platform comes back

- `Outbox.Wake` (called when a heartbeat is accepted again) no longer starts delivering the whole backlog at once. The drain starts after one random delay of up to `min(WakeSpread, waiting items × 100 ms)`, 30 s at most by default, so a fleet that comes back after a platform outage does not send every queued result in the same second. The queue keeps its order. `outbox.Config.WakeSpread` sets the bound; a negative value drains at once.

### Changed: a release no longer opens a pull request in openctemio/openctem

- The release workflow no longer opens a `versions.yaml` pull request in openctemio/openctem (the pull request in openctemio/sensor is unchanged). The platform reads new releases from its signed release feed (openctem RFC-037 §12). Nothing changes for users of the SDK.

### Fixed: SENSOR_INSTANCE_ENROLLMENT_TOKEN is in the settings registry

- The variable was read by the kit but missing from the settings registry, so
  the config report did not list it and `docs/SETTINGS.md` and the README had
  no row for it. It is registered as a secret (never printed) and documented.

### Fixed: a shared sensor's signed jobs are verified without a tenant id

- A shared sensor belongs to no organization, so its identity has no tenant id.
  Signed-job verification now requires the sensor id only in shared mode (the
  signed statement names the organization); an organization sensor without a
  tenant id is still refused at start.

## v0.34.0 — 2026-10-15

### Security: the job's identification reaches every request, or the task is refused

- The tool host now enforces the organization's identification (`http_policy` User-Agent and headers, such as a bug-bounty program's required header) per task. Before, `Context.HTTP` only added it when the tool set no value of its own, and an exec tool received the headers nowhere: a program's targets could be probed without its required identification.
- `Task.Identity` carries it. `Context.HTTP` sets it on every request, redirects included, over what the tool set.
- An exec tool receives it through `{{http.user_agent}}` and the new `{{http.headers:-flag}}` (the flag and `Name: value` per header).
- A tool that may send HTTP to its targets and can do neither is refused (`refused_by_policy`). Port scans, host discovery and DNS lookups, and tools that reach no target, are not affected. A tool that applies it itself declares `features.http_identity` (new descriptor key).

### Upgrade notes

- Tools that receive identification-carrying jobs must pass `{{http.user_agent}}` and `{{http.headers:-flag}}` on their argv or declare `features.http_identity`; otherwise those tasks are refused.

- Replace the import path `github.com/openctemio/sdk-go/pkg/transfer` with `github.com/openctemio/ctis/transfer`; nothing else changes.

### Removed: pkg/transfer moved to ctis

- The feed transfer module `github.com/openctemio/sdk-go/pkg/transfer` (`transfer`, `transfer/bundle`) moved unchanged to the contract module `github.com/openctemio/ctis/transfer`. Bundles are byte-identical (a golden test in ctis pins them to v0.1.0). The tag `pkg/transfer/v0.1.0` stays fetchable, so existing pins keep building.
- The module-tag workflow and script are removed with it: the SDK has no nested module left.

### Added: capability http.identity@1

- `toolhost.CapabilityHTTPIdentity` (`http.identity@1`): a sensor whose tools all run through the tool host advertises it (`ToolRegistry.AddCapabilities`). The tool host sends the job's User-Agent and headers (`OrgHTTPPolicy`, for example a bug-bounty program's required identification) on every request of every tool it runs.
- The platform gates jobs that carry such identification on this capability instead of on the SDK version.

### Changed: the SDK is licensed under the Apache License 2.0

- The SDK moves from the GNU General Public License v3.0 to the Apache License 2.0, so third-party and commercial sensors, tools and adapters can import and link it without taking on the GPL's terms.
- This and every later release is Apache License 2.0. Releases published before it stay available under the GPL-3.0 they carried; nothing changes for code that already uses them.
- New `NOTICE` and `AUTHORS` files: the copyright notice is "Copyright 2026 The OpenCTEM Authors", and `AUTHORS` lists the copyright holders.
- The OpenCTEM platform and the sensor stay GPL-3.0.

### Fixed: the job's identification goes only to tasks that send HTTP to their targets

- The tool host gave every task of an identification-carrying job the organization's User-Agent and headers, including tasks it exempts: a DNS resolver, passive subdomain sources behind the egress proxy, a port scan.
  - A tool that checks the identification itself refused those tasks ("cannot send the job's identification").
  - A tool requesting through `Context.HTTP`, or an exec tool passing `{{http.user_agent}}` / `{{http.headers:-flag}}`, sent the program's identification to third-party sources.
- A task that sends no HTTP to its targets now gets none of it: `Task.Identity` is nil, and its http settings are built without the organization's User-Agent and headers. The organization's TLS rule still applies. Tasks that do send HTTP to their targets are unchanged: the identification reaches every request, or the task is refused.
- On a target-reaching tool, only `scan.ports`, `discover.hosts` and `resolve.dns` are exempt. `discover.subdomains`, `lookup.rdap` and `lookup.asn` are no longer exempt on such a tool, because it could serve them over HTTP to the targets. Passive tools stay exempt by their network class.
- New `tool.Manifest.SendsHTTPToTargets(capability)`: the rule the tool host applies, exported so a sensor can check the same thing outside the tool host.

## v0.33.0 — 2026-10-14

### Added: the scan-target guard checks each target by the scanner that receives it

- `ScanTargetPolicy.ByScanner` checks each target of a scan command by its scanner (`ScanTargetPolicy.ValidateFor`): a code scanner's path is confined to the allowed roots (relative paths in the first root), a trivy image gets its registry host checked, and every other scanner is a network scanner whose target must be a URL, host, `host:port`, address or range, a name that does not resolve being refused. `ValidateNetworkTarget` and `IsCodeScanner` are exported for checks outside the executor. Off (the default), targets are checked by their shape as before.
- A target the executor's built-in check refuses is listed in `metadata.refused_targets` with rule `target_guard` (`RefusedTargetRuleGuard`), so the platform can count the targets the sensor's target guard refused; its outcome stays skipped/refused, and the command runs on the other targets.
- A path inside an allowed scan root that is a sensitive directory (`/etc`, `~/.ssh`, ...) is refused too, as it is without roots.
- The conformance suite has a `TargetGuard` check (`SuiteOptions.GuardScanner`, `GuardTarget`): a scan mixing a good target with refused ones completes on the good one, lists each refused target with a reason and settles it skipped/refused; a scan of refused targets only fails.

### Added: run a list tool in waves of whole hosts, releasing each wave's hosts as it ends

- `core.PlanWaves(targets, network, maxWaves)` cuts a target list into at most `maxWaves` waves of whole hosts (`politeness.Group`): every target of one host is in one wave, waves are balanced by target count and keep the targets' order.
- `core.RunWaves(ctx, targets, network, maxWaves, fn, done)` runs `fn` once per wave, one after the other, and settles a wave's targets as soon as its run succeeds (`done`, or the job's `TargetDone` when nil). A failed wave and the waves after it are not settled: their targets stay unfinished and go out again, while the earlier waves keep their results. The local queue frees those hosts at once and reports them as `released_keys`, so the next tool of a pipeline starts on them while later waves run.
- For tools that report no per-target end while they run (nuclei runs every template over every host and its output gives no "host finished" signal); a tool that streams per-target results keeps calling `TargetDone` as each one ends.
- Needs ctis with `politeness.Group`.

### Fixed: `SENSOR_JOB_ID` is in the SDK settings registry

- `RegisterSDKSettings` registers `SENSOR_JOB_ID` (`EnvJobID`, group `runtime`), the variable a kit-based sensor reads to run one platform command and exit. The config report now lists it, `docs/SETTINGS.md` documents it, and a sensor started with it no longer gets a `config.env_unknown` check for it.
- Sensors that register `SENSOR_JOB_ID` themselves must drop that line when they move to this release: the registry refuses a name registered twice.

### Fixed: `openctem tool init` marks the standard params scan-scoped

- The `tool.yaml` that `openctem tool init` writes declares each of the capability's standard params (for example `ports`, `top_n`, `rate` of `scan.ports@1`) with `x-octm-scope: scan`. Without it they defaulted to the sensor scope, so a scan that set one of them was refused ("may be set only in the sensor's settings, not by a scan").
- Migration: a tool scaffolded with an earlier release adds `"x-octm-scope": "scan"` to each standard param in its `config` schema.

## v0.32.0 — 2026-10-14

### Upgrade notes

- Platforms must accept the ctis `egress_refused` class (ctis with `outcome.EgressRefused`) before sensors built on this release report it; an older platform reads such a target as unfinished and hands it out again.

- Breaking for a caller of the removed functions: drop the call; the platform already leaves suppressed and decided findings out of its views and gate.

### Behaviour change: a target the confinement kept the tool from reaching is not "done"

- When the forwarder's scope refused every connection a tool made toward a target, the tool host settles that target as failed with the class `egress_refused` (`tool.EgressRefused`, ctis `outcome.EgressRefused`) and the task is at best partial; when it refused every connection of the task, every target the tool reported done is settled so. The task log has one line with the count. `toolhost.Outcome.EgressTally` and `egress.Forwarder.Tally` give the counts per target.

### Removed: the client-side suppression filter

- `Client.GetSuppressions`, `Client.FilterSuppressedFindings` and `client.SuppressionRule` are removed. Nothing called them, and filtering on a sensor would hide matches from the platform, which decides known false positives itself (rules, triage status, gate) and must see every match to notice when flagged code changes. The wire protocol is unchanged: `GET /api/v2/sensor/suppressions`, the v3 `GetSuppressions` RPC and their types stay for platform compatibility.

### Added: offline sigstore signature check for downloaded content (pkg/blobsig)

- `blobsig.Verify` / `VerifyDigest` check a cosign keyless bundle (`cosign sign-blob --bundle`) for a file. The certificate must chain to the Sigstore public good Fulcio roots, the signature must have a Rekor inclusion proof and signed timestamp, and the certificate identity must equal the expected OIDC issuer and subject exactly. `blobsig.GitHubWorkflow(repo, workflow, ref)` builds the identity of a GitHub Actions release workflow.
- The trust root (`trusted_root.json`) is embedded, so verification needs no network. It is refreshed with SDK releases.
- New dependency: `github.com/sigstore/sigstore-go` v1.3.0.

### Added: content delivery from the platform with delta installs (contentcache, client)

- `contentcache.HTTPFetcher` gets content from the platform's sensor content routes (`/api/v2/sensor/content`): the desired-state document, packs by digest, a pack's file index, and files by sha256. `Client.ContentFetcher()` builds one on the sensor's connection and credentials.
- **Delta installs.** When the fetcher serves indexes, a new version of a pack is built from the files the cache already holds plus the changed files it fetches. The rebuilt canonical archive must match the signed digest and size, so integrity is the same as a full download, and any mismatch falls back to the full archive. Each held pack records its file index (`.openctem-index.json`); an archive may not contain that name.
- **Conditional desired state.** `HTTPFetcher.Desired` sends the last `ETag`. A 304 costs no body and reuses the last document.
- **Prefetch.** `Cache.Prefetch` syncs the desired set on a jittered schedule (±20%, with a random first run) and at once on a wake-up, so scans find their content already held.
- **Stats.** `Cache.Stats()` reports hits (held, nothing fetched), misses, delta installs, bytes downloaded and bytes saved.

### Fixed: a confined port scan reaches its target names' addresses

- A tool that resolves a target name itself through the task forwarder's DNS and dials the address it got (naabu over SOCKS5) was refused (`IP is not a target`) on every connection, so a confined port scan found nothing. The forwarder now admits the addresses an admitted name is pinned to: each address alone (never its range), with the same ports and scope limits as its names, never a metadata or link-local address. Names are still never resolved again, so a rebound DNS answer cannot move a target.

### Documentation: README matches v0.31

- The README no longer says the old `AGENT_*` names are applied with a warning: a sensor refuses to start while a removed name is set and names its replacement.
- The README describes protocol v3 (gRPC or HTTPS) as the default with v2 as fallback, lists `SENSOR_TRANSPORT`, `SENSOR_SANDBOX`, `SENSOR_SANDBOX_NETWORK`, `SENSOR_KEY_BIND` and the local-policy variables, and states the GPL-3.0 license the `LICENSE` file carries.

## v0.31.0 — 2026-10-14

### Upgrade notes

- Internal: `localQueue.setProgress` takes a callback. No exported API changed except the new `CommandProgress.ReleasedKeys` field.

### Added: a held command frees each host as soon as its targets settle

- The local queue tracks each held command's hosts with ctis `politeness.Holding`. When the job reports a target done (`Progress.TargetDone`), the hosts no pending target of it needs are freed at once. A command for the same hosts, from the next tool, is then admitted before the first command ends.
- The freed keys are reported on the heartbeat (`CommandProgress.ReleasedKeys`, `released_keys`), so the platform stops counting them as held and offers that work too.
- A freed host ends the claim backoff and wakes a poll that waits for a free slot.
- A target the command never had, or one settled twice, frees nothing. A bucket marker stays held while a pending address of its bucket does.

## v0.30.0 — 2026-10-14

### Added: pkg/source fetches one commit of a repository for a platform code scan

- `source.Fetcher.Fetch(ctx, ctis source.Repository, *Credential)` fetches exactly the requested commit, read-only, into a private `0700` directory under the scan workspace and returns a `Checkout` (`Remove` when the scan is done).
- Hardening in one place:
  - HTTPS only, to the platform-named host pinned to an address the SSRF guard accepted (`http.curloptResolve`), with no redirects;
  - no hooks, submodules, filters or system or global git configuration;
  - symbolic links checked out as plain files;
  - `transfer.fsckObjects`, and a check that the checkout is the requested commit;
  - a time limit and a size limit on disk (`ErrTooLarge`).
- The credential reaches git only as an HTTP header scoped to the clone URL, in git's environment: never in argv, the checkout or a scanner's environment.
- `AllowPrivate` lets a tenant's own sensor reach an internal SCM on a private address. Loopback, link-local (cloud metadata), CGNAT and reserved ranges are always refused. `CAFile` trusts an internal SCM's private CA. `Proxy` sends the fetch through an HTTPS proxy.

### Added: code-scan jobs fetch their repository source

- A scan command whose payload carries `source` (a ctis `source.Repository`) is a code-scan job. The executor fetches exactly that commit into the first scan-target root (a sensor without scan roots refuses such jobs), scans the checkout, reports on the repository the platform named with the source's branch and commit as a full scan, and removes the checkout. A full scan that found nothing still reports, so the platform can mark fixed findings.
- When the source names a credential, the executor asks the platform for it for this command only: `client.SourceCredential`, `POST /api/v2/sensor/commands/{id}/source-credential` under the lease epoch, v2 HTTPS (protocol v3 does not carry it). `sensorkit` wires it.

## v0.29.0 — 2026-10-14

### Upgrade notes

- Source compatible for callers: every settings identifier of `pkg/core` (and `pkg/tool`'s `DecodeConfig` / `Manifest.ConfigSchema`, which use them) keeps its name; the types are now aliases of `github.com/openctemio/ctis/settings`, which the API compatibility check reports as type changes. A sensor that mixes both names needs no edit.
- `(*core.SettingsSchema).ManifestSettings()` is removed (it was only used inside the SDK to build the manifest). Build `core.ManifestToolSettings{SchemaVersion: s.Version, Digest: s.Digest()}` if you need it.
- A tool manifest that declares a top-level `proxy`, `user_agent` or `headers` setting no longer loads.

### Removed

- `(*SettingsSchema).ManifestSettings()`: the manifest builds the schema's version and digest itself.

### Deprecated: `SENSOR_TOOLS`

- When the kit reads `SENSOR_TOOLS` itself it logs a deprecation warning: the variable only narrows the installed tools and will be removed. Narrow with the local policy's `tools.allow` instead.

### Added: `SENSOR_PAIRING_CODE` pairs a new sensor in one start

- `pkg/sensorkit`: a sensor with no identity and no API key attaches to the pairing code in `SENSOR_PAIRING_CODE` (the code an administrator created with "expect a sensor") on its first start, so reverse pairing needs no separate `pair` command. The code is validated before any request (a malformed one stops the sensor with exit 2), is a secret in the settings registry, and is never printed: the pairing instructions name the variable instead. Once the sensor is paired, or when it has an API key, the variable is ignored with a note and can be removed.

### Added: layered tool settings in the command executor

- A scan command may carry `settings_layers: {tenant, sensor}`: the administrators' tool settings, covered by the job signature. The executor checks each layer against the tool's own schema and resolves, in order: the tool's defaults, the tenant's and the sensor's layers, the scan's config (declared keys), the job's decision and the local policy. An invalid layer, a key a layer may not set, or a raise of a narrowing option fails the command.
- The job's decision reaches every tool through its common options (`x-octm-common`): the command's rate and concurrency (never above the value in force: the tool's default or what an administrator set), and the per-target budget as the tool's per-request timeout (budget ÷ (retries + 1), at least 2 s, never longer than the timeout in force). The local policy's `rate.max_rps` lowers the common rate (source `local`).
- The result's metadata says what ran: `effective_settings` (each key's value and the layer that set it).

### Changed: a tools allowlist no longer drops sensor-wide built-ins

- `pkg/sensorkit`: new `ScannerOption` `Builtin()` marks a scanner that is part of the sensor itself (the reachability probe, compiled-in passive lookups). `Options.Tools` / `SENSOR_TOOLS` no longer drop such scanners from the inventory; the local policy's `tools.allow` still narrows them.

### Changed: tool settings come from the CTIS contract

- `pkg/core` settings types (`SettingsSchema`, `SettingProperty`, `ToolSettings`, `SettingsLayer`, `SettingsErrors`, scopes, sources) are now aliases of `github.com/openctemio/ctis/settings`, so the platform validates administrators' values with the same code the sensor runs. The golden vectors moved to ctis (`settings/testdata/vectors`).
- New from the contract: `x-octm-common` (a manifest key is a common tool option: `timeout`, `rate`, `concurrency`, `retries`; type and bounds checked) and `x-octm-flag` (the tool's native flag, display only); top-level `proxy`, `user_agent` and `headers` keys are refused; layers `SettingSourceTenant` and `SettingSourceJob`; a later layer that raises a narrowing option (`rate`, `concurrency`, `retries`) an earlier layer set is an error.

## v0.28.0 — 2026-10-14

### Added: liveness counters in the heartbeat's command progress

- `core.CommandProgress` carries `records`, `output_bytes` and `cpu_ms` next to `done`/`total`/`finished`: the records the tool host accepted for the job and their bytes, and the CPU time of the job's tool processes with the processes they start (read from `/proc` on Linux; 0 elsewhere). All are monotonic for the job and left out while zero.
- `pkg/sensorkit/toolhost` counts each accepted record (`core.RecordOutput`) and tracks the tool process (`core.TrackProcess`); `core.ExecuteScanner` / `StreamScanner` track the scanner process.
- The platform calls a task stalled only when none of these and the settled targets moved for its stall window, so a slow but working batch tool is not taken back. The counters are hints: they can delay a stall decision, never a task's overrun or a run's cap.

### Added: the platform can ask for what a stalled task finished

- A heartbeat answer may carry `stop_command_ids`: held commands the platform asks the sensor to stop and complete with what they finished (the task stalled). The poller cancels the run with `core.ErrStoppedByPlatform`; the tool host treats it like a stop by the job's own budget (the settled targets' records are delivered, the task ends `partial` with the rest in `unfinished_targets`), the executor parses and pushes under a context the stop does not end, and the result is reported, not released. A run that settled nothing is reported failed, and the platform re-queues it.
- `cancel_command_ids` is unchanged: a canceled command delivers nothing and is released.
- Needs the heartbeat doorbell (on by default); a sensor without it ignores stops, and the platform re-queues the task after a grace period.

### Added: per-target outcomes in the command result

- A completed scan command's result carries `target_outcomes`: one entry per target of the job, in the ctis `outcome` contract (`done`, `failed` with `unreachable` / `timeout` / `tool_error`, `skipped` with `refused` / `excluded`, `unfinished`). The platform settles every target with an outcome and hands out only the unfinished ones again, instead of rerunning the whole task.
- `pkg/sensorkit/toolhost`: a run that delivers (ok or partial) writes the same list into the report's `target_outcomes` property, from each target's settled state and error class, plus the unfinished targets of a run that stopped part-way. A failed or canceled run carries none.
- `pkg/core`: `TargetOutcomes` builds the list from a report (explicit outcomes, `unfinished_targets`, `failed_targets`; any other target of the run is done). Targets a policy refused before the run are `skipped`/`refused`; a target the scan-target policy rewrote (a resolved path) is named by the payload's own value.
- `pkg/testkit`: `Normalize` removes the `target_outcomes` property (the tool host's stamp, absent in-process).
- ctis bumped to the version with the `outcome` package.

## v0.27.0 — 2026-10-14

### Removed: the `github.com/openctemio/sdk-go/pkg/politeness` module

- The per-host politeness keys are part of the CTIS contract now: `github.com/openctemio/ctis/politeness`, with the same API and keys. The platform imports them from ctis, so it no longer depends on the SDK. The nested module was never tagged and nothing outside OpenCTEM imported it; import `github.com/openctemio/ctis/politeness` instead.

### Changed: a tool run that stops part-way keeps the targets it finished

- `pkg/sensorkit/toolhost`: a task that stops after the tool settled at least one target (the tool crashed, reported a failure, went silent past its idle timeout, or hit a time limit) now ends `partial` instead of `failed`. The records the runtime accepted are delivered, and the targets the tool never reached are listed in `Outcome.Unfinished` and in the report's `unfinished_targets` property; the report's coverage is `partial`, so nothing is auto-resolved from targets that were not scanned. A cancel (the platform took the task back, or the sensor is stopping), a policy refusal and rejected output still fail the task as before.
- A task stopped by the job's own time budget (its context's deadline) is reported as a `timeout`, not a cancel, so the rule above applies to it.
- `pkg/core`: when the job's time budget stops a scan that still returns results, the command executor parses and pushes them under the job's context without the expired budget, instead of failing the push. A cancel still ends the job and pushes nothing.

### Changed: the command poller takes its politeness keys from ctis

- `pkg/core` (the poller's per-host admission, and the deprecated `core.HostKey`) uses `github.com/openctemio/ctis/politeness`. The keys and the admission behaviour are unchanged.

## v0.26.0 — 2026-10-13

### Security: scan jobs carry their exclusions; ranges are cut address by address

- A scan job's payload may carry `exclusions` (addresses, CIDR prefixes, `first-last` ranges): the platform's scope exclusions that touch the job's targets, covered by the job signature (api RFC-088).
- Before any other check, `LocalPolicy.AdmitCommandTargets` walks each range target (at most 2^16 addresses) and leaves out every address that the job's exclusions, `targets.deny` or the built-in deny list covers; the range is replaced by the smallest prefix set of the addresses kept. This also runs on a sensor without a policy file.
- An address target the job excludes is removed (rule `job_exclusions`); a job with nothing left, or a single-target job whose target would be cut, fails; an unreadable exclusion refuses the job.
- New `ScanOptions.ExcludeHosts` hands the exclusions to tools that can skip hosts themselves.

### Behaviour change: a range that overlaps `targets.deny` or the built-in deny list is cut, not refused whole

- Up to 2^16 addresses, such a range now runs on the addresses outside the deny entries. Wider ranges are still refused whole.

### Behaviour change: the sensor admits a command under the platform's politeness keys

- The command poller's per-host politeness uses the keys the platform sent with the command (`host_keys`, the keys it admitted the command under and holds while it runs). A command sent with an empty list (a passive stage, which sends no traffic to the target) is never held back for a busy host. A command from an older platform without `host_keys` is keyed by `pkg/politeness`, the function the platform uses.
- Keys conflict as on the platform: the same host, or an address and a range scan of its /24 (IPv6 /120) bucket; two addresses of one bucket no longer hold each other back, and an address and a range covering it now do.
- Sent keys are bounded (at most 500, each at most 512 bytes). `network_id` in the payload scopes the computed keys of private addresses and names (api RFC-089).
- This ends the claim/hand-back loop seen on live sensors ("its hosts are busy on this sensor"): the sensor no longer refuses work the platform has just offered for a host the two keyed differently.

### Deprecated: `core.HostKey`

- Use `github.com/openctemio/sdk-go/pkg/politeness` (`HostOf`, `Keys`). `HostKey` now returns `politeness.HostOf`: the host of any URL other than a `.git` clone URL is the host alone (was `host/first-path-segment` for paths of two or more segments), and a scheme-less `host/path` is the host.

### Added: discover.hosts@1 in the capability taxonomy and its conformance suite

- ctis is bumped to the taxonomy with `discover.hosts@1` (host discovery: light liveness probes on addresses and ranges, T1; out `ip` with `properties.live_by`), so tools can implement it.
- The tool conformance suite gains an active `discover.hosts@1` suite: a loopback address answering on one port, probed on that port, must be reported live with the probe that answered, and nothing the tool was not given may be reported.
- New `core.LiveHostsReport`: the host discovery mechanism a tool wrapper calls. It turns a port probe's report into the capability's report (each answering address of the job's targets as a live `ip_address` with `properties.live_by` = `tcp:<port>`, nothing else). `core.ErrNoProbePorts` is what a wrapper answers for a job without probe ports: the platform names them in every host discovery job, a sensor never picks its own.

### Added: one definition of the per-host politeness keys (`pkg/politeness`)

- New nested module `github.com/openctemio/sdk-go/pkg/politeness` (standard library only, tagged `pkg/politeness/vX.Y.Z`): which hosts a scan job touches and when two jobs touch the same host. A name, the host of a URL or a service, an address with the marker of its /24 (IPv6 /120) bucket, and a range with one key per bucket each have a key; an address and a range scan of its bucket conflict, two addresses of one bucket do not.
- Network context (api RFC-089): with a network id, the keys of private, shared, loopback and link-local addresses and of names end in `#<network>`, so overlapping private ranges at two sites are two sets of hosts; public addresses are never scoped to a network. A network id that cannot be read leaves the keys global.
- The platform imports this module so it computes the same keys it holds and sends with a job (api RFC-090). The sensor runtime moves onto it in a follow-up change.

### Added: per-target and per-task budgets, and per-command progress on the heartbeat

- `ScanCommandPayload.Budget` (`TaskBudget`: `target_seconds`, `task_seconds`,
  `stall_seconds`) carries the platform's layered budget. Every value is
  clamped (a target budget to 1 s – 1 h, a task to 1 min – 24 h).
- `ScanOptions.TargetTimeout` is the per-target budget: a tool wrapper passes
  it as the tool's own per-request or per-host timeout flag.
- `core.RunPerTarget` runs one function per target with that budget, bounded
  concurrency, a reach `timeout` outcome for a target that exceeds it, and the
  finished targets kept when the job's context ends. One unresponsive host
  costs one target budget instead of holding up the whole task.
- Without an explicit `timeout_seconds`, a job's context ends at twice its
  task budget, so a slow but progressing task is not cut at its estimate.
- Every scan job has a `core.Progress` (`core.TargetDone(ctx, target)`); the
  heartbeat reports each held command's progress (`done`, `total`, and the
  finished targets as `finished` index ranges into the command's target list,
  up to 256 ranges) to a platform that lists the `command_progress` feature,
  so it can tell a slow task from a stuck one and settle finished targets one
  by one.
- A tool run through the tool host counts each target it settles toward the
  job's progress, so out-of-process and sandboxed tools report progress too.

## v0.25.0 — 2026-10-13

### Added: `net.confined@1` capability and a network-confinement setup check

- `executor.CapabilityNetConfined` (`net.confined@1`) names the capability a sensor advertises when every tool it runs for a job is network-confined to the task's forwarder. The platform sends jobs that need confinement (a web scope, scope limits) only to a sensor that advertises it. A sensor advertises it from its runtime's status (`Status().NetworkEnforced` with tools out of process), never from a setting.
- The config report has a new check, `runtime.sandbox_network`: `confined` (pass), or a warning with the detected cause: `userns_blocked` (the container runtime's seccomp profile refuses user namespaces: run with the sensor's seccomp profile), `userns_restricted` (the host restricts unprivileged user namespaces: keep the default AppArmor profile), `off` (`SENSOR_SANDBOX_NETWORK=off`), `sandbox_off` (`SENSOR_SANDBOX=off`) or `unavailable`. The platform's setup checklist explains each code and its fix.

### Added: the sensor describes its network in the manifest

- New package `pkg/netctx`: what the host owner declares (`SENSOR_NETWORK_SITE`, `SENSOR_NETWORK_REACH`, `SENSOR_NETWORK_DNS_SUFFIXES`, `SENSOR_INTERNET` = auto|direct|proxy|none) and what the SDK detects (on-link prefixes without container bridges, routing table, resolvers and search domains, the address the platform's egress echo saw), with a fingerprint that changes when the sensor moves. A sensor built on `sensorkit` gets it without code.
- The manifest carries it as member `network`, only to a platform that lists the `network` hello feature (`protov2.FeatureNetwork`); the kit detects again every 5 minutes and a changed report registers the manifest again. `client.EgressEcho` calls `GET /api/v2/sensor/egress-echo`; the conformance fake serves it (`FakePlatform.SetNetwork`).
- The report is never wider than the local policy: with `targets.allow` only prefixes inside it are named (narrowed or dropped, counted in `trimmed`); `targets.deny` ranges, and private ranges when private targets are refused, are not named. `SENSOR_NETWORK_REPORT` = summary (default: private prefixes listed, public counted) | full | off (fingerprint and internet mode only). Detection makes no network call besides the echo: no cloud metadata, no LAN scanning.
- An egress check that fails is reported as `unknown`, never `none`; `none` comes from the declaration or from a routing table without a default route.
- New preflight checks `network.egress`, `network.dns_view` and `network.declared_vs_detected`. `core.LocalPolicy.NetworkScope` and `core.BaseSensor.SetNetworkReporter` are new.
- A value of the new settings the SDK cannot use stops the sensor (exit code 2), naming the setting.

### Added: `core.RetryAfterHinter`

- An error that carries the platform's advised wait. `client.V2Error` (the error of every protocol v2 call, the command poll included) implements it (`RetryAfterHint`).

### Added: every job result says which targets the sensor could not reach

- New package `pkg/reach`: `Classify(err)` maps an error toward a target to `reached`, `port_closed` (the path works, the port is closed), `no_route`, `firewall_refused`, `timeout` or `dns_failure` (Linux, macOS and Windows socket errors, IPv4 and IPv6, DNS errors); `ClassifyText` does the same for a tool's per-target failure text. `Recorder` collects a job's outcomes; a target that answered once is reached.
- The command poller gives every job a recorder (`reach.FromContext`); the guarded dialer (`LocalPolicy.DialContext`) and a confined task's forwarder record every dial toward a target (never a vendor host or a destination the policy refused), and a scanner or output parser can record its own. The result metadata carries `reach` (counts per class and per /24 or /64 block and port class, at most 512 rows), `unreached_targets` (at most 100) and `unreached_targets_total`. An executor that sets `reach` itself keeps it.
- A scan with an unreached target reports `partial` coverage, so what it did not report on that target is not read as "no findings". `toolhost.Outcome.Reach` holds a confined task's summary.

### Added: polite reach probe and its conformance suite

- `reach.Probe(ctx, guard, targets, opts)` tests whether this sensor reaches a job's targets: one TCP connect per (address, port) from 443, 80, 22 until one answers, no payload, no ICMP, 2 s per connect. It dials only through the sensor's guard (`core.LocalPolicy` satisfies `reach.Guard`): every target is checked again, a range address by address, and only the address literals the guard returns are dialed. Bounds that options cannot raise: 10 connects per second, 256 addresses, 8 ports, one connect per address at a time; a large range the guard refuses is not walked to its end. Without a guard it refuses to run.
- `conformance.RunReachSuite(t, prober)` checks a sensor's probe with a recording dialer: never an address outside the admitted set (literals, ranges with a denied address inside, names resolving outside, IPv6, link-local, metadata), the rate, size and per-address bounds, classes, an unroutable target reported unreached, and cancellation. `conformance.SDKReachProber` runs it on `reach.Probe`.

### Added: retest commands carry the job's web scope

- A `retest` command's `web_scope` (as on a scan command) now reaches the tool's retest task (`tool.Task.WebScope`). The tool host enforces it: on a sandbox that confines the network, the task forwarder checks every request, and a tool that does not declare `features.web_scope` is refused. An invalid scope fails the command before anything runs. Before, the field was dropped, so the platform had to refuse retests of findings on hosts with a path exclusion.
- Conformance: `RunContractSuite` runs a web-scoped retest (`Retest/web_scope`) for a tool that declares `features.retest` and `features.web_scope`, and fails when the tool requests a denied path. `LintDescriptor` warns about a networked retesting tool without `features.web_scope`.

### Fixed: `SENSOR_CA_FINGERPRINT` can pin a root the platform does not send

- A pinned CA fingerprint was accepted only when the server sent that certificate in its TLS chain. The built-in gateway (internal TLS) sends the server certificate and the intermediate, not the root whose fingerprint the console shows, so pinning that root refused every connection.
- When the pinned certificate is not sent, the chain is now verified against the API trust (`SENSOR_CA_CERT_FILE`, else the system trust store) and accepted only when a verified chain contains the pinned certificate. Name, validity and usage are still checked; a trusted CA other than the pinned one (an interception proxy, a second CA in the file) is still refused.
- Operators pinning the gateway root: put the root in `SENSOR_CA_CERT_FILE` as well as its fingerprint in `SENSOR_CA_FINGERPRINT`.

### Fixed: a collector no longer reports "No scanner is available"

- A sensor that adds no scanner and runs its collectors on its own schedule (platform commands off), or one with collectors only, no longer reports the failing `tools.available` check (`none`, blocks scans). A collector needs no scanner. A sensor that takes platform commands with no collector, or that added scanners, still reports it.

### Fixed: target names are never looked up with a search domain appended

- A host resolver with search domains (`search lan` from DHCP, copied into containers) made a tool's resolver also ask `<target>.lan` when a target did not resolve. The forwarder logged these lookups as refusals (`egress refused app.example.com.lan (dns)`), and under a public-internet scope they could be resolved upstream.
- A confined task's `/etc/resolv.conf` names only the relay and has no search list (unchanged, now tested). The SDK's own target lookups (the forwarder, the tool host, the local policy and scan-target checks) use absolute names, with a trailing dot.
- The forwarder answers a search-domain variant of a name that is not a target NXDOMAIN, never resolves it, and does not record it as a refusal (`egress.Forwarder.SearchDomains`, `egress.SearchDomains`).
- The doctor reports `network.dns_search` (information only) when the host resolver has search domains.

### Fixed: a request the web scope refuses no longer breaks the connection

- The task forwarder answered a refused request with a 403 and closed the connection. HTTP tools then saw EOF or a reset on kept-alive and pipelined requests and counted them toward their per-host error budget. A few refused templates could make nuclei skip the whole host, allowed paths included.
- A refused request now gets a complete 403 (`X-Openctem-Egress: refused`, `Content-Length`), its body is read and discarded (never sent upstream, at most 1 MiB), and the connection stays open for the next request, which is checked the same way. This applies in clear and on the TLS-terminated path.
- The connection still closes after a refusal that is not a request to this destination (CONNECT, an upgrade, another `Host` or port), a body over 1 MiB, `Expect: 100-continue`, the client's `Connection: close`, and protocol errors and non-HTTP traffic. The absolute-form proxy path keeps one request per connection.

### Fixed: versioned sensor-wide capabilities are reported

- The tool registry dropped any capability with `@` in its name, so `scope.limits@1` and `net.confined@1` never reached the platform: a confined sensor was never given the jobs that need confinement or scope limits. Capability names may now contain `@`.

### Fixed: a command handed back is no longer claimed again in a tight loop

- A command the sensor handed back (its hosts busy here, no free slot, a type it does not serve) became claimable again, the platform rang the doorbell and the same command was claimed and released about twice a second. After a poll that only hands commands back, `CommandPoller` now waits 1 s, doubling to at most 1 min (`core.MinClaimBackoff`, `core.MaxClaimBackoff`) with jitter, before polling again; doorbell rings in that time poll once it is over. A command that ends on the sensor, or a poll that starts one, ends the wait, so a command waiting for a busy host still runs as soon as the host is free.
- A poll the platform refuses with `Retry-After` (429/503) is not repeated before it, whatever wakes the poller, capped at 5 min (`core.MaxPollRetryAfter`).

### Fixed: `SENSOR_SANDBOX_NETWORK=required` is checked before pairing

- A sensor without an identity paired first and only then refused to start because this host cannot confine a tool's network. `sensorkit.New` now checks the requirement before pairing, so the platform does not admit a sensor that cannot run.
- Added `sensorkit.ValidateSandboxNetwork`: the same check for a program's own pair command.

## v0.24.0 — 2026-10-13

### Security: the task forwarder enforces the job's web scope

- On a sandbox that confines the network, a task with a web scope has every connection read as HTTP by its forwarder (`egress.Scope.Web`, set by the tool host from `tool.Task.WebScope`): TLS is terminated with the forwarder's per-task authority, each request (redirects included) is checked with `webscope.Scope.Allows` as the server reads its path, and a request outside the scope is refused with a 403, recorded and never sent. Non-HTTP traffic to a target of such a task is refused.
- A tool whose own requests do not follow the scope (a template scanner) can now take web-scoped jobs when it runs confined.
- The conformance kit's `vuln.templates` suite checks a tool that declares `features.web_scope` with `/.env` denied.
- `webscope.Scope.Allows` refuses a path a server that drops path parameters reads as denied (`/;/admin`, `/x/..;/admin`): both readings, with and without parameters, must pass. `CleanPath` refuses a dot segment with parameters and a control character.

## v0.23.0 — 2026-10-12

### Upgrade notes: every sensor setting is SENSOR_-prefixed; old names are refused

- Renamed: `API_URL` → `SENSOR_API_URL`, `API_KEY` → `SENSOR_API_KEY`, `REGION` → `SENSOR_REGION`, `PLATFORM_KEY_AUTORENEW` → `SENSOR_KEY_AUTORENEW` (`sensorkit.EnvAPIURL`, `EnvAPIKey`, `EnvRegion`, `EnvKeyAutoRenew`).
- `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` are no longer read as aliases.
- One switch for private scan targets: `SENSOR_ALLOW_PRIVATE_TARGETS`. `OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS` is gone (`core.EnvAllowPrivateTargets` is a deprecated alias of `core.EnvSensorAllowPrivateTargets`), and the SDK's egress switch `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE` no longer widens scan targets. The SDK no longer honors the API's `OPENCTEM_HTTPSEC_ALLOW_PRIVATE`.
- `sensorkit.MigrateLegacyEnv` (run by `New`) refuses every removed name (`sensorkit.RemovedEnv`) with exit code 2, naming the replacement and never the value. Rename them in `.env` files, compose files, systemd units and Helm values before upgrading. The `-agent-id` flag is still migrated.

### Deprecated: sensorkit CI runner mode (CIRun)

- `sensorkit.CIRun`, `NewCIRun`, `CIRunConfig`, `CIRunConfigFromEnv`,
  `DetectCIOIDC`, `CIVerdict` and `WriteVerdict` are deprecated. The sensor no
  longer runs in CI (sensor v0.11.0); CI scanning is the `openctem-ci` runner
  (repository openctemio/ci), which also handles aggregate runs and the Azure
  Pipelines, Bitbucket, CircleCI and Jenkins identities. Nothing in the sensor
  calls these identifiers; they are removed in a later minor release.

## v0.22.0 — 2026-10-11

### Added: one data volume for the sensor's state, outbox and content

- `sensorkit.DefaultDataDir` (`/var/lib/openctem`): sensors mount one
  persistent volume there, holding `state/`, `outbox/` and `content/`. The
  persistence check already judged a directory by its nearest mount, so a
  volume at `/var/lib/openctem` counts for the state directory (now tested);
  a volume on each subdirectory keeps working.
- The kit creates the state directory 0700 when it is missing (a bind mount
  or a Kubernetes volume does not get the image's directories), narrows a
  looser mode to 0700, and warns when another user owns it, with the
  `chown` to run.
- New config check `storage.outbox_persistent` (`persistent`,
  `not_persistent`, `unknown`): an outbox off any volume loses undelivered
  results when the container is recreated. A state directory or outbox off
  any volume is also said on the sensor's log at start.

## v0.21.0 — 2026-10-11

### Behaviour change: a confined task's rate toward each target host adapts

- The task forwarder paces each destination host with an additive-increase,
  multiplicative-decrease controller (`pkg/adapt.HostRate`): a host starts at
  a quarter of the ceiling, doubles per clean 2-second window up to it, then
  grows by a tenth of the ceiling per clean window; 429 and 503 halve it (at
  most once per window) and `Retry-After` is honored per host (connections are
  held up to 10 s, refused for longer waits); resets, timeouts, refused
  connections on a port that answered before, failed TLS handshakes and a run
  of 20 consecutive 403s after other answers count as failures or a block.
- The ceiling is the lowest of every limit: the tool's rate param (the scan's
  `rate_limit`, already lowered by scan windows, program rules and the local
  policy), `RunOptions.TargetRate`, and the local policy's `rate.max_rps`,
  which now also caps the connection rate of tools without a rate param. The
  rate never goes above the ceiling and never below 1 request per second.
- Five consecutive failures open a host's breaker for 15 s (doubling, ±20 %
  jitter), then one probe is let through; after three trips the host is given
  up for the task. Closed or filtered ports never count, so port scans are
  not slowed.
- Hosts the task could not fully cover (`breaker_open`, `rate_floor`,
  `blocked`) do not fail the task: they are listed in `Outcome.TargetRate`,
  `ScanResult.CoverageGaps` and the command result metadata
  (`coverage_gaps`, `coverage_gaps_total`, `target_rate`), and the scan's
  report declares partial coverage, so findings on those hosts are not
  auto-resolved. Every rate change and its reason is logged to the task.
- All bounds live in one table, `adapt.TargetRate`.

### Added: protocol v3 gRPC binding on the platform's own port (ALPN routing)

- The gRPC binding's client offers the ALPN id `openctem-sensor/3` next to `h2` (`client.SensorALPN`). A platform gateway with ALPN routing passes such a connection through to the API's mTLS listener on the platform's own port, so gRPC works with an IP address or a single host name and no extra port (openctem api RFC-059 §5). The listener still negotiates `h2`; the id routes, it does not authenticate (the client certificate and the pinned sensor CA are unchanged).
- `protov2.TransportV3.GRPCALPNEndpoint` (`grpc_alpn_endpoint` on the v2 hello): the endpoint reached by offering the id. The client prefers it over `grpc_endpoint`. Platforms name the single-port endpoint only there, so older clients, which would meet the gateway's own certificate and stop (`platform_certificate_refused`), stay on the HTTPS binding.
- `conformance.FakePlatform.RouteV3GRPCByALPN` and `V3OfferedALPN` emulate the gateway's routing in sensor tests.

### Fixed: a platform restart no longer drops a sensor from protocol v3 to v2

- A negotiation whose hello gets no answer (a platform restart, a gateway
  502, a network error) used to be read as "the platform has no v3": the
  sensor moved to v2 and stayed there until the next recheck. Now a working
  v3 binding is kept, and the negotiation is retried after about 30 seconds.
  An HTTPS-binding hello answered `unavailable` is treated the same way.
- A sensor with no binding yet that gets no answer stays on v2 with the new
  reason `platform_unreachable` (instead of `platform_without_v3`) and asks
  again after about 30 seconds.

## v0.20.0 — 2026-10-11

### Security: bearer-key sensors move to a key-bound identity by themselves

- A daemon started with an API key, against a platform whose hello lists `key_bind`, makes its own Ed25519 key in `<state dir>/identity/` (0600 in 0700), binds it with one call authenticated by the API key (`Client.BindKey`, `POST /api/v2/sensor/identity/bind`, with a proof of possession) and signs every request from then on. The platform retires the API key in the same step (one way); the sensor keeps its id, tenant and grant.
- An identity in the state directory now wins over a configured `API_KEY` (the sensor warns to remove it).
- The key and a marker are written before the call; if the answer is lost, the next start binds the same key again or confirms it with a request signed by that key.
- A refusal (the organization requires an administrator's approval, or the sensor cannot bind) removes the generated key; the sensor keeps its API key and says to re-pair it.
- `SENSOR_KEY_BIND=off` keeps the API key. A bearer-key sensor now sends one extra hello at start.

### Upgrade notes: `pkg/transfer` is its own Go module

- `pkg/transfer` and `pkg/transfer/bundle` moved into a nested module, `github.com/openctemio/sdk-go/pkg/transfer`, released as `pkg/transfer/vX.Y.Z` (first: `pkg/transfer/v0.1.0`). Import paths are unchanged.
- A consumer requires `github.com/openctemio/sdk-go/pkg/transfer` instead of `github.com/openctemio/sdk-go`. A build that requires both the new module and an `sdk-go` version that still contains `pkg/transfer` (v0.19.0 and earlier) fails with "ambiguous import": drop the `sdk-go` require, or require an `sdk-go` release made after this change.
- `transfer.New` now refuses a URL origin without `Config.Client`; there is no unguarded default client. Pass an SSRF-guarded client such as `httpsec.SafeHTTPClient(0)`. A fetcher with local (directory) origins only needs no client.

### Changed: the transfer module depends on the standard library and the Prometheus client only

- The DSSE envelope, pre-authentication encoding and key id are restated in `pkg/transfer/bundle`, byte-identical to `pkg/jobsig`; one golden vector in both test suites keeps them together. Envelopes signed before and after this change verify the same way.
- CI runs tests, build, vet, `go mod tidy -diff`, golangci-lint and govulncheck for the nested module; **Release Module Tag** (`.github/scripts/release/tag-module.sh`) tags it.

### Changed: protocol v3 remembers a failing gRPC binding and never downgrades on an identity refusal

- A gRPC network failure (unreachable, handshake, HTTP/2 refused, stream reset, unimplemented) is kept in the certificate directory (`transport-v3-state.json`, 0600): negotiations and restarts within the backoff go straight to the HTTPS binding with the same reason, and gRPC is tried again after 30 minutes, doubling per consecutive failure up to 4 hours (from `ReprobeInterval`). A success clears it.
- A platform that does not offer gRPC (or v3) yet, a certificate or HTTPS-binding failure is asked again within 10 minutes instead of 30, so sensors move up soon after the platform's path is fixed.
- An identity refusal no longer leaves the client on v2: it sends nothing but hello and the heartbeat (a paused sensor still learns it is paused) until a later negotiation is accepted.

## v0.19.0 — 2026-10-11

### Security

- The mapping file is part of the contract:
  - it must be a regular file inside the manifest's directory (no symlink, no `..`), of at most 256 KiB;
  - a bad mapping file refuses the tool at load;
  - a mapping file changed after load, or a missing one, refuses the task before the tool starts.
- The mapping language is closed (paths, constants, templates, a fixed set of transforms, bounded RE2 predicates; no code). It is bounded by the task's output limits.
- The report's tool is always the manifest's, never one the output claims.
- Output in a named format goes through the hardened, fuzzed `ctis/importer` parsers and then through the same record checks as any tool output: CTIS validity, declared outputs and limits.

- A capability job sent to a scanner that cannot apply it fails. This covers a job carrying a capability, params or a tier ceiling. Its settings are never dropped silently.
- The executor refuses:
  - malformed capability references, including a ref without its major and look-alike case;
  - params without a capability;
  - an unknown tier;
  - more than 64 params, or a param over 16 KiB.
- The platform derives a tool's trust level from `origin`, which the sensor sets from how the tool was loaded, never from the tool's own claim.

- The kit runs a tool under test only through the runtime's host and sandbox, as a sensor would. Its fixtures listen on loopback only, and nothing is reached beyond them.
- Scope check: the tool is given one target while another address listens. Any connection to that address fails the check.
- `secrets.code@1` plants fresh fake credentials and fails when a raw value reaches the report or the logs, in any field.
- `diff` treats these as breaking changes that need a major version bump:
  - narrowing what a tool takes or emits;
  - raising its tier or adding a side effect;
  - adding a required config key.

- Each of these is `invalid_input` before anything starts:
  - a standard param the tool does not map;
  - a value outside the capability's enum or the tool's narrowed values;
  - an integer outside either bound;
  - a malformed port list;
  - a config key that the task also sets to another value;
  - params without a capability;
  - a capability the tool does not implement.

  Nothing is dropped silently.
- A tool's minimum tier is the highest of its declared tier, the capability floors, and T2 for any side effect. When it is above the job's `max_tier`, the task is `refused_by_policy` before it starts.
- The local policy's rate cap applies whatever the workflow asked.

- A manifest is refused when it:
  - implements a capability outside the taxonomy (matched exactly), or a reserved one;
  - declares a tier below a capability's tier floor;
  - declares side effects without tier T2;
  - consumes an asset type no implemented capability takes, or produces an output none may emit;
  - maps a param to a missing or mistyped config key, or widens a standard param's values or bounds.
- With `implements` set, the old `capabilities` list may only repeat its ids.
- `MinimumTier` is the highest of the declared tier, the capability floors, and T2 for any side effect. The platform may assign a higher tier, never a lower one.
- Display strings are refused when they contain control or bidirectional-override characters. Icons come from a closed set, never a URL. `docs_url` must be https without credentials. `engine.version_probe` refuses shells and placeholders.

### Security: a task can no longer read another task's files

- The process sandbox hid only the sensor's protected paths, so a task could read and list the directories of the tasks running beside it (on a shared sensor, another tenant's checkout and tool output). The task root (`executor.TaskRoot()` and the backend's `WorkRoot`) is now hidden from every task; a task reads and writes only its own directory and the paths it is given.
- The tool host's protocol directory moved from `$TMPDIR/openctem-tool-*` to the task root (`executor.NewTaskDir`).
- A task root must be a directory owned by the sensor's user: a symbolic link or another user's directory is refused, and an owned one is closed to other users (0700).

### Security: the SSRF guard refuses IPv6 ranges that translate to IPv4

- `pkg/httpsec` also hard-blocks four IPv6 ranges that carry an IPv4 address:
  - NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`;
  - 6to4 `2002::/16`;
  - Teredo `2001::/32`.
- On a network with NAT64/DNS64, a name that resolved to `64:ff9b::a9fe:a9fe` reached the cloud metadata address `169.254.169.254` through the translator.
- `192.0.0.0/24` and `198.18.0.0/15` are refused too.
- The table matches the platform's copy (api `pkg/httpsec`), which the platform's security lint compares line by line.

### Security: sensors pin the job-signing root and accept signer keys from its signed, expiring key set

- A sensor can pin the installation's offline job-signing root (api RFC-040 §5.6 K3) instead of the online signer key. The platform's hello serves the current key set (`signed_jobs.keyset`): a DSSE envelope signed by the root listing the online keys, with a version and an expiry at most 30 days out. Job signatures are then accepted only from keys of the current, verified key set (and from keys in `SENSOR_JOB_SIGNING_KEYS`), so a signer key is rotated or revoked by a new key set, without pairing the sensor again.
- `pkg/jobsig` verifies a key set against the pinned root before it parses it further: payload type `application/vnd.openctem.keyset.v1+json`, strict decode, the root's Ed25519 signature over the exact bytes, not expired (2-minute skew), version never lower than the accepted one and the same version only with the same bytes. The accepted key set is kept in `<state dir>/job-signing-keyset.json` (fsync before use), so a rollback is refused across restarts too.
- The key set is fetched from hello at start, before the next job check when the doorbell's `config_version` moves, and when a job's key is not in it (at most every 30 seconds). With a root pinned and no valid key set (none, expired or refused), signed jobs are refused with rule `job_keyset`; a key the key set no longer lists is refused with rule `job_signature`. The sensor warns 7 days before expiry; the posture adds `jobs.root`, `jobs.keyset_version` and `jobs.keyset_expires_at`.
- Pairing pins the root of the key set the hello serves (`identity.json` `job_signing_root`, trust on first use), only when the key set is signed by it and current. A root pinned at pairing makes signed jobs required, and the online keys pinned at pairing are then not used.
- New setting `SENSOR_JOB_SIGNING_ROOT` (the root's `SHA256:<hex>` key id or base64 key; overrides the root pinned at pairing). The local policy schema is unchanged (v1 is frozen).
- New API: `jobsig.KeySet`, `KeySetTrust`, `NewKeySetTrust`, `KeySetConfig`, `KeySetSource`, `VerifyKeySet`, `TrustOnFirstUse`, `ParseRoot`, `ReasonKeySet`, `KeySetPayloadType`, `KeySetKind`, `Config.KeySet`, `Verifier.KeySet`; `core.RefusalRuleJobKeySet`, `JobGuard.SetConfigVersion`, `SetJobsKeySet`, `JobsPosture.Root/KeySetVersion/KeySetExpiresAt`; `protov2.SignedJobs.KeySet`; `identity.Identity.JobSigningRoot`; `sensorkit.Options.JobSigningRoot`, `EnvJobSigningRoot`, `JobSigningKeySetFile`, `KeySetWarnBefore`.

### Security: golang.org/x/net v0.60.0 (GO-2026-6617, HTTP/2 HPACK encoder race)

- govulncheck found the vulnerable symbols reachable through net/http; the module is bumped, and CI builds and checks with Go 1.26.9 (GO-2026-6611/6612/6613/6617 in net/http).

### Security: new sensors fail closed without a local policy

- A sensor that requires a sensor-local policy and has none refuses every job with a network target (URL, host, IP, CIDR, image reference), custom templates and out-of-band callbacks before any tool starts: `refused by local policy: no_local_policy: ...`, with the refusal rule `no_local_policy`. Jobs without network targets (repository and filesystem scans, health checks, collectors, content refresh) keep running, and the kill switch still applies.
- A sensor requires a policy when `SENSOR_REQUIRE_LOCAL_POLICY=true`, or, with the variable unset, when its key-bound identity was paired by this SDK: pairing now writes `"require_local_policy": true` into `identity/identity.json` (`identity.Identity.RequireLocalPolicy`). `core.LocalPolicyOptions.Required`, `LocalPolicy.Required`, `LocalPolicy.WithRequired` and `sensorkit.ResolveRequireLocalPolicy` expose it.
- Without a policy, `LocalPolicy.CheckTarget` now applies the built-in deny list (loopback, link-local and `169.254.169.254`, multicast, unspecified, CGNAT, reserved, private unless the private-range switch) instead of allowing every target, so a retest or tool task that checks its targets directly cannot reach them.

### Security: the platform TLS identity is pinned at pairing

- Pairing over HTTPS records the platform's TLS identity in `identity/identity.json`: `"platform_tls_pin": "sha256:<hex>"` with `"platform_tls_pin_element": "anchor_spki"` (the SHA-256 of the SubjectPublicKeyInfo of the trust anchor of the chain the pairing verified, so leaf and intermediate renewals by the same CA keep working while any other CA is refused), or `"ca_cert"` when `SENSOR_CA_FINGERPRINT` was set at pairing (it wins and is stored). Every request of one pairing must lead to the same anchor.
- Every platform client the SDK builds (protocol v2, the v3 HTTPS binding, the gRPC certificate requests) enforces the stored pin, with no fallback to the system roots: `platform certificate does not match the pin stored at pairing; re-pair or set SENSOR_CA_FINGERPRINT`. `SENSOR_CA_FINGERPRINT` overrides the stored pin. A malformed stored pin stops the sensor.
- Protocol v3: the gRPC CA bundle is sticky. A different bundle replaces it only over a pinned channel (the gRPC binding, or the HTTPS binding under a platform TLS pin); an endpoint change alone never does. A gRPC certificate that does not verify against the bundle is a hard error (`platform_certificate_refused`, `client.ErrPlatformCertificate`): nothing is sent on any binding until gRPC verifies again. `SENSOR_TRANSPORT=grpc` no longer drops to the HTTPS binding or v2, also when the platform lists no protocol v3.
- `posture.platform_tls.pin` reports `fingerprint` when a stored pin is enforced.
- New API: `identity.Identity.PlatformTLSPin`, `PlatformTLSPinElement`, `Identity.TLSPin`; `httpsec.SetAPIPinnedSPKI`, `APIPinnedSPKI`, `HasAPIPin`, `PinRecorder`, `NewAPIClientRecordingPin`, `AnchorSPKI`, `FormatFingerprint`, `PinElementAnchorSPKI`, `PinElementCACert`, `ErrPlatformPinMismatch`, `ErrPlatformChangedDuringPairing`; `client.ErrPlatformCertificate`, `client.ErrCABundleChanged`, `client.ReasonPlatformCertificate`.

### Security: port- and path-limited targets are enforced outside the tool (pkg/scopelimit)

- A signed job statement can carry `limits` (`jobsig.Statement.Limits`, `scopelimit.Limit`): for each target the organization's scope covers only through a port-limited or path-limited entry, the allowed ports, protocol and URL path prefix, as the platform's job signer holds them in its ledger. The verifier checks every limit names one of the statement's targets and is well formed (`ReasonLimits`). A verifier that predates the field refuses such a statement (unknown field), so a limited job never runs unlimited on an older sensor.
- The limits reach the scan only from the verified statement (`ScanOptions.Limits`, `tool.Task.Limits`), never from the payload. A scanner that does not implement `core.ScopeLimitScanner` refuses a job with limits (`RefusalRuleScopeLimits`); contract tools (`toolcompat`) implement it.
- The tool host refuses a task with limits on a sandbox that does not confine the network, and for a tool whose network class reaches more than its targets (vendor, egress proxy).
- The task's egress forwarder enforces them: a connection to a limited host (or address) on another port is refused; on a port whose limits name path prefixes, every HTTP request is read (TLS is terminated with a per-forwarder authority, `Forwarder.AuthorityPEM`) and refused with `403` and a `http-path` record when its Host is not the destination or its path is outside the prefixes. Paths are compared after percent-decoding and dot-segment removal, case sensitive; an encoded `/` or `\`, a backslash, NUL, an invalid escape and `..;` segments are refused. Protocol upgrades and non-HTTP/1.x traffic to such a port are refused.
- A sensor that enforces limits advertises `scope.limits@1` (`scopelimit.Capability`) in its manifest.

### Security: a secret scanner's raw match no longer survives in the title or other fields

- The adapters (`betterleaks`, `sarif`, `trivy`), `core.SARIFParser` and `importtool` run on `github.com/openctemio/ctis` with `RedactSecretFinding`. A secret that a scanner repeats in its message, description, commit message, tags or properties is masked there too, not only in the snippet. Before, a SARIF snippet holding the whole code line, or a leak record with only a match line, left the bare secret in the finding title.
- The tool runtime's output rules (`internal/toolrt`, applied on both sides of the process boundary) mask any secret finding whose snippet or masked value a tool left unmasked, and the same value wherever another field repeats it.
- `pkg/ctis` re-exports `RedactSecretFinding` and `ContainsSecret`.

### Security: custom templates are trusted through the signed job

- The job statement (`jobsig.Statement`) gains `templates`: the SHA-256 of
  every custom template the payload carries, in order. `jobsig.Verify`
  refuses a statement whose list differs from the payload's (new reason
  `templates`, helpers `jobsig.PayloadTemplateDigests` and
  `jobsig.TemplateDigest`).
- When a command's signed job verified, its custom templates run without
  `SENSOR_TEMPLATE_SIGNING_KEYS`: the platform's job signer names a template
  only when its digest is approved in the signer's scope ledger (api
  RFC-040 P2). The executor compares the decoded templates with the
  verified list before writing them. The local `allow_custom_templates`
  gate and the template validation still apply.
- Sensors without signed jobs keep the per-tenant manifest path
  (`SENSOR_TEMPLATE_SIGNING_KEYS`), now a fallback planned for removal.

### Security: a tool no longer receives another tool's credentials from the environment

- Every tool task got every bundled tool's environment namespace: `TRIVY_*`, `SEMGREP_*` (incl. `SEMGREP_APP_TOKEN`), `PDCP_*`, `NUCLEI_*`, `DOCKER_HOST`, and others. That included a program the operator installed from outside the project. A tool, or a hostile template it loads, could read another tool's credentials.
- `core.ScannerEnvironFor(tool, extra...)` passes a namespace only to the tool it belongs to. The tool host uses it: a compiled-in tool gets its own namespace, and an operator-installed tool gets none (its credentials come from its manifest, in the run message).
- Unchanged:
  - variables the caller passes;
  - names the operator allows (`OPENCTEM_SDK_SCANNER_ENV_ALLOW`, `core.SetScannerEnvAllowlist`);
  - inherit mode;
  - the legacy `core.ExecuteScanner` path.
- Upgrade note: an operator-installed tool that read a vendor variable from the sensor's environment must declare it as a credential, or the operator must allow the name explicitly.

### Security: credentials in log text are masked

- Every command log line's text is now also masked for credentials a tool prints about its targets:
  - `Authorization`, `Cookie` and `Set-Cookie` header values;
  - `key=value` or `key: value` pairs (JSON-quoted keys included) whose key names a secret (token, api_key, password, secret, session);
  - the user info of URLs.
- This comes on top of the existing masking of the sensor's key, tool secrets and secret-named fields. The platform redacts again.

### Security: confined tool tasks reach only their targets, through their own forwarder

- Where the sandbox confines the network (`executor.Config.ConfineNetwork`), the tool host starts a forwarder (`pkg/sensorkit/egress`) for every task whose manifest network is not `none`. Its sockets live in a task directory no task can read. The scope follows the manifest's network:
  - `targets`: the admitted targets, names at the addresses the local policy admitted (`core.LocalPolicy.AdmittedAddrs`), never resolved again;
  - `vendor`: the vendor hosts at public addresses;
  - `egress-proxy`: any public address.

  Every destination is recorded in `Outcome.Egress`. Each refusal is a warning in the task's command log.
- sensorkit turns confinement on by default: `SENSOR_SANDBOX_NETWORK=auto` (where user namespaces are available; otherwise a warning), `required` (refuse to start without it; for shared sensors) or `off`. `openctem tool run|test` do the same (`OPENCTEM_SANDBOX_NETWORK`), and `--scope` reports every destination the task's forwarder refused.
- The forwarder now refuses the cloud metadata addresses outside link-local (`168.63.129.16`, `100.100.100.200`, `fd00:ec2::254`). It also gained `Scope.AnyPublic` and `ServeDNSStream`.
- DNS for an admitted name: A and AAAA come from the scope. Other record types (CNAME, MX, TXT, NS, ...) are asked of the sensor's upstream resolver (`Forwarder.Upstream`, `egress.UpstreamDNS`) and passed back only when the answer matches the question. An unadmitted name is never asked upstream.
- A confined task with a forwarder also gets `OPENCTEM_EGRESS_PROXY` (`executor.EnvEgressProxy`), the relay's proxy URL, for wrappers whose tool takes a proxy flag rather than the proxy variables.
- Upgrade notes:
  - A tool that dials raw sockets instead of honouring the proxy variables gets "network unreachable" when confined.
  - A sensor container needs a seccomp profile that allows user namespaces for confinement; without one it runs as before, with a warning.

### Security: the paired identity directory is a protected path of the tool sandbox

- No tool may read the identity directory (the signing key, the protocol v3 client certificate and pinned CA).

### Security: sensors verify the platform's signed jobs before they run them

- New package `pkg/jobsig` verifies the job signer's DSSE envelope (api RFC-040 §5.6): Ed25519 over the pre-authentication encoding of the exact statement bytes with a pinned key (indexed by its recomputed `SHA256:<hex>` id), then a strict v1 statement bound to this sensor's organization and id, the command's id, type and lease epoch, the SHA-256 of the payload bytes as received and the tool and targets that payload names, issued within 2 minutes and not expired (at most 1 hour), a nonce not seen before and a sequence number above the last accepted from that key, persisted with fsync in `<state dir>/job-signing-seq.json` before the job is accepted.
- `core.CommandPoller.SetJobGuard` checks every command right after its claim, in claim order, before the start transition, the local policy, the command gate and the executor. With a pinned key the poller claims through `core.CommandClaimer` (`client.ClaimCommand`) so it verifies the claim answer's payload, signed job and lease epoch. A command that fails, or comes unsigned to a sensor that requires signed jobs, is failed with a structured refusal (layer `builtin`, rule `job_signature`) and never run. `Kit.RunJob` checks the claimed job the same way.
- Pairing reads the platform's hello right after the confirmation and pins the job signer keys it lists in `identity.json` (`job_signing_keys`, trust on first use over the pinned and signed pairing connection). A sensor whose identity pinned keys requires signed jobs.
- New settings: `SENSOR_JOB_SIGNING_KEYS` (key ids `SHA256:<hex>`, resolved through the hello, or base64 Ed25519 keys; added to the keys pinned at pairing) and `SENSOR_REQUIRE_SIGNED_JOBS` (`true`/`false`; unset: required when the identity pinned keys). Both need a paired (key-bound) sensor; `SENSOR_REQUIRE_SIGNED_JOBS=true` without a pinned key stops the sensor at start.
- The manifest's posture reports `jobs.signed`: `required`, `verified_when_present` or `off`.
- New API: `jobsig` (`Verifier`, `Keys`, `ParseKeys`, `Statement`, `Envelope`, …); `core.JobGuard`, `NewJobGuard`, `CommandPoller.SetJobGuard`, `CommandClaimer`, `Command.SignedJob`, `EnvRequireSignedJobs`, `RequireSignedJobsFromEnv`, `RefusalRuleJobSignature`, `JobsPosture`, `SetJobsPosture`; `client.Command.SignedJob`; `protov2.Command.SignedJob`, `Hello.SignedJobs`, `SignedJobs`, `SignedJobKey`, `FeatureSignedJobs`; `identity.Identity.JobSigningKeys`; `sensorkit.Options.JobSigningKeys`, `EnvJobSigningKeys`, `ResolveRequireSignedJobs`, `JobSigningStateFile`.

### Security: jobs can carry a web scope that the SDK enforces

- A job (`ScanCommandPayload.web_scope`, `tool.Task.WebScope`) can carry a web scope (`pkg/webscope`). It names:
  - the hosts a web tool may request (`*.example.com` covers the domain and every name under it);
  - the path prefixes it may request, and the paths it never requests (`deny_paths`);
  - the methods it may use (GET, HEAD and OPTIONS when none are named).
- `tool.Context.HTTP` refuses every request outside the scope, redirects included. The path is checked as the server sees it: decoded, with dot segments resolved. A path with an encoded slash, backslash or NUL is refused.
- A networked tool must declare `features.web_scope` to take a job with a web scope; otherwise the job is refused (`refused_by_policy`). An invalid scope is refused, never ignored, and a scanner that cannot take capability jobs fails such a job.
- Exec-profile tools read the scope from the new `{{task.web_scope_file}}` placeholder.
- The conformance kit's new `crawl.web` and `dast.web` suite fails a tool that requests a denied path, or that does not declare `features.web_scope`.

### Upgrade notes

- Nothing changes for a sensor without a root pin. A sensor paired from this release with a platform that serves a key set pins its root. To move an existing sensor to the root, set `SENSOR_JOB_SIGNING_ROOT` to the root key id the installation owner recorded (`openctem-signer root keygen` printed it).
- Once a root is pinned, the platform must keep a current key set deployed and renew it before `not_after`: an expired key set makes the sensor refuse every signed job until a new one is served. Keep `<state dir>/job-signing-keyset.json` on the persistent state volume.

- Existing paired sensors and bearer-key sensors are unchanged (legacy, with a start-up warning) until they set `SENSOR_REQUIRE_LOCAL_POLICY=true` or pair again. A sensor paired with this release, or re-paired, refuses network jobs until `/etc/openctem/sensor-policy.yaml` is installed or `SENSOR_ALLOWED_RANGES` is set; `SENSOR_REQUIRE_LOCAL_POLICY=false` keeps the legacy behavior on purpose.
- A legacy sensor without a policy now refuses built-in-denied targets (metadata, loopback, private without the switch) on paths that called `CheckTarget` directly, as the scan executor already did.

- `core.OrgHTTPPolicy` is no longer comparable with `==` (its new `Headers` field is a map). Code that compared two policies compares their fields instead; nothing in the SDK or the sensor does.

- Existing paired sensors are unchanged (pin `none`, with a start-up warning) until they pair again or set `SENSOR_CA_FINGERPRINT`. Sensors paired with this release pin automatically; to move one to a platform behind another CA, pair it again or set `SENSOR_CA_FINGERPRINT`.
- A sensor that already holds a gRPC CA bundle (`transport-v3-platform-ca.pem`) and has no platform TLS pin refuses a different bundle sent over HTTPS: it stays on the HTTPS binding in auto mode (reason `certificates_unavailable`) with a log line. Pair again, set `SENSOR_CA_FINGERPRINT`, or remove that file to accept the new bundle. Rotations sent over the gRPC binding are accepted as before.
- `SENSOR_TRANSPORT=grpc` sensors that relied on the silent drop to v2 or HTTPS now send nothing until the gRPC binding works; use `auto` for fallback.

- Replace `adapters/<tool>.NewAdapter().Convert(ctx, data, opts)` with `importer.Parse(ctx, bytes.NewReader(data), importer.Options{Format: importer.Format<Tool>, ...})` from `github.com/openctemio/ctis/importer`. The result is the same CTIS, with the importer limits applied. `core.SARIFParser` already uses it. For a tool you run, prefer the exec profile with `run.output.format: <tool>` (no code).
- `examples/custom-adapter` now shows the importer.

- `pkg/scanners/tenable` is removed. Nothing in the sensor, the platform or the asset collector imported it. Convert `.nessus` exports with `github.com/openctemio/ctis/importer` (`importer.Parse` with format `nessus`), which reads the same NessusClientData_v2 format with credential redaction and the CTIS limits.

- `settings.DocsBase` changed value (a page URL with a trailing slash; the
  anchor is still `#<NAME>`). Code that only calls `Setting.DocsURL()`
  needs no change; code that built links from `DocsBase` itself gets the new
  page.

- ctis is now at CTIS 1.5: reports the SDK builds are stamped `"version": "1.5"`. No new 1.5 member is emitted yet, so receivers on CTIS 1.4 (any minor of major 1 is accepted) read them unchanged.

- **A networked tool's `fixed` on a finding now needs the attempt's HTTP exchange.** The runtime keeps `fixed` only when the verdict carries an `http_exchange` evidence item whose response arrived; otherwise the verdict is `unverifiable`. Tools without network (code scanners) and asset retests are unchanged. Report retest verdicts with `ctx.Report` and the exchange. A sensor should bump to this release together with the evidence its retest tools emit.
- `tool.Emitter` gained `Endpoint` and `tool.RetestContext` gained `Report`. Only the runtime implements them, so a tool needs no change; a test double that implements either interface must add the method. `tool.RetestVerdict` is no longer comparable with `==`, because it holds evidence.
- `ctis.SchemaVersion` is `1.6`. Reports keep validating at every older version.

- Existing sensors are unchanged (`jobs.signed: off`, unsigned jobs run) unless they set `SENSOR_JOB_SIGNING_KEYS` or `SENSOR_REQUIRE_SIGNED_JOBS`, or pair again with a platform that signs jobs; a sensor paired from this release with such a platform requires signed jobs. To require them on an existing paired sensor, set `SENSOR_JOB_SIGNING_KEYS` to the signer's key id (`openctem-signer pubkey`) and `SENSOR_REQUIRE_SIGNED_JOBS=true`.
- The platform signs jobs only when the API has `SIGNER_SOCKET` set and the separate `openctem-signer` runs (openctem `deploy/docker-compose.job-signer.yml`). A sensor that requires signed jobs refuses every command of a platform that does not sign them.
- Keep `<state dir>/job-signing-seq.json` on the persistent state volume; a corrupt file stops the sensor rather than accept old jobs again. A new signer key is pinned by updating `SENSOR_JOB_SIGNING_KEYS` or pairing again (rotation through a signed key set is not built yet).

### Upgrade notes: older SDKs refuse statements with templates

- A sensor on an earlier SDK that verifies signed jobs refuses a statement
  carrying `templates` (unknown field), so jobs with custom templates fail
  on it until it is upgraded. Jobs without custom templates are unchanged.

### Behaviour change: a refused scan target no longer fails the whole job

- A scan job target that the sensor-local policy refuses, or cannot check, is removed from the job, and the job runs on the other targets. "Cannot check" means the name does not resolve or the target is a wildcard pattern. The same applies to the executor's own check before the scanner starts.
- The command completes with `metadata.refused_targets` (`{target, reason, rule, detail}`, at most 100), `metadata.refused_targets_total` and `metadata.partial: true`. Reasons: `unresolvable`, `wildcard_pattern`, `denied_by_policy`, `invalid_target`.
- The command still fails when every target is refused, or when the single target of a single-target job is refused. The error lists the targets.
- Retest and validation commands still refuse the whole job when one target is refused.
- An address the policy cannot check is still never scanned. A refused target never reaches an executor or a tool.

### Behaviour change: `*.x` in the sensor-local policy covers `x` itself

- A `targets.allow` or `targets.deny` entry `*.x` now covers `x` and every name below it, at any depth. It used to cover only the names below `x`. This matches the platform's scope patterns (api RFC-054 §4.1).
- Allow lists: a policy with `*.example.com` now also admits `example.com`. To keep the apex out, add `example.com` to `targets.deny`.
- Deny lists: `*.example.com` in `targets.deny` now also refuses `example.com`. A policy that relied on the old reading to scan the apex while denying its subdomains must deny the subdomains it means instead.
- Patterns and hosts are compared case-insensitively, without one trailing dot, and in IDNA ASCII form: an upper-case or internationalized entry now matches the names it spells.

### Removed

- `pkg/scanners/tenable`: the deprecated Nessus REST client and `.nessus` converter.

### Removed: pkg/adapters (deprecated)

- The deprecated tool adapters `pkg/adapters` and `pkg/adapters/{betterleaks,nuclei,sarif,semgrep,trivy,vuls}` are removed (about 3,600 lines), together with the internal `importbridge` that ran them. Neither the sensor, the platform nor the asset collector imported them. Every tool output is now parsed by one library, `github.com/openctemio/ctis/importer` (OpenCTEM Tool Contract v1, decision TC5).

### Deprecated

- `capabilities` in tool.yaml and `Builder.Capabilities`: use `implements` / `Builder.Implements`. The top-level `retest` key is the older spelling of `features.retest`; a manifest may set one, not both.

### Added: `sensorkit/contentcache`, the sensor's content pack cache (api RFC-061 K3)

- Packs are addressed by digest.
- **Before a pack is stored:**
  - the downloaded bytes must hash to the digest;
  - the platform's DSSE statement must verify against an operator-pinned key: the tenant content key, naming this sensor's organization, or the platform content key;
  - the statement must name the same digest;
  - the archive must pass the canonical rules again (regular files only, clean relative paths, caps).
- Packs are unpacked read-only under `<root>/packs/sha256-<hex>/`, and the root is private (0700).
- **Using packs:**
  - `Acquire`/`Release` hold a pack per task;
  - `Resolve` sets a task's pack paths from the cache and replaces any path a job sent.
- `Sync` installs the desired set (two downloads at a time) and purges revoked digests, refusing them from then on. It drops least recently used packs outside the desired set while the cache is over its budget; a pack in use is never removed.
- `testdata/platform-vector.json` pins the platform's archive, statement and envelope format.

### Added: content slots — a tool declares its templates, rules and wordlists; tasks get read-only packs

- `tool.yaml` `content:` declares the content a tool reads (api RFC-061), slot by slot:
  - `kind`: a known one (`nuclei-templates`, `semgrep-rules`, `yara-rules`, `vuln-db`, `wordlist`, `signatures`) or a namespaced `x-<vendor>/<kind>`;
  - `format`, `default`, `modes` (default, custom, merge), `selectors`.
- A task carries `content` per slot: packs by `sha256:` digest with the path the sensor's cache resolved. A tool reads them through:
  - `task.ContentPaths(slot)` in Go;
  - `task.content_paths(slot)` in the Python helper;
  - `run.task.content` for adapters;
  - `{{content.<slot>}}` / `{{content.<slot>...}}` in exec argv.
- Isolation:
  - `executor.Config.Private` hides more roots (the content cache) from every task, and `TaskSpec.ReadPaths` grants a task read-only access to exactly its packs;
  - `toolhost.Host.ContentRoot` and `tool.CheckTaskContent` refuse a pack outside the cache, an undeclared slot, an unsupported mode or selector, and a non-digest.
- `openctem tool run --content slot=dir` hands a local directory to a slot for development.
- Delivery of packs from the platform (desired state, prefetch, pin at dispatch) follows.

### Added: pkg/sensorkit/egress, the per-task forwarder; the scope check records every destination

- `egress.Forwarder` serves HTTP CONNECT, absolute-form HTTP and SOCKS5 on a listener the caller gives it, and answers DNS queries (`AnswerDNS`, `ServeDNS`). For every connection it:
  - checks the destination against the task's `Scope` (admitted names at their pinned addresses, never resolved again; admitted prefixes; vendor hosts at public addresses only; metadata, link-local, multicast and unspecified addresses always refused);
  - applies a token-bucket rate per task and per host;
  - records the destination, verdict and bytes.

  DNS answers only admitted names; anything else gets NXDOMAIN. Experimental; it is the forwarder of api RFC-060 (per-task network confinement) and RFC-034 (egress profiles).
- `openctem tool test --scope` runs the tool with its proxy variables pointing at a recording forwarder whose scope is the task's targets. A request through the proxy for anything else fails the check and names the destination. A tool that fetched an outside URL used to pass.

### Added: zero-code tools for any JSON CLI and for every ctis importer format

- An exec-profile tool can write `json` or `jsonl` output with a mapping file:
  - `run.output: {format: jsonl, from: stdout, mapping: mapping.yaml}`;
  - the mapping uses the declarative language of `ctis/importer/mapping`, in JSON or YAML;
  - the runtime turns each record into CTIS, and the tool needs no code.
- An exec-profile tool can also write a named format of `ctis/importer`: `nuclei`, `semgrep`, `trivy`, `betterleaks`, `gitleaks`, `grype`, `zap`, `vuls`, `cyclonedx`, `spdx`, `osv`, `csaf`, `openvex`, `nessus`, `qualys`, `defectdojo` (`tool.ImporterFormats`).
- `LoadManifestFile` loads the mapping file and records its digest in `run.output.mapping_digest`, which the manifest digest covers. `tool.LoadMappingFile` loads a mapping file on its own.
- Parser and mapping issues appear in the outcome's logs, at most 10.

### Added: exec tools take list, optional and switch settings in run.argv

- Besides `{{config.k}}`, an exec tool's `run.argv` may use:
  - `{{config.k?}}`: the argument is left out when the key is not set, empty or false;
  - `{{config.k...}}`: an array key, one argument per item, or comma-joined inside a larger argument; left out when empty;
  - `{{config.k?:-flag}}`: a boolean key, the flag only when true.

  Before, a list param (`record_types`, `tags`) could not reach a CLI at all, and an unset key became an empty argument. Every value keeps the flag-injection and dangerous-flag checks.
- `openctem tool validate` (and the kit's lint) warns when an exec tool maps a capability param onto a config key that no argument uses: the tool would accept the param and ignore it.
- `tool.ConfigArg` and `tool.ArgvPlaceholders` parse the placeholders.

### Added: per-task network confinement in the process sandbox (opt-in)

- `executor.Config.ConfineNetwork` runs every task in its own user, network and mount namespaces (api RFC-060). Only loopback exists inside, and the task's way out is its forwarder: `TaskSpec.EgressProxy` and `EgressDNS` are the forwarder's unix sockets. The task sees a proxy on `127.0.0.1:1080` (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, set whatever the caller passed) and a resolver on `127.0.0.1:53`, or on each address `/etc/resolv.conf` names where the file cannot be bind-mounted. With no sockets, a confined task has no network at all.
- The launcher creates the namespaces itself: it re-executes as the inner launcher, because the sensor is non-dumpable and could not write the new namespace's id maps. The tool runs as the inner launcher's child, on the confined thread (`no_new_privs`, Landlock and seccomp are inherited), with no capabilities (`SECBIT_NOROOT` locked, empty bounding set).
- `Status.NetworkEnforced` is true only when the probe proved confinement works; otherwise `Status.NetworkMissing` names the reason (user namespaces refused by the container seccomp profile or the host AppArmor restriction) and tasks run unconfined. `Config.RequireNetwork` makes that an error instead (for shared sensors).
- Off by default: nothing changes until a caller sets it. The tool host, sensorkit and the CLI turn it on in a follow-up.

### Added: `transfer` and `transfer/bundle`, chunked signed feed transfer (api RFC-070)

- `transfer.Fetcher` downloads from ordered origins (release URL, mirrors, a local directory):
  - retries with exponential back-off and jitter; Retry-After on 429/5xx, capped (a longer wait moves to the next origin);
  - per-attempt and overall deadlines, a stall guard, and Range resume of a partial download;
  - conditional GET (ETag) for pointers;
  - a circuit breaker per origin; 404 and hash mismatches move to the next origin at once;
  - every request through the SSRF-guarded client by default; file names are one path element.
- `Blob` keeps content-addressed files in `<cache>/blobs`, verified against sha256 and size before they are stored, so chunks shared by two releases are fetched once.
- `bundle.Writer` writes format v2: gzip JSON Lines chunks named by their digest, with content-defined boundaries from record ids, and a signed manifest per snapshot or delta. `bundle.WritePointer` signs the pointer that pins the manifests.
- `bundle.Consumer` verifies the key set, pointer, manifest pin, signature and caps before any chunk. It then applies chunk by chunk, each through the `Applier` in its own transaction, with a durable `Checkpoint`:
  - a crash resumes at the next chunk;
  - an older sequence is refused;
  - a partial bundle is never marked applied;
  - a delta is used only on top of its base.
- `FileCheckpoint` (0600) is included. Prometheus counters are exposed through `Register` on both types.

### Added: posture report

- `local_policy.required` (`true`/`false`) on every heartbeat and manifest: `absent` with `required: false` is a legacy install without a policy.
- The manifest member `posture` (sent to a platform that lists the new hello feature `posture`): `platform_tls.pin` (`fingerprint`, `ca_file`, `none`) and `sandbox` (`mode`, `sandboxed`, `network_enforced`). `core.SensorPosture`, `core.CurrentPosture`, `core.PlatformTLSPin`, `BaseSensor.SetPosture`; the kit sets it.
- The config report's `policy.local` check fails with code `required_absent` while a required policy is missing. The new setting `SENSOR_REQUIRE_LOCAL_POLICY` is registered.

### Added: per-target admission and the poller's lines in the command log

- `LocalPolicy.AdmitCommandTargets` returns a `CommandAdmission` with the refused targets. It also rewrites the payload of a scan job. `AdmitCommand` keeps refusing the whole job.
- Added `core.RefusedTarget`, the `RefusedTarget*` reasons, the `Meta*` keys and `RefusedTargetsMetadata`.
- `CommandPoller.SetCommandLogSink` (`core.CommandLogSink`) writes the poller's own lines to the command's log, tagged `source: sensor`. They cover: received, the policy check with each refused target and its reason, a refusal before running, the tool gate, the outcome (completed, partial, failed, timed out, kill switch) and a hand-back (no free slot, busy hosts, drain).
- `sensorkit` wires its log shipper as that sink, so a command refused before any tool started still has a log saying why. Its lines are queued ahead of its result. A hand-back line is sent directly before the release.
- The log shipper continues a command's batch sequence across finishes. The platform keeps the first batch of each number, so a restarted sequence was dropped.

### Added: the sensor manifest carries each tool's full descriptor; scan jobs carry their capability

- `core.ToolContract` gains two fields:
  - `Descriptor`: the tool's full manifest in canonical JSON. Its SHA-256 is `Digest`, and it is left out above 64 KiB.
  - `Origin`: `builtin` for a tool compiled into the sensor, `adapter` for one the operator installed.

  Both travel in the sensor manifest, which is registered only when it changes. Heartbeats carry only the manifest digest, so their size is unchanged.
- A tool on the contract reports the capability ids it implements (`scan.ports`) as its capabilities, beside its older capability words.
- `ScanCommandPayload` gains `capability` (`scan.ports@1`), `params` (the standard params) and `max_tier`, and `ScanOptions` carries them.
- A `core.CapabilityScanner` (`TakesCapabilityJobs`) receives these job fields. A `toolcompat` scanner whose manifest implements a capability is one, and it hands them to the tool runtime, which maps the params and checks the tier.

### Added: tool network permission `resolver`

- A target-scan tool may declare `permissions.network: resolver`: DNS questions about its targets only, answered through the sensor's resolvers, and no connection to any host, the targets included. It is the network of a DNS resolution tool that never contacts the target hosts (a passive, T0 step).
- Under network confinement the task's forwarder answers DNS for the admitted targets as it does for `targets`, and refuses every connection (`egress.Scope.DNSOnly`). Targets are admitted against the local policy as for `targets`. The executor network class is `resolver`; `tool.Context.HTTP` reaches nothing.
- The tool descriptor JSON schema accepts `resolver`.

### Added: the `openctem tool` CLI and the conformance kit for the tool contract

- New command `cmd/openctem` with six `tool` subcommands (reference in `docs/tools/cli.md`):
  - `init --kind exec-sarif|exec-ctis|exec-json|go|python --capability <id@major>` scaffolds a tool from the capability. The scaffold passes `openctem tool test` as written.
  - `validate` checks the descriptor; errors carry JSON pointers.
  - `run` runs one task offline, through the sensor runtime.
  - `test` runs the conformance kit.
  - `diff` checks the version bump of a descriptor change.
  - `describe --json` prints the canonical descriptor and its digest.
- `openctem-conformance tool` is now an alias of `openctem tool test`, kept for one minor release.
- New in `pkg/conformance`:
  - `LintDescriptor`;
  - `RunContractSuite`:
    - every fixture is checked against the contract of each implemented capability;
    - per-capability suites on loopback fixtures cover `scan.ports@1`, `probe.http@1`, `vuln.templates@1`, `secrets.code@1`, `sast.code@1` and `sca.deps@1`;
    - the scope check;
  - `FuzzOutput` fuzzes the parser of an exec tool's output format;
  - `DiffManifests` gives the semantic version bump a descriptor change needs.
- CI templates `ci/github/openctem-tool.yml` and `ci/gitlab/openctem-tool.yml`, with actions pinned by commit.

### Added: the job HTTP policy carries headers

- A scan job's `http_policy` can now carry `headers` (`core.OrgHTTPPolicy.Headers`). These are headers the platform requires on every request of the job's tools, for example a bug-bounty program's identification header (api RFC-065).
- At most 10 headers. Names must be tokens and values printable ASCII of up to 200 bytes.
- The tool host merges them after the manifest: each replaces a `tool.yaml` header of the same name, whatever its case.
- Refused names:
  - credentials: `Authorization`, `Cookie`, `Proxy-*`;
  - headers the HTTP client and the forwarder own: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, and similar.
- A policy that breaks these rules fails the job.

### Added: the organization's HTTP policy narrows its tools' requests (job `http_policy`)

- A scan job can carry `http_policy: {user_agent, allow_insecure_tls}` (`core.OrgHTTPPolicy`, `ScanCommandPayload.HTTPPolicy`).
- The tool host merges it after the sensor-local policy:
  - its User-Agent applies unless the local policy forces one;
  - `allow_insecure_tls: false` refuses, with `refused_by_policy`, a tool whose `tool.yaml` skips TLS verification;
  - it never allows what the local policy forbids.
- An invalid policy fails the job. The tool sees only the effective settings (`task.http`).

### Added: openctem_tool.py, a Python helper for tools

- `openctem tool init --kind python` writes `openctem_tool.py` next to the tool: one file, standard library only, that speaks adapter protocol v1. The tool writes only `run(ctx, task)`. The helper provides:
  - the handshake, `describe` from `tool.yaml` and `validate`;
  - `cancel`, honoured while `run` works (`ctx.check()`), and heartbeats against the idle timeout;
  - records, per-target status, logs, progress and the result.
- `ctx.connect(host, port)` opens a TCP connection through the task's forwarder when the sensor confines the network (api RFC-060), where a raw socket has no route; elsewhere it connects directly.
- The python scaffold uses the helper. Before, every Python tool re-implemented about 60 lines of protocol and ignored `cancel` while it ran.

### Added: the runtime maps a capability task onto the tool

- `tool.Task` gains three fields:
  - `Capability` (`scan.ports@1`);
  - `Params`: the capability's standard params, as the workflow set them;
  - `MaxTier`: the job's tier ceiling.
- `Manifest.ApplyParams` maps the params onto the tool's config keys through `implements[].params`, and consumes them. The tool reads only its config.
- `toolhost` applies the contract before a task starts:
  - the job's tier ceiling;
  - the param mapping;
  - the rate cap.
- After the task, `toolhost` checks the capability's required output with `capability.Check` and the tool's output shape.
  - Violations are logged and counted in `Stats.ContractViolations`, and an ok task becomes `partial`.
  - Records are still delivered, and the platform checks them again.
- Provenance carries `capability` and `contract_violations`. The run message carries `capability` and `max_tier`; adapters may ignore them.
- `toolhost.RatePolicy`: a policy with `CapRate` caps the tool's `safety.rate_param` key, and sets it when the task left it unset. The change is logged. The sensorkit policy caps it by the local policy's `rate.max_rps`.

### Added: tools declare the capabilities they implement (tool.yaml `implements`)

- A manifest names the capabilities of the OpenCTEM capability taxonomy (`github.com/openctemio/ctis/capability`) it implements, with the major: `implements: [{capability: scan.ports@1, params: {top_n: {key: top_ports}}, output_shape: open_port_assets}]`. `params` maps the capability's standard params to the tool's config keys and may narrow enum values or integer bounds. A standard param that is not mapped is one the tool does not take.
- New optional keys:
  - `input` (`batch: one|list`, `max_targets`);
  - `presentation` (`display_name`, `category` and `icon` from closed sets, an https `docs_url`);
  - `publisher` and `license` (SPDX);
  - `engine` (`name`, `license`, `min_version`, a `version_probe` argv);
  - `safety` (`rate_param`, `side_effects`, `expands_targets`);
  - `features` (`retest`, `cancel`; `streaming` is reserved);
  - `permissions.proxy` (`honors|ignores`);
  - `sdk.min`;
  - `deprecated`.

  Manifests that use none of them keep their digest.
- Builder: `Implements("vuln.templates@1")` maps standard params to parameters of the same name and a matching type. `ImplementsWith(tool.Implementation{...})` maps them explicitly. `BatchTargets(n)` sets list input.
- `Manifest.ImplementedCapabilities`, `Implementation`, `MinimumTier`, `Batches` and `RetestFeature`.
- `core.ToolContract` carries `implements` and `batch`.
- The JSON Schema of tool.yaml describes the new keys.

### Added: tool.Dial and a default User-Agent; ctx.HTTP() works on a confined sensor

- `ctx.HTTP()` goes through the task's forwarder when the sensor confines the task's network (`OPENCTEM_EGRESS_PROXY`, api RFC-060); before, it dialed directly and had no route there. Its host check still refuses other hosts before anything is sent.
- Its requests carry the User-Agent `openctem-<tool>/<version>` unless the tool sets its own per request (`req.Header.Set("User-Agent", ...)`). Before, they carried Go's default.
- `tool.Dial(ctx, "tcp", addr)` is for tools that speak TCP themselves (port scanners, TLS and protocol probes). It connects through the task's forwarder with HTTP CONNECT on a confined sensor, where a destination that is not a target fails with `tool.ErrEgressRefused`, and directly elsewhere. `tool.EgressProxy()` returns the forwarder, or nil.

### Added: tool.yaml http — the User-Agent, headers, timeout and TLS of a tool's requests

- `http: {user_agent, headers, timeout, tls: {insecure_skip_verify, min_version}}` in `tool.yaml` (`tool.HTTPSpec`, in the JSON Schema).
  - `ctx.HTTP()` applies it; a request's own values still win.
  - Exec tools pass `{{http.user_agent}}`.
  - The descriptor (and so the platform) carries it, and the task's start log line records it (header names only).
- Refused by validation:
  - `Authorization`, `Cookie` and `Proxy-*` headers (credentials come from the credential broker);
  - framing headers;
  - non-printable values;
  - a timeout outside 1s to 10m;
  - `tls.insecure_skip_verify` for a `vendor` network tool.

  A vendor tool's TLS is always verified.

### Added: the sensor's local policy decides last about the tools' requests (schema v3)

- Local policy schema v3 (`openctem.io/sensor-policy/v3`: every v2 key plus `http`):
  - `http.user_agent` replaces every tool's User-Agent;
  - `http.allow_insecure_tls: false` refuses, with `refused_by_policy`, a tool whose `tool.yaml` skips TLS verification.

  `core.LocalPolicy.HTTPPolicy()` reads it. v1 and v2 files are unchanged and still refuse the key.
- The effective settings (the manifest's `http` with the policy applied) travel in the task (`tool.Task.HTTP`, `run.task.http` for adapters). The runtime sets them; a job's value is discarded. `ctx.HTTP()`, `{{http.user_agent}}` and the task's start log line use them.

### Added: tools on a sensor's own tool host ship their logs

- `Kit.ToolLogSink()` returns the command log sink for a `toolhost.Host` the sensor builds itself (`Host.LogSink`). Before this, only the kit's private host shipped tool lines, so a sensor that ran its scanners through its own host sent none.
- The sink may be taken before `Run`, and sends nothing until the kit runs with a platform client.
- Lines are redacted, bounded per command (2,000 lines / 1 MiB), batched and queued ahead of the command's result, as for the kit's own tools. They never block the tool: past the bounds they are dropped and counted.

### Added: each tool run logs its start and its end

- A tool host with a log sink logs, to the task's command log:
  - "Tool <name> <version> started", with the targets and the capability;
  - "Tool <name> finished: <status>", with the exit code, records, duration and error class.
- A run that could not start logs an error line.

### Added: sensor protocol v3 transport (gRPC over mTLS, Connect/HTTPS fallback)

- A paired (key-bound) sensor negotiates protocol v3 when the platform's v2 hello lists `transport_v3` (openctem api RFC-059): gRPC over mutual TLS with a 7-day client certificate issued for the sensor's own key (renewed at two thirds of its lifetime, pinned to the platform's sensor CA), then the HTTPS binding (RFC 9421 signatures) when gRPC fails at the transport level (unreachable, handshake, HTTP/2 refused, reset, unimplemented), then protocol v2. An identity refusal never falls back. gRPC is probed again every 30 minutes; three consecutive transport failures renegotiate.
- `SENSOR_TRANSPORT=auto|grpc|https|v2` (default auto). Bearer-key sensors stay on v2.
- v3 sits under the v2 client as a round tripper: retries, the outbox and segmented, idempotent uploads are unchanged, so a lost connection mid-upload still stores the report once.
- The control stream pushes the doorbell (work waiting, cancels, pause) to `core.Doorbell.Handle`: a job starts within a second instead of at the next heartbeat. The heartbeat reports the binding and the fallback reason.
- New: `client.EnableTransportV3`, `StartTransport`, `TransportStatus`, `SetControlEventHandler`, `ParseTransportMode`; `sensorsig.Signer.TLSKey`; `protov2.Hello.TransportV3`; `pkg/sensorproto/v3` (generated, the platform's proto); `conformance.FakePlatform.EnableV3` (both bindings) for sensor tests.

### Added: evidence builders and retest verdicts with evidence (CTIS 1.6)

- The SDK speaks CTIS 1.6 (`pkg/ctis` re-exports `Endpoint`, `WebLocation`, `EvidenceItem` and the ctis evidence builders).
- `tool.HTTPExchange(req, reqBody, resp, respBody, match...)` builds an `http_exchange` evidence item:
  - it keeps the exchange raw and marks the sensitive values (authorization and cookie headers, credential parameters) in `sensitive[]`, without masking them;
  - a body over 64 KiB keeps a window around the first match, and the match offsets follow the window;
  - `content_sha256` covers the full capture.
- Tools can emit CTIS 1.6 endpoints: `Emitter.Endpoint`, the `endpoint` record kind of the adapter protocol, and `endpoints[]` in exec-profile output (CTIS and every importer format). A tool declares `endpoint` in `produces`, and the runtime checks each endpoint as CTIS (an undeclared one is quarantined, an invalid one refused).
- `tool.Evidence(kind, label, data)` builds an item of a kind CTIS does not know yet.
- `RetestContext.Report(item, tool.VerdictReport{...})` reports a verdict with up to five evidence items and the `template_digest` of the check that ran. `tool.RetestVerdict` carries both. Exec and adapter tools send them on the `verdict` message.
- The runtime checks verdict evidence again: too many items, an invalid item or an unreadable digest make the verdict `unverifiable`. Every item is marked again (`ctis.MarkSensitive`).
- Conformance: every capability suite fails a tool whose finding evidence is not valid CTIS, or leaves a sensitive header value unmarked.

### Changed

- `ScanTargetPolicy` resolves host names with the local policy's resolver when it has a local policy and no `LookupIP` of its own.

- The pinned ctis module locates Nessus host-level results on their host: `importtool` output for `.nessus` now carries `network` on port-0 results.

### Fixed: the audit logger no longer loses events when it stops

- `audit.Logger.Stop` waits for the flushes `Log` starts before its final flush and before closing the file. A flush that had taken events from the buffer could write them after the file closed, and they were lost (seen as 996 of 1000 events in `TestLogger_ConcurrentLogging`).

### Fixed: openctem tool runs tools in the sensor's sandbox, and scaffolds pin the SDK they need

- `openctem tool run` and `test` (and `openctem-conformance tool`) installed no executor backend, so tools ran as plain child processes while the docs said they ran in the sensor's sandbox. A tool that only worked outside the sandbox passed the kit and failed on a sensor. They now run in the process sandbox: `--sandbox off|auto|required`, default `$OPENCTEM_SANDBOX`, else `auto`.
- `init --kind go` wrote `require github.com/openctemio/sdk-go v<sdk.Version>`, a release older than the descriptor keys the CLI writes (`implements`), so the scaffold panicked on its own `tool.yaml`. The scaffold now requires the SDK version the CLI was built from, and its CI workflow installs the CLI at that version instead of `@latest`.
- `openctem tool run .` failed with `fork/exec bin/<tool>: no such file or directory`: the manifest path is now made absolute, as `test` already did.
- `docs/adapter-protocol.md` no longer says an operator-installed tool runs only on a backend that enforces the network class. The process sandbox does not enforce it yet.

### Fixed: the config report no longer asks a signed-jobs sensor for template keys

- A sensor that requires signed jobs trusts custom templates through the verified job statement, so the `policy.template_keys` check now reports `not_needed` for it instead of warning `missing` (and blocking custom templates in the platform's view). A sensor that verifies signed jobs only when present still needs `SENSOR_TEMPLATE_SIGNING_KEYS` for unsigned jobs, and is still warned.

### Fixed: sensorkit sensors apply the local policy's http section and pin confined tasks to admitted addresses

- **The problem.** The kit's tool host reads optional policies by type assertion, and the kit's policy implemented neither of two of them:
  - without `HTTPPolicy`, schema v3 `http.user_agent` and `http.allow_insecure_tls` were ignored for kit-hosted tools;
  - without `HostResolver`, a confined task's forwarder resolved a target host again at start instead of dialing the addresses the policy admitted.
- **The fix.** The kit's policy implements both now, and compile-time assertions keep every optional policy implemented.
- The local policy report now shows the http section (`http_user_agent`, `allow_insecure_tls`).

### Fixed: tool descriptors stay within the manifest size the platform accepts

- The sensor manifest carries at most 128 KiB of tool descriptors in all (`core.MaxManifestDescriptorBytes`). Past it, the largest descriptors are left out, deterministically. Those tools keep their digest and contract fields, and the platform plans with them as before. Without the budget, a sensor with many large descriptors could exceed the platform manifest cap (256 KiB in OpenCTEM), and its manifest would be refused.

### Fixed: settings docs links point at the settings reference

- `settings.DocsBase` (and so each setting's default `DocsURL()`, and the
  links in `docs/SETTINGS.md`) is `https://docs.openctem.io/sensors/settings/`
  with an anchor per setting. The old `/sensor/settings` page did not exist.
- CI checks every docs.openctem.io and GitHub file link in the repository
  (`scripts/check_docs_links.py`, job "Docs links").

### Fixed: a finding check may consume the assets findings are on

- A tool implementing `verify.finding@1` (input: a finding) runs on the asset the finding is on, so its `consumes` may list any asset type. Before, the descriptor check refused every asset type, because the capability has no asset input port. Other capabilities still constrain `consumes` to their inputs.

### Documentation

- Added a root `SECURITY.md` (report vulnerabilities to security@openctem.io).
- Removed `docs/GRPC.md` (the deprecated gRPC transport is served by no platform), `docs/ARCHITECTURE_BEST_PRACTICES.md` (described tool wrappers that moved to the sensor) and `examples/ci-cd` (CI scanning lives in openctemio/ci).
- README, `docs/ARCHITECTURE.md`, `docs/SECURITY.md` and the integration-test example match the SDK at this release: protocol v2 only, a working quick start.

## v0.18.0 — 2026-10-06

### Security

- An input must be a regular file inside the task directory: absolute paths, `..`, links and directories are refused, and so are archives (the runtime extracts them). Files are parsed with the importer's hostile-input limits (no XML entities or external resources, size, depth and record caps).

- The sensor refuses to start when its identity directory or files are
  readable by others, owned by another user or symbolic links, and prints
  the exact `chmod`/`chown` to run.

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

- **Sensor-local policy** (api RFC-040 §5.7). The network owner writes a read-only YAML file at install time
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

### Security: tool tasks are admitted against the sensor-local policy before they start

- `toolhost.Admit` and `toolhost.Host.Policy` (`*core.LocalPolicy` implements
  `toolhost.Policy`): every task of a tool on the tool contract is checked
  before any task directory, credential or process exists. The local
  policy's `tools.allow` and kill switch apply; each target of a tool whose
  network is `targets` passes the target guard (allow/deny lists, private
  ranges, ports, resolved addresses). A refused target is removed from the
  task and reported `skipped` with class `refused_by_policy`, so the tool
  never receives it; a task with no target left is refused. The policy's
  `rate.max_job_seconds` caps the run time. A manifest that declares
  `linux_caps` is refused (the runtime grants none), and `RunOptions.Mode`
  checks the manifest's `modes`.

### Upgrade notes

- A local policy that lists `checks.allow` must add `retest` for the sensor to accept retests; without it the platform's retest of a finding fails on that sensor and settles as unknown.

- The SDK needs an OpenCTEM API that serves sensor protocol v2 (every API
  since 2026-10-02); the API removed protocol v1. Against an older API every
  platform call answers `client.ErrV2Unsupported`: upgrade the API first.
- `SENSOR_PROTOCOL=v1` (or `-protocol v1`, `client.Config.Protocol: "v1"`) is
  refused with `client.ErrProtocolV1Retired`. Remove the setting; `auto` and
  `v2` are the same.
- Code that used the removed `pkg/chunk` manager or `client.UploadChunk` uses
  `Client.PushFindings`, which splits large reports into protocol v2 segments.

- Replace `ctis.FromSARIF(data, &ctis.ConvertOptions{...})` with `(&core.SARIFParser{}).Parse(ctx, data, &core.ParseOptions{...})`: the option names are the same (`AssetType`, `AssetValue`, `AssetID`, `Branch`, `CommitSHA`, `BranchInfo`, `DefaultConfidence`, `ToolType`). Code that needs the bare module converter imports `github.com/openctemio/ctis` directly.

- `ctis.IdentityHints.AgentID` (added earlier in this unreleased cycle) is now `ctis.IdentityHints.ScannerAgentID`; the JSON name stays `agent_id`, so reports are unchanged. The Go name says it is the scanner's own endpoint agent.
- **CTIS 1.4** (`pkg/ctis` follows `github.com/openctemio/ctis`): `ctis.SchemaVersion` changed from `"1.3"` to `"1.4"`, so `NewReport()` and every adapter now stamp `"version": "1.4"`. Reports declaring 1.0 to 1.3 are still accepted, decode strictly and validate. Code that compared a version against the literal `"1.3"` should use `ctis.SupportedSchemaVersions()` / `ctis.IsSupportedVersion()` (versions this SDK knows every member of) or `ctis.IsCompatibleVersion()` (any minor of major 1). The OpenCTEM API accepts the 1.4 stamp today; do not send the new 1.4 members until the API runs a ctis 1.4 build.

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

### Behaviour change

- `API_KEY` is no longer required: a sensor without one pairs instead of
  exiting with "missing: [API_KEY]". Set `Options.NoAutoPair` to keep the
  old refusal.

### Removed: the protocol v1 fallback client

- The client speaks sensor protocol v2 only. Every call that used to fall back
  to `/api/v1/agent/*` when the platform did not offer a v2 feature (results,
  heartbeat incl. `SendHeartbeatWithHints` / `SendHeartbeatForCancels` /
  `TestConnection`, command poll and transitions, `CheckFingerprints`,
  `BaselineDiff`, `GetSuppressions` and its user-route fallback, and
  `platform.PlatformClient.RenewKey`) now answers `client.ErrV2Unsupported`
  (`platform.ErrRenewUnsupported` for renewal) against a platform that does
  not serve the v2 route. The outbox keeps such a report queued instead of
  dead-lettering it.
- Removed with it: `client.ProtocolV1`, `client.IngestResponse`,
  `Client.UploadChunk` / `AsChunkUploader`, the v1 chunk upload in `pkg/chunk`
  (`Splitter`, `Manager`, `Config`, `Uploader` and their types; `SplitSegments`
  stays), `platform.SensorBuilder.WithChunkManager`, `PlatformSensor.ChunkManager`
  / `NeedsChunking` / `SubmitChunkedReport`, the v1 wire constants of
  `pkg/sensorproto/legacyv1` (its settings migration stays),
  `protov2.FeatureResultsV2`, `protov2.HeaderProtocolAdvert`,
  `protov2.DeprecationProtocolV1`, and the v1 routes of the conformance fake
  (`FakePlatform.V1Reports`). Requests no longer carry `X-Agent-ID`: protocol
  v2 identifies a sensor by its key.
- `PlatformSensor.SmartSubmitReport` returns `(string, error)`: every report
  goes through the upload pipeline (large ones as protocol v2 segments).

### Removed: `ctis.FromSARIF` and the SARIF kind helpers

- `pkg/ctis.FromSARIF`, `NormalizeSARIFKind` and `NormalizeSARIFBaselineState` are removed, and the module's bare `FromSARIF` is no longer re-exported. Convert SARIF with `core.SARIFParser` (same asset rule, same options), which runs on `github.com/openctemio/ctis/importer`. `SARIFLog` and `SARIFRun` stay.

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

- **Preflight checks and the config report** (api RFC-033, config report).
  What a sensor used to print to stderr only is now
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
- **Local policy schema v2; v1 frozen**.
  `openctem.io/sensor-policy/v1` never gains a key again
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

- **Structured policy refusals**. A command a
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

- **HTTP probe results keep what they learned about the server**.
  `core.LiveHost` gains `TLS` (`core.TLSLeaf`: the leaf
  certificate's subject, SANs, issuer, serial, validity and SHA-256
  fingerprint), `FaviconMMH3`, `JARM`, `ASN` (`core.ASN`) and `CDNType`.
  `pkg/ctis` follows ctis to the commit that adds `LiveHostInput.TLS`,
  `FaviconMMH3`, `JARM`, `ASN` and `CDNType` and emits a `certificate` asset
  per leaf (re-exported `TLSLeafInput`, `ASNInput`). The sensor maps httpx
  output onto them.

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

### Added: a conformance kit for tools in any language

- `conformance.RunToolSuite(t, "tool.yaml", opts)` and the command `openctem-conformance tool <tool.yaml>` check a tool that is its own program (any language) against adapter protocol v1 the way a sensor runs it: the manifest loads and validates; the handshake answers protocol 1, ignores an unknown message and describes the tool exactly as its tool.yaml does; an unknown configuration key is refused; standard output carries only protocol messages; the program exits 0 when its input ends; a cancel is honoured within the grace; and each self-test fixture runs through the runtime's own host (with every runtime check) and produces exactly the expected normalized CTIS. `-update` (or `OPENCTEM_UPDATE_GOLDEN=1`) writes the expected reports.

### Added: per-command logs reach the platform

- Every log line of a platform command now goes to the sensor's standard error and, on a platform that offers protocol v2 feature `logs`, to the command's log on the platform (`POST /commands/{id}/logs`), which keeps it with the task and shows it on the run page. Sources: a tool's `ctx.Log()` (`toolhost.Host.LogSink`) and the sensor's own code through `Kit.CommandLogger(ctx)`.
- Lines are redacted on both sinks (the tool's credentials, the sensor's key, fields named like secrets), cleaned of control characters and bounded per command (2,000 lines, 1 MiB, then a note of what was dropped). Batches go through the outbox (new kind `command_log`), are delivered before the command's result and survive an outage; they are evicted first under the byte cap and a refused batch is dropped, so logs never mark a command's results as lost.
- `client.SendCommandLogs` / `QueueCommandLogs`, `sensorproto/v2.CommandLogsRequest`, `CommandLogLine`, `CommandLogsResponse`, `FeatureLogs`, and the fake platform's `SetLogs` / `CommandLogs` for tests.

### Added: pin the platform CA by fingerprint

- `httpsec.SetAPIPinnedCA` / `httpsec.ParseCAFingerprint`: every API client
  created afterwards accepts the platform only when its TLS chain verifies
  up to the certificate with that SHA-256 fingerprint (a root or an
  intermediate the platform sends, or a self-signed platform certificate).
  The system trust store and `SENSOR_CA_FILE` no longer apply while a pin
  is set; the name, validity and key usage are still checked. This is what
  makes the first contact of a pairing sensor safe from a fake platform
  (api RFC-052).
- With a pin, the platform URL must use a host name: crypto/tls sends no server name for an IP address and x509 would skip the name check, so a pinned connection to an IP address is refused (`ErrPinnedCANoServerName`).

### Added: the file importer as a parser-class tool

- `pkg/importtool` (Beta): a tool of the tool contract, class `parser`, network `none`, workdir only. It converts the task's input files (Nessus v2 XML, Qualys detection XML with its KnowledgeBase, DefectDojo Generic Findings JSON, CycloneDX, SPDX, osv-scanner results, CSAF, OpenVEX) to CTIS with the `ctis/importer` package and emits them through the runtime's checks. Problems are logged with their line numbers; the statements of VEX documents go to the artifact `vex-statements.json`, never into findings.
- `testkit.Options.Files` writes files into the task directory before a run, as the runtime places a parser's inputs.

### Added: the kit runs tools of the tool contract (AddTool, adapter directories)

- `Kit.AddTool(t)`: a tool compiled into the sensor (or a legacy scanner
  through `toolcompat.FromScanner`) is reported with its contract and runs
  dispatched and scheduled scans out of process: each task admitted
  against the local policy in force (reloads included), only declared
  credentials delivered (`Options.ToolCredentials`), output checked and
  stamped, then delivered through the outbox like any scan. The program
  calls `adapter.Dispatch(tools...)` at the top of `main`.
- `Options.AdapterDirs` / `SENSOR_ADAPTER_DIRS`: tools the operator
  installed as `tool.yaml` plus a program (adapter protocol v1 or the exec
  profile), in `<dir>/tool.yaml` or `<dir>/<name>/tool.yaml`. A manifest is
  loaded only when the directory, the manifest and a program shipped next
  to it are owned by root or the sensor's user, not group- or
  world-writable and not symbolic links, and only with a run section; a
  name the sensor already provides is never replaced. A refused manifest is
  a warning and an `adapter_refused` check in the config report.
- `toolcompat.AsScanner` serves a contract tool to the command executor; a
  task none of whose targets was scanned fails its command instead of
  completing with no results.
- `core.ToolSettings.Values()`; `conformance.FakePlatform.AcceptedReports()`.

### Added: sensors run the platform's retest command

- `sensorkit` serves the `retest` command for every tool whose manifest declares retest (`tool.WithRetest`) and reports capability `retest:<tool>` for each, which the platform routes retests by. The command (`{"scanner", "targets": [addresses], "items": [{ref, target, kind, rule_id, fingerprint}], "timeout_seconds"}`) becomes one retest task that runs out of process like a scan, and the command completes with `metadata.retest.verdicts`: one `still_present`, `fixed` or `unverifiable` per item.
- The command is admitted like a scan before anything runs: the platform's tool policy, the local policy's `checks.allow`, `tools.allow` and every target. An item on an address that is not one of the command's targets, or a tool without retest, fails the command. Timeout: 2 minutes by default, at most 30.
- A sensor that runs a tool itself serves its retests with `Kit.HandleRetest(name, run)` (`run` runs the task through a toolhost Host); the kit reports `retest:<name>` and admits each command the same way. `toolcompat.Retester` (implemented by the contract tools the kit adds) and `toolcompat.RetestCapability` expose the same to a sensor that wires its own executor.

### Added: run one job by id and exit

- `Kit.RunJob(ctx, id)` runs the one platform command with that id and returns: the sensor as a Kubernetes Job (or any per-job launcher). It sets up everything `Run` sets up, claims the command by id, runs it through the same checks and executor as a polled command (local kill switch, served command types, expiry, local policy, the platform's tool gate), waits for the outbox to deliver its results (`JobDeliveryTimeout`, 5 minutes) and stops; it never takes other work. It returns an error when the command cannot be claimed, is not run (released to the platform) or its results are not delivered in time; a command that ran and failed is reported to the platform as failed and is not an error. `EnvJobID` (`SENSOR_JOB_ID`) names the variable sensors read for it.
- `client.ClaimCommand(ctx, id)` claims a command by id and returns it with its payload; `core.CommandPoller.RunClaimed(ctx, cmd)` runs an already claimed command with every check of a polled one.
- Mount the outbox on a persistent volume for a Job: results not delivered before the pod ends are otherwise lost.

### Added: key-bound sensors pair on first start (api RFC-052)

- `pkg/sensorkit/identity`: the sensor's identity on disk
  (`<state dir>/identity/signing.key`, PKCS #8 PEM, and `identity.json`,
  both 0600 in a 0700 directory owned by the sensor's user) and `Pair`, the
  interactive pairing client: the sensor makes its own Ed25519 key, checks
  the platform's signed answer (and its pinned key), prints a code and a
  fingerprint for the administrator to compare, waits for approval and
  confirms the identity with a signature. No secret is ever typed or
  pasted.
- `client.Config.Signer`: a key-bound client signs every request (RFC 9421,
  `pkg/sensorsig`), heartbeats included, and never sends a bearer key.
- The kit: a sensor started without `API_KEY` uses its paired identity, or
  pairs on first start and then runs (`Options.NoAutoPair` stops it
  instead). `SENSOR_CA_FINGERPRINT` pins the platform's TLS chain;
  `SENSOR_PLATFORM_KEY` pins the platform's pairing key. With a CA pin,
  `API_URL` must use a host name; an IP address is warned about in the
  config report (`platform.ca_pin_host`).

### Added: sensor pairing protocol and signed sensor requests

- `pkg/sensorproto/pairing`: the interactive pairing protocol of api
  RFC-052 (wire types, the nonce commitment, the platform transcript and
  its signature check with an optional pinned platform key, the short
  authentication string a person compares, user codes). Its test vectors
  are byte-identical with the platform's copy.
- `pkg/sensorsig`: RFC 9421 request signatures with the sensor's Ed25519
  key (one narrow profile: `@method` `@path` `@query` `content-digest`,
  created/expires/nonce/keyid, RFC 7638 key id) and a signing
  `http.RoundTripper` that never sends a bearer credential.

### Added: declare a simple tool with a builder

- `tool.Define(name, version)` declares a tool of the tool contract without writing a manifest by hand: target types, output types, typed parameters (`StringParam`, `IntParam`, `NumberParam`, `BoolParam`, `ListParam` with label, help, default, range, allowed values, pattern and size limits) and a handler `func(ctx, job, emit)`. The parameters become the manifest's configuration schema, which the platform renders and the runtime enforces before the handler runs.
- `tool.Job` gives the task with typed access: `Targets(types...)`, `Param(key).String()`, `.IntOr(d)`, `.BoolOr(d)`, `.Strings()`. `tool.Emit` builds CTIS records (`Vulnerability`, `Misconfiguration`, `Asset`) and passes them through the same checks as the emitter.
- The result is an ordinary `tool.Tool`: same manifest validation, same out-of-process execution, admission, output checks and provenance, same tests. A parameter whose key looks like a secret is refused (declare a credential instead). Nothing is removed; `tool.New` stays.

### Added: retest in the tool contract

- A target-scan tool can declare `retest: true` in its manifest and implement `tool.Retester` (`tool.WithRetest(t, fn)` adds a handler to any tool). A retest task carries `Task.Retest` items (a finding or asset ref, the target it is on, rule id, fingerprint); the tool answers one verdict per item with `RetestContext.Verdict`: `still_present`, `fixed` or `unverifiable`.
- The rules are enforced by the SDK, in tests (`testkit.Result.Verdicts`) as on the adapter side: every item must be on one of the task's targets (a retest never widens scope), at most 1,000 items, no records in a retest task (`tool.ErrRetestRecord`), the first verdict per item counts, an item without a verdict is `unverifiable`, and `fixed` stands only when the item's target was reported done and the task finished. Verdict details are cleaned, capped and redacted.
- Adapter protocol v1 gains the `verdict` message and the `retest` member of the run task (feature `retest` in the runtime's hello); the JSON Schemas of `tool.yaml` and of the protocol describe both. Adapters that do not know them are unaffected: the runtime sends a retest only to a tool whose manifest declares it.
- The runtime side (`pkg/sensorkit/toolhost`) applies the same rules across the process boundary: a retest task is checked and admitted before anything starts, items on targets the local policy refuses are not sent and end `unverifiable`, records in a retest are refused (counted as invalid output), a verdict on an item not in the task is refused, and `Outcome.Verdicts` holds one final verdict per item in task order. An exec-profile tool cannot declare retest (it has no verdict channel).

### Added: run a legacy scanner or collector as a tool of the tool contract

- `pkg/tool/toolcompat` (Beta, transitional): `FromScanner(manifest, scanner,
  ...)` and `FromCollector(manifest, collector, ...)` turn a `core.Scanner`
  or `core.Collector` into a `tool.Tool`. Compiled into the sensor and
  listed in `adapter.Dispatch`, it runs out of process in the task sandbox
  like any tool: the child scans (all targets at once for a
  `core.MultiTargetScanner`), converts the raw output with the SDK's
  parsers (or `WithParser`), and emits the report through the runtime's
  checks, so an undeclared record type is quarantined and a failed scan
  fails only its target.
- `WithState` sends the scanner's exported fields to the child (fields
  tagged `json:"-"` stay behind); secrets travel only as declared
  credentials (`WithPrepare` with `ctx.Secret`, or
  `WithAPIKeyCredential` for a collector, whose `APIKey` is never sent).
  The task's configuration, validated against the manifest's schema,
  reaches the scanner as `ScanOptions.Settings`.

### Changed

- The absent-policy warning says what actually happens: "jobs may enable
  out-of-band callbacks (interactsh), and custom templates run when
  SENSOR_TEMPLATE_SIGNING_KEYS is set" (it said both "are allowed").

- **`pkg/ctis` imports `github.com/openctemio/ctis`**,
  pinned to ctis main at `7d7d5ec` (untagged; includes
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
  an absent value is not `full`). A scan
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

### Changed: the tool adapters run on the ctis importer

- `pkg/adapters/{trivy,nuclei,semgrep,betterleaks,vuls,sarif}` (Deprecated) now delegate to `github.com/openctemio/ctis/importer`, the one conversion entry point the platform's import and CI endpoints and the sensor use. Their exported API is unchanged, and so are the asset rules: the repository the caller names (or the CI job's repository) wins, else the asset the file names; a code report with findings and neither is still `ctis.ErrNoAssetForFindings`. Inputs now get the importer's hostile-input limits (size, depth, string and record caps, UTF-8).
- Output differences, all to CTIS 1.4: `native`, `scores`, typed `vulnerability.ids`, `remediation` and `source_extra` are filled; tool capabilities use the platform's words (`sca`, `secret`, ...); finding ids are no longer set (receivers key findings); secret types use the schema vocabulary (`aws_key`, `generic_secret` instead of `credential` or `AWS`); semgrep's "requires login" placeholder fingerprint is replaced by a fingerprint of path, rule and line; semgrep impact is lower-case; the vuls instance id is an identity hint (`identity_hints.cloud_resource_id`); a SARIF log converts exactly as the module's `FromSARIF` does (title from the result message, no adapter-generated fingerprint, ids, data flow, tag filtering or markdown help references). Secret fingerprints are unchanged.
- The adapters' internal helpers and their unit tests are removed (the importer tests cover the conversion), and so are the `assetctx` helpers nothing uses any more.

### Changed: SARIF converts through the ctis importer

- `core.SARIFParser` and the tool host (`pkg/sensorkit/toolhost`, `output.format: sarif`) convert SARIF with `github.com/openctemio/ctis/importer`, the conversion the platform's import and CI endpoints use. The asset rule is unchanged (options, then branch info, then `versionControlProvenance`, then the CI job; findings with none of them are `ctis.ErrNoAssetForFindings`), and so are the findings: `ToolType` and `DefaultConfidence` still apply (ctis#34), and `BranchInfo` is still the report branch.
- Differences, all additions or fixes: the input gets the importer's hostile-input limits; a user and password in a `versionControlProvenance` repository URL are removed from the asset value; the asset carries a name and its branch and commit properties, and the report its scope; a result with neither a message nor a rule is skipped with an issue; `DefaultConfidence` 0 now means 90 (it used to give findings confidence 0).

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

- **semgrep: a partially parsed file no longer drops every finding.**
  semgrep emits `errors[].type` as a string or an array
  (`["PartialParsing", [...]]`); `SemgrepError.Type` was a string, so
  `json.Unmarshal` failed for the whole document and the adapter returned no
  findings at all. `SemgrepError` now decodes every shape and keeps the kind
  name in `Type` (still a string, e.g. `"PartialParsing"`).

### Fixed: guarded clients try every validated address

- The SSRF-guarded dialer resolved every address of a host, checked them all, and then dialed only the first. A platform or target name with an IPv6 and an IPv4 address failed to connect when only one family was reachable. It now tries the validated addresses in resolver order; no unchecked address is ever dialed.

### Documentation

- `docs/adapter-protocol.md`: the language-neutral contract for a tool in any language (transport, conversation, the rules the runtime enforces, time and cancel, exit codes, conformance, installing).
- `examples/python-adapter`: a complete tool in plain Python (standard library only) with its tool.yaml and self-test fixture, checked in CI by the conformance suite.

- `docs/rfcs/sensor-sdk-v2.md`: the accepted design for the next SDK
  generation (one tool contract with a `tool.yaml` manifest, out-of-process
  execution for every tool, adapter protocol v1 for any language, one
  runtime, stability tiers, transport v3 behind the SDK). `docs/STABILITY.md`
  now gives every package a tier (Stable, Beta, Frozen, Internal-bound,
  Deprecated). The module description no longer lists scanner wrappers
  (they moved to the sensor in v0.17.0).

### Documentation: every public package states its stability tier

- Each public package comment now ends with `Stability: <Tier>
  (docs/STABILITY.md).` (Stable, Beta, Frozen or Internal-bound; deprecated
  packages keep their `Deprecated:` paragraph), as `docs/STABILITY.md`
  lists them. The CI `api-compat` job weighs an incompatible change by that
  tier: Stable and Frozen fail unless the pull request is labelled
  `breaking-change` with an `### Upgrade notes` fragment, Beta warns,
  Internal-bound and Deprecated are listed only, and a package without a
  tier fails. A push to `main` reports against the latest release without
  failing (every change on `main` passed the gate as a pull request).

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

- **The tool wrappers moved to the sensor** (sdk-go is the
  shared interfaces, runtime and safety layer). These packages
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
- **Scanner proxy mode** (api RFC-034 G1).
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

- **Platform policy and slim heartbeats** (api RFC-033 §6.12).
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
