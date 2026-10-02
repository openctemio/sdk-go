# Changelog

All notable changes to `github.com/openctemio/sdk-go`.

## Unreleased

### Fixed

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
||||||| parent of 8fcd393 (feat(sensor): control plane under load (api RFC-035 Phase 1))

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
<<<<<<< Updated upstream
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
||||||| Stash base
=======
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
>>>>>>> Stashed changes

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
