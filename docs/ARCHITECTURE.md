# SDK architecture

This document explains how the SDK's parts fit together and how a sensor built
on it talks to the OpenCTEM platform. Product documentation is at
https://docs.openctem.io.

## Overview

A **sensor** is the deployable runtime that runs security tools near the
targets and reports to the platform. The platform never connects to a sensor:
the sensor connects out, over HTTPS, using sensor protocol v2
(`/api/v2/sensor/*`).

```
                +---------------------------------------+
                |           OpenCTEM platform           |
                |  sensors | scans | findings | assets  |
                +-------------------^-------------------+
                                    | HTTPS, sensor protocol v2
                                    | (heartbeat, commands, results)
                +-------------------+-------------------+
                |    Sensor (pkg/sensorkit runtime)     |
                |                                       |
                |  pkg/client       command poller      |
                |  durable outbox   local policy        |
                |  per-task tool sandbox                |
                +---------+-------------------+---------+
                          |                   |
                tools (pkg/tool,     scanners, collectors,
                adapters)            parsers (pkg/core)
```

## Key concepts

### 1. Sensor identity

Every request a sensor makes is attributed to the sensor by its credential:
either a key-bound identity created by pairing (the sensor signs every request
with its own Ed25519 key, RFC 9421) or a bearer API key (`SENSOR_API_KEY`). Protocol
v2 identifies a sensor by its credential alone.

```go
c := client.New(&client.Config{
    BaseURL: "https://openctem.example.com", // the API base URL
    APIKey:  os.Getenv("SENSOR_API_KEY"),
})
```

A sensor:
- is registered on the platform (paired, or created with a key);
- sends heartbeats that report its status, tools and capacity;
- claims and runs the commands the platform dispatches to it;
- pushes results, which the platform attributes to it.

### 2. Sensor runtime

`pkg/sensorkit` is the runtime in one call: settings, connection, heartbeat,
commands, durable outbox, key renewal, local policy, tool sandbox and drain
(see the [README](../README.md)). `pkg/core` holds the lower-level parts it is
built from (`BaseSensor`, `CommandPoller`, registries) for a sensor that wires
them itself:

```go
sensor := core.NewBaseSensor(&core.BaseSensorConfig{
    Name:    "my-sensor",
    Version: "1.0.0",
}, apiClient)

sensor.AddScanner(myScanner)
sensor.AddCollector(myCollector)

sensor.Start(ctx)
```

Modes:
- **Daemon**: long-running; polls for the commands the platform dispatches
  (`Kit.Run`), or runs one command and exits (`Kit.RunJob`, for a Kubernetes
  Job).
- **Runner**: one run in CI (`Kit.RunOnce`), authenticated by the CI job's
  workload identity.

### Heartbeat doorbell

A daemon can let the heartbeat tell it when there is work, instead of polling
for commands on a fixed interval (API: RFC-023 §9.2a). Share one
`core.Doorbell` between the heartbeat and the command poller:

```go
bell := core.NewDoorbell(&core.DoorbellConfig{
    OnRotateKey: keyRenewManager.RenewNow, // optional
})
sensor.SetDoorbell(bell) // heartbeat sends X-OpenCTEM-Sensor-Features: doorbell
poller.SetDoorbell(bell) // polls when the doorbell rings
```

| Heartbeat answer | SDK action |
|---|---|
| `pending_jobs > 0` | the poller polls immediately (no fixed wait) |
| `next_heartbeat_seconds` | next heartbeat delay, clamped to 5 s – 5 min |
| any hint present | the fixed poll is dropped; poll on the doorbell plus a safety poll every 5 min |
| no hints (older server) or heartbeat failed | fixed-interval polling exactly as before |
| `actions: pause` | claim and start nothing (poll, scheduled scans); running jobs finish; heartbeats continue; lifted by the first answer without `pause` |
| `actions: resume` | lifts a pause |
| `actions: drain` | like `pause`, but final until the process restarts |
| `actions: rotate_key` | `OnRotateKey` (e.g. `KeyRenewManager.RenewNow`) |
| `actions: update` | logged once; nothing is downloaded or run |
| unknown action | ignored, logged once |
| `config_version` | `Doorbell.ConfigVersion()`; changes are logged |

The hints only say *that* work is waiting; jobs are still fetched and claimed
through `GET /api/v2/sensor/commands`. There is no free-text or shell action.

**Claim backoff.** A poll that starts nothing and only hands commands back
(their hosts are busy on this sensor, no slot is free, the type is not
served) would otherwise repeat at the speed of the round trip: the release
makes the command claimable, the platform rings the doorbell and the same
command comes back. After such a poll the poller waits 1 s, doubling to at
most 1 min (plus up to half a step of jitter) while polls stay fruitless;
a doorbell ring during the wait polls once the wait is over. Meanwhile the
platform can give the command to another sensor. A command that ends here
(its host may be free now) or a poll that starts a command ends the wait. A
poll the platform refuses with `Retry-After` (429/503) is not repeated
before it (capped at 5 min); only time lifts that wait.

**Order of the checks on a claimed command.** A command passes, in order:
the command types the sensor serves and its expiry (before the claim); the
claim itself; its **job signature** (`CommandPoller.SetJobGuard`,
`pkg/jobsig`: with a pinned signer key the payload, signed job and lease
epoch of the claim answer are verified, and a sensor that requires signed
jobs refuses an unsigned command; [security guide](./SECURITY.md#signed-jobs));
the start transition; the sensor-local policy; the platform's tool gate;
then the executor and the tool. A refusal at any step fails the command
with its layer and rule (`job_signature`, `targets.allow`, …) and nothing
after it runs.

### The local store and the janitor

A daemon opens `pkg/localstore` beside its outbox (`SENSOR_STORE_DIR`; the
master key is `SENSOR_STORE_KEY_FILE` or a 0600 `master.key` in that
directory) and passes it to the outbox, which then seals every item under the
data key of the item's organization (file format 2). At start, before any job
is claimed, the kit:

1. reports each job the journal shows as unfinished (`Store.Recover`; the poller journals
   every job from the platform's start until its result is queued,
   `CommandPoller.SetJobJournal`) through
   the outbox as a failed command result naming the step that was running, so
   the platform hands the work to another sensor instead of waiting for a
   lease to expire;
2. sweeps the job workspaces a crash left (`SENSOR_WORKSPACE_DIR`);
3. starts the `localstore.Janitor`: a sweep at start, after a burst of
   acknowledged results (`outbox.Config.OnDelivered`) and every 10 minutes.
   `Kit.SetStorePolicy` tunes its caps; every field is clamped, so a policy
   can never switch cleanup off.

The command poller claims nothing while `Janitor.AcceptsWork` is false: the
outbox holds 85 % of its cap in unacknowledged results (or the last refused
item would not fit), storage is at the high watermark after the cold cache
was evicted, or the volume is low. It resumes when that clears and logs each
change once. Unacknowledged results are never deleted for space; results beat
new work. Tools cannot read the store: its directory and key file are in the
sandbox's protected paths. The heartbeat carries `local_store` (bytes per
class, watermark, whether claiming is stopped, the last sweep, the boot
generation and whether it was reset), only to a platform that lists the
`local_store` feature. Keep `store/` on the same persistent volume as `outbox/`: it holds the keys
of the sealed items, and an outbox that survives without it cannot be read.
`doctor` reports the store directory's privacy, the key
file's mode and where the key lives, and the volume's free space.

### The content cache and jobs that pin content

The sensor holds content packs (wordlists, templates, rules) in a
digest-keyed cache, `content/` next to the local store: one directory per
pack digest, so a pack that two organizations' jobs need on a shared sensor
is downloaded and stored once. Only platform packs are ever cached on a
shared sensor; an organization's own packs exist only on that organization's
sensors; a list generated for one job is never cached (see below).

- **Trust.** The pairing pins the content-signing keys (platform; and the
  organization's own for its sensors) in `identity.json`. A pack is stored only
  when its bytes hash to the digest, its DSSE statement verifies against a
  pinned key and names that digest (and this organization, for a tenant pack),
  and the archive passes the canonical rules. It is verified again on every
  load (cached for six hours on an unchanged fingerprint); a pack that fails is
  removed and fetched again. A key the platform merely sends is never trusted.
- **One budget.** The janitor prunes the cache under the same quota as the
  outbox, journal and workspaces (policy `pack_budget_bytes`, default 2 GiB;
  `SENSOR_CONTENT_BUDGET_MB` can only lower it). A pack a running task holds is
  never removed. At the high watermark the cold packs go first.
- **Refresh.** On a schedule (15 minutes, jittered) and at once when a heartbeat
  answer carries a new `content_version`; the heartbeat reports the digests held.
- **Jobs pin content.** The signed statement lists `content: [{slot, digest}]`
  and the payload carries the matching `content` members. The verifier requires
  them to be equal; the executor mounts a pack only when the verified statement
  lists it. A missing pack is fetched at claim (one download however many jobs
  claim it at once); if it cannot be delivered the command fails with
  `content_unavailable` and is requeued.
- **Wordlists.** The tool host composes the lists a job names (named files of
  its packs, and lists the platform generated for the job, carried inline in
  the signed payload) into one normalised, de-duplicated, capped file in the
  task's own directory (`pkg/tool/wordlist`). The tool reads that one path. An
  inline list is held in memory, written only to the task directory and removed
  with it; it never reaches the cache.

### Results delivery: protocol v2 and the durable outbox

**Protocol.** Protocol v2 is the only sensor protocol (the platform retired
v1 in 2026-10). `client.Config.Protocol` is `auto` (default) or `v2`, which
are the same; `v1` is refused. The client reads `GET /api/v2/sensor/hello`
for the features and limits. Results go as
`PUT /api/v2/sensor[/commands/{command_id}]/results/{report_id}` with
`Content-Type: application/vnd.openctem.ctis.v1+json`, a `Content-Digest`
(sha-256 of the bytes as sent) and zstd. Reports over the per-request limits
are sent as segments (each a complete CTIS document with the report's tool,
metadata and the assets its findings reference; `chunk.SplitSegments`) and a
commit. A platform without protocol v2 answers `client.ErrV2Unsupported`;
the outbox keeps the report queued until the platform serves v2.

| v2 answer | SDK |
|---|---|
| 202, or 200 for an identical replay | delivered |
| 429, 503 (`Retry-After`), 500, 502, 504, network | retried with the same `report_id`, back-off with jitter |
| 413 | the refused request is halved into segments and sent again |
| 409 `report-expired` / `segment-set-mismatch` | sent again under a new `report_id` |
| 409 `report-conflict` / `report-committed` | delivered if the status resource says the report is committed |
| 404 `command-not-found` (the command closed) | sent again unsolicited (not bound to the command) |
| 401 | delivery paused until the key is accepted (heartbeat) or replaced (`SetAPIKey`) |
| other 4xx | refused: dead letter |

**Outbox.** `Client.EnableOutbox(client.OutboxConfig{Dir: ...})` (the sensor
does it by default in daemon mode) makes delivery durable (`pkg/outbox`):

- Every report and command result is written to `Dir` **before** the first
  send and removed only when the platform acknowledged it; a crash, `kill -9`
  or restart loses nothing. Replays are idempotent on v2 (same `report_id`,
  same bytes: the server answers 200 and stores nothing).
- One file per item (`pending/<id>.item` + `.state`), each written to a
  temporary file, fsynced, renamed and the directory fsynced; mode 0600 in a
  0700 directory; an exclusive `flock` so two processes never share it;
  sealed with AES-256-GCM under `outbox.key` (0600, created on first use;
  `KeyFile` can point at a mounted secret instead). A torn or corrupted file
  fails authentication and is moved to `corrupt/`; it never crashes the
  process.
- Never fills the disk and never drops an unacknowledged result: a byte cap
  (default 1 GiB, and at most half of the space the outbox could use) evicts
  dead letters and then command log batches, oldest first, with a log line,
  the `openctem_sensor_outbox_evicted_total` metric (`outbox.NewCollector`)
  and `evicted_count` on the heartbeat. When pending results alone fill it,
  `Enqueue` refuses new items (`ErrFull`; the client then tries a direct
  send) and `Outbox.AcceptsWork` (also through `localstore.Janitor`) tells
  the sensor to stop claiming jobs until deliveries make room; a small
  reserve keeps room for command results. The age cap (default 7 days)
  deletes dead letters only.
- Refusals (400, 409, 413 that splitting cannot fix, 415, 422, ...) go to
  `dead/` with `<id>.reason.json` (the problem document); they are never
  retried by themselves (`Outbox.RequeueDead` after fixing the cause).
- Oldest first, one at a time (or two); a circuit breaker stops sending
  after repeated failures, and an accepted heartbeat drains the queue at
  once.
- A command is reported complete only after its results were accepted: the
  `CommandPoller` puts the command id on the context (`core.WithCommandID`),
  results are bound to it, and the command result waits behind them in the
  outbox. A refused result turns "completed" into "failed".
- The heartbeat carries `outbox: {pending_count, pending_bytes,
  oldest_age_seconds, dead_letter_count, evicted_count}`.

`PushFindings` with an outbox waits up to `OutboxConfig.SyncWait` (30 s) for
the first delivery and otherwise returns `PushResult{Queued: true}`. The old
`pkg/retry` file queue and the SQLite chunk store were replaced by the outbox;
reports left in `~/.openctem/retry-queue` are imported on first start.

### Feed transfer: chunked signed bundles

Large data moves in two directions, and each direction has one code path
(api `docs/rfcs/RFC-070-chunked-feed-transfer.md`):

- **Push** (sensor or collector to platform): the results protocol and the
  outbox above. Segments are the chunks (`chunk.SplitSegments`), the
  `report_id` plus segment number is the idempotency key, `V2Progress`
  resumes after a restart, and the outbox is the encrypted, capped
  store-and-forward spool.
- **Pull** (published feed to platform or sensor): the contract module
  `github.com/openctemio/ctis/transfer` (`transfer` and `transfer/bundle`),
  which lived here as `pkg/transfer` until v0.1.0 of that module. It is a
  format shared by the platform, the feed publishers and sensors, so it is
  part of ctis and the platform never depends on the SDK. Its DSSE envelope
  is restated byte-identical to `pkg/jobsig` (the same golden vector is in
  both test suites).

`transfer.Fetcher` downloads from an ordered list of origins (release URL,
mirrors, a local directory for air-gapped installs) through the caller's
SSRF-guarded client (required for URL origins; there is no unguarded
default). Per origin: retries with exponential back-off and jitter, Retry-After
on 429/503 (capped; a longer wait moves to the next origin), a per-attempt
timeout, a stall guard, and resume of a partial download with a Range
request. A 404 or a hash mismatch moves to the next origin at once; an origin
that keeps failing opens its circuit for a cool-down. `Small` reads a pointer
or manifest (capped; conditional GET with the cached ETag); `Blob` returns a
content-addressed file from `<cache>/blobs`, verified against its sha256 and
size before it is moved there, so a chunk shared by two releases is fetched
once.

A v2 bundle is a flat set of files: `latest.v2.dsse.json` (signed pointer:
sequence, the snapshot and delta manifest names, sizes and digests),
`snapshot.v2.manifest.dsse.json` and `delta.v2.manifest.dsse.json` (signed
manifests: per record stream, the chunks with sha256, size, uncompressed
size, record count and id range) and `sha256-<hex>.jsonl.gz` chunks. Chunk
boundaries come from a hash of the record id (records in ascending id order),
so one changed record changes one chunk. `bundle.Writer` writes them;
`bundle.WritePointer` signs the pointer.

`bundle.Consumer.Run`:

1. loads the `Checkpoint` (applied sequence; bundle in progress and next chunk);
2. verifies the key set (caller's `Trust`), the pointer (signature, feed,
   expiry, at most 8 days valid) and refuses a sequence older than the
   applied one (`ErrRollback`);
3. takes the delta only when its base is the applied sequence, otherwise the
   snapshot; resumes the bundle in progress when its manifest digest matches;
4. fetches the manifest, checks it against the pointer's pin, its signature
   and the caps (chunk count, sizes, total), all before any chunk;
5. per chunk: `Blob` (hash and size verified), then `Applier.ApplyChunk`
   streams the records (`Chunk.Records` refuses more decompressed bytes or a
   different record count than declared, and lines over the cap), then the
   checkpoint is saved;
6. `Applier.Complete` (a snapshot removes what it no longer holds), then the
   sequence is saved as applied and cached chunks of older bundles are
   pruned.

A crash between chunks resumes at the next chunk; a chunk may be applied
twice, so appliers upsert by record id and never replace a record of a newer
sequence. `FileCheckpoint` stores the state in a 0600 file; the platform
implements `Checkpoint` on a table. `Fetcher.Register` and
`Consumer.Register` expose the counters (files, bytes, retries, resumes,
fall-backs, failures; chunks applied and failed, resumes, refusals). Logs
carry names, origins, sizes and errors, never record content.

### Per-host politeness keys

The keys are defined once, in the CTIS contract
(`github.com/openctemio/ctis/politeness`), which the platform imports too:
which hosts a job touches and when two jobs touch the same host (api
`docs/rfcs/RFC-090-work-pool.md`). A name, the host of a URL or a service,
an address (with the marker of its /24 or /120 bucket) and a range (one key
per bucket) each have a key; an address and a range scan of its bucket
conflict, two addresses of one bucket do not. With a network context (api
RFC-089) the keys of private addresses and of names carry the network, so
overlapping private ranges at two sites stay two hosts; public addresses
never do. The platform holds the keys of a job while it runs and sends them
with the job (`host_keys`); the command poller admits the job under them.

### 3. Components

Components are the building blocks that perform actual work:

| Component | Purpose | Where |
|-----------|---------|-------|
| **Tool** | A workload described by a manifest (`tool.yaml`), run out of process in the sandbox | `pkg/tool`, `pkg/tool/adapter` |
| **Scanner** | Runs a security tool binary (older interface; bridged to the tool contract) | `core.Scanner`, `core.BaseScanner` |
| **Parser** | Converts tool output to CTIS | `core.Parser`, `core.SARIFParser` |
| **Collector** | Pulls data from a source | `core.Collector` |
| **Command executor** | Runs one command type | `core.CommandExecutor`, `Kit.HandleCommand` |

The scanner wrappers for specific tools (nuclei, semgrep, trivy, betterleaks,
the recon tools) live in the sensor (`github.com/openctemio/sensor`), not in
the SDK.

## Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Scanner    │────▶│    Parser    │────▶│  CTIS Report  │
│  (Semgrep)   │     │  (SARIF)     │     │              │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
┌──────────────┐     ┌──────────────┐             │
│  Collector   │────▶│  CTIS Report  │─────────────┤
│  (GitHub)    │     │              │             │
└──────────────┘     └──────────────┘             │
                                                  ▼
                                          ┌──────────────┐
                                          │  SDK Client  │
                                          │ (sensor_id) │
                                          └──────┬───────┘
                                                  │
                                      PushFindings() / PushAssets()
                                                  │
                                                  ▼
                                          ┌──────────────┐
                                          │  OpenCTEM API │
                                          └──────────────┘
```

## CTIS (CTEM Ingest Schema)

All components produce **CTIS Reports** - a standardized format for security findings and assets:

```go
report := ctis.NewReport()
report.Tool = &ctis.Tool{Name: "my-scanner", Version: "1.0"}

// Add findings
report.Findings = append(report.Findings, ctis.Finding{
    ID:       "finding-001",
    Type:     ctis.FindingTypeVulnerability,
    Title:    "SQL Injection",
    Severity: ctis.SeverityCritical,
    Location: &ctis.FindingLocation{
        Path:      "src/db.go",
        StartLine: 42,
    },
})

// Push to server
client.PushFindings(ctx, report)
```

## Transport

The SDK speaks sensor protocol v2 over HTTPS (`pkg/client`) and, for a
key-bound sensor, sensor protocol v3 (`pkg/sensorproto/v3`: gRPC with mutual
TLS when the platform advertises it, else the HTTPS binding, else v2).
Protocol v1 is retired and refused; its gRPC transport and proto files are
removed.

## Implementing Custom Components

### Custom Scanner
```go
type MyScanner struct {
    *core.BaseScanner
}

func (s *MyScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
    // Run your scanning logic
    return &core.ScanResult{
        RawOutput: output,
    }, nil
}
```

### Custom tool

New integrations should use the tool contract rather than a scanner: see
"Write a tool" in the [README](../README.md), and
[docs/adapter-protocol.md](adapter-protocol.md) for tools written in other
languages.

## Best Practices

1. **Keep the state directory.** Mount one persistent volume at
   `/var/lib/openctem` (state, outbox and content under it): the state holds
   the paired identity or the renewed key, the outbox undelivered results.

2. **Use CTIS.** Convert every output to CTIS reports.

3. **Never lose results**: enable the durable outbox (the kit does it for a
   daemon; see "Results delivery"):
   ```go
   c := client.New(cfg)
   if err := c.EnableOutbox(client.OutboxConfig{Dir: "/var/lib/openctem/outbox"}); err != nil {
       log.Fatal(err)
   }
   defer c.Close()
   ```

4. **Ship a local policy.** The sensor-local policy limits targets, ports and
   tools whatever the platform sends. A sensor paired by this SDK refuses
   every job with network targets until it has one (`SENSOR_REQUIRE_LOCAL_POLICY`;
   see [the security guide](./SECURITY.md#a-sensor-without-a-local-policy-fail-closed-or-legacy)).

5. **Follow the [SDK security guide](./SECURITY.md)** for the target policy,
   template signatures, scanner environment and sandbox.

## Security Features

- **Transport**: TLS always verified; the platform's TLS identity is
  pinned at pairing (`identity.json` `platform_tls_pin`) or by
  `SENSOR_CA_FINGERPRINT`, with no fallback to the trust store; the gRPC CA
  bundle is sticky and a certificate failure never falls back to another
  binding; no redirects followed by the API clients, SSRF-safe HTTP
  (`pkg/httpsec`).
- **Command path**: signed jobs (the platform's separate job signer signs
  every claimed command; a sensor that pinned its key verifies the
  signature, this sensor, the command, its payload bytes, its lease and a
  replay-proof sequence number before the command starts, `pkg/jobsig`;
  required for sensors paired with a signing platform), scan-target
  policy, sensor-local policy (fail closed without one on new installs),
  signed custom templates, dangerous-flag blocklist, rate-limit ceilings.
- **Posture**: the manifest reports the local policy state and requirement,
  the platform TLS pin, the tool sandbox and whether signed jobs are
  required (`jobs.signed`), so the platform can flag unhardened sensors.
- **Tools**: per-task sandbox (Landlock, seccomp, rlimits, no_new_privs),
  scanner environment allow-list, output caps.
- **Results**: encrypted durable outbox (AES-256-GCM), idempotent delivery.

See the [Security Guide](./SECURITY.md) for detailed information.

## See Also

- [SDK README](../README.md) - Quick start guide
- [Security Guide](./SECURITY.md) - Security best practices
- [OpenCTEM documentation](https://docs.openctem.io) - product and API documentation
- [CTIS module](https://github.com/openctemio/ctis) - CTIS type definitions (`pkg/ctis` re-exports them)
