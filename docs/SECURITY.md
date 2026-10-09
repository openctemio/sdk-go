# SDK Security Guide

This document describes the security features and best practices for the OpenCTEM SDK.

---

## Security Features

### 1. Credential Storage Security

The SDK provides secure credential storage with multiple protection layers.

#### Key Validation

All credential keys are validated to prevent path traversal and injection attacks:

```go
import "github.com/openctemio/sdk-go/pkg/credentials"

// Keys are automatically validated
err := credentials.ValidateKey("my.api.key")  // OK
err := credentials.ValidateKey("../etc/passwd")  // Error: path traversal not allowed
err := credentials.ValidateKey("key@#$")  // Error: invalid characters
```

**Validation rules:**
- Keys must be 1-256 characters
- Only alphanumeric characters, dots, underscores, and hyphens allowed
- Cannot start with dot or hyphen
- Path traversal sequences (`..`, `/`, `\`) are rejected

#### Encrypted Storage

For sensitive credentials, use `EncryptedFileStore` with AES-256-GCM encryption:

```go
import "github.com/openctemio/sdk-go/pkg/credentials"

// Create encryption key (32 bytes for AES-256)
key := make([]byte, 32)
crypto_rand.Read(key)

encryptor, err := credentials.NewAESEncryptor(key)
if err != nil {
    log.Fatal(err)
}

store, err := credentials.NewEncryptedFileStore("/secure/path/creds.enc", encryptor)
if err != nil {
    log.Fatal(err)
}

// Credentials are encrypted at rest
store.Set(ctx, "api.token", &credentials.Credential{
    Type:  credentials.CredentialTypeAPIKey,
    Value: "secret-token",
})
```

**Features:**
- AES-256-GCM authenticated encryption
- Random nonce per encryption (prevents pattern analysis)
- Automatic key validation on all operations
- `SecureClear()` for zeroing credentials in memory

#### Secure Comparison

Use constant-time comparison for credential verification to prevent timing attacks:

```go
import "github.com/openctemio/sdk-go/pkg/credentials"

// Timing-safe comparison
if credentials.SecureCompare(providedToken, expectedToken) {
    // Tokens match
}
```

### 2. gRPC transport (deprecated)

`pkg/transport/grpc` is deprecated: no OpenCTEM platform serves it and it is
removed in a later minor release (see [STABILITY.md](STABILITY.md)). Use
`pkg/client`, which speaks sensor protocol v2 over HTTPS. Sensor protocol v3
(gRPC with mTLS and an HTTPS fallback) is planned and will be generated from
its own protocol definitions.

### 3. Platform Sensor Security

> `pkg/platform` requires the platform (SaaS) control plane: its
> `/api/v1/platform/*` routes are not served by the open-source API.
> Self-hosted sensors use `pkg/client` + `core.CommandPoller`, which carry
> their own target validation and command-expiry checks. The job checks
> below do not validate scan targets — a platform executor must do that
> itself (e.g. with `core.ScanTargetPolicy`).

Platform sensors include comprehensive security controls.

#### Job Validation

All jobs are validated before execution:

```go
import "github.com/openctemio/sdk-go/pkg/platform"

config := &platform.PollerConfig{
    // Restrict allowed job types
    AllowedJobTypes: []string{"scan", "collect"},

    // Limit payload size (default: 10MB)
    MaxPayloadSize: 10 * 1024 * 1024,

    // Require auth tokens on all jobs
    RequireAuthToken: true,

    // Validate JWT tenant claims match job tenant
    ValidateTokenClaims: true,
}
```

**Validation checks:**
- Job ID, tenant ID, and type are required
- Job type must be in whitelist (if configured)
- Payload size limits enforced
- Auth token validation with JWT claim matching
- Timeout validation (max 1 hour)

#### Lease Security

Lease identities are now cryptographically secured to prevent hijacking:

```go
import "github.com/openctemio/sdk-go/pkg/platform"

config := &platform.LeaseConfig{
    // Secure identity enabled by default
    // Format: prefix-hostname-pid-<32-char-random-hex>
    UseSecureIdentity: nil,  // nil = true (default)

    // Optional prefix for identification
    IdentityPrefix: "scanner",
}
```

**Security features:**
- 16-byte cryptographic random nonce in identity
- Cannot be guessed or forged by attackers
- Automatic job cancellation on lease expiry

#### Lease Expiry Handling

Jobs are automatically cancelled when lease expires:

```go
poller := platform.NewJobPoller(client, executor, config)
poller.SetLeaseManager(leaseManager)

// When lease expires:
// 1. All running jobs are cancelled via context
// 2. Jobs report "canceled" status
// 3. OnLeaseExpired callback is invoked
```

### 4. Template Security

Custom scan templates are validated to prevent attacks.

#### Template Validation

```go
import "github.com/openctemio/sdk-go/pkg/core"

// Templates are automatically validated
err := core.ValidateTemplate(&core.EmbeddedTemplate{
    ID:           "my-template",
    Name:         "sql-injection.yaml",  // Must be simple filename
    TemplateType: "nuclei",              // Must be: nuclei, semgrep, betterleaks ("gitleaks" is accepted as betterleaks)
    Content:      templateContent,
    ContentHash:  "sha256:...",          // Optional integrity check
})
```

**Validation rules:**
- Path traversal in names rejected (`../`, `/`, `\`)
- Hidden files (starting with `.`) rejected
- Template type must be whitelisted
- Max 50 templates per command
- Max 1MB per template
- Content hash verification (if provided)
- Platform signature verified against a pinned key (see below)
- Duplicate filename detection

#### Template Signatures

A scan command's custom templates run only when something the sensor pins
vouches for exactly those bytes, or the command fails before any template
is written or any scanner runs. Two ways, in this order:

1. **The signed job** (preferred). When the command's signed job verified
   (see [Signed jobs](#signed-jobs)), its statement lists the SHA-256 of
   every custom template (`templates`, `"sha256:<hex>"` of the decoded
   content, in the payload's order). The platform's job signer names a
   template only when its digest is approved in the signer's scope ledger
   (api RFC-040 P2). `jobsig.Verify` refuses a statement whose list is not
   exactly the payload's (reason `templates`), and the executor compares
   the decoded templates with the verified list again before writing them.
   No `SENSOR_TEMPLATE_SIGNING_KEYS` is needed.
2. **The per-tenant manifest** (fallback for sensors without signed jobs):
   the platform's signed manifest of the templates
   (`ScanCommandPayload.CustomTemplatesEnvelope`) against keys pinned in
   `SENSOR_TEMPLATE_SIGNING_KEYS`. That key is held by the API, so this path
   is weaker; it is to be removed once signed jobs are required
   everywhere.

Either way the local policy's `allow_custom_templates` gate and the
template validation above still apply: a signature never lets a template
the sensor's owner refused, or a dangerous protocol, through.

The
manifest (`core.TemplateManifest`, kind `openctem.template-manifest/v1`)
names the tenant, the sensor and the command it is for, when it was issued
and when it expires, and the id, name, type and SHA-256 of every template in
order. It travels in a DSSE envelope (payload type
`application/vnd.openctem.template-manifest+json`): the exact signed bytes,
Ed25519 over DSSE's pre-authentication encoding, by a key derived for the
tenant. The sensor checks it against keys its operator pinned:

```go
v, err := core.ParseTemplateSigningKeys(os.Getenv("SENSOR_TEMPLATE_SIGNING_KEYS"))
exec.SetTemplateVerifier(v) // sensorkit does this from SENSOR_TEMPLATE_SIGNING_KEYS
exec.SetSensorID(id)        // sensorkit does this from SENSOR_ID when set
```

`TemplateVerifier.Verify` checks the signature over the exact payload bytes
before parsing them, then refuses: another payload type or manifest kind,
unknown manifest fields, a manifest for another command (or another sensor,
when the sensor knows its id), an expired one or one issued in the future
(5 minutes of clock skew allowed), and any difference between the manifest's
list and the command's templates (one changed, added, held back or
reordered). No pinned key: `core.ErrNoTemplateKeys`; no envelope:
`core.ErrTemplatesUnsigned`. Several keys may be pinned (comma-separated) to
roll the platform key.

The tenant's public key comes from the platform
(`GET /api/v1/scanner-templates/signing-key`) and is pinned out of band, so
neither a man in the middle nor a write to the platform's database or
command queue can make a sensor run a template the platform did not
validate and sign for it.

#### Rate Limits

Scan commands can ask for gentler limits with the config keys `rate_limit`,
`bulk_size` and `concurrency` (whole numbers from 1 to `core.MaxScanLimit`;
anything else fails the command). The executor puts them in
`ScanOptions.RateLimit`, `BulkSize` and `Concurrency`; a scanner applies
them with `core.CapScanLimit(requested, own, ceiling)`, so a scan never runs
above the ceiling the sensor's operator configured. Rate-limit flags in extra
args (`core.RateLimitToolFlags`: `-rate-limit`, `-bulk-size`, `-c`,
`-per-host-rate-limit`, ...) are refused, so they cannot get around it.

`core.TemplateCache` additionally requires the tenant ID to be a UUID and the
template type to be on the allowlist (both become path components), checks
that every written path stays inside the cache directory, and scopes cache
hits per tenant and template type.

### 5. Scan Target Validation (command path)

`core.DefaultCommandExecutor` validates every server-supplied scan target
with a `core.ScanTargetPolicy` before a scanner runs:

- Network targets (URLs, hosts, IPs, CIDRs, image refs): only `http`/`https`
  URL schemes; loopback, link-local (incl. `169.254.169.254` IMDS), CGNAT,
  multicast, unspecified and reserved ranges are always blocked; RFC1918/ULA
  are blocked unless private targets are allowed. Hostnames are resolved and
  every address is checked (fail closed for dotted names).
- Filesystem targets: symlinks are resolved first; with allowed roots set the
  path must be inside one of them, otherwise `/`, system directories
  (`/etc`, `/proc`, ...) and home credential dirs (`~/.ssh`, `~/.aws`, ...)
  are refused. The scanner receives the resolved path.
- Targets starting with `-` (flag injection) or containing control
  characters are refused; so are flag-like `exclude` entries.

```go
exec := core.NewDefaultCommandExecutor(pusher)
exec.SetScanTargetPolicy(&core.ScanTargetPolicy{
    AllowedRoots: []string{"/workspace"},
    AllowPrivate: true, // on-prem sensor scanning its own network
})
```

| Variable | Effect |
|----------|--------|
| `OPENCTEM_SDK_SCAN_ROOTS` | Allowed roots (`:`-separated) for the default policy |
| `OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS=1` | Allow RFC1918/ULA targets (`SENSOR_ALLOW_PRIVATE_TARGETS=1` — or its pre-rename name `AGENT_ALLOW_PRIVATE_TARGETS=1`, read with a deprecation warning — and `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE=1` are honored too; setting the sensor and agent names to different values refuses every target) |

#### A sensor without a local policy: fail closed or legacy

The sensor-local policy (`/etc/openctem/sensor-policy.yaml`, or the
`SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` shorthands) is the network
owner's limit on what the sensor scans. It holds even against a compromised
platform or a TLS man-in-the-middle on the control path: those can send any
job, but cannot make the sensor scan outside its policy (api RFC-040). A
sensor with no policy depends on whether it **requires** one:

| | No policy, required (new installs) | No policy, legacy |
|---|---|---|
| Job with a network target (URL, host, IP, CIDR, image reference) | Refused before any tool starts: `refused by local policy: no_local_policy: ...` | Admitted outside the built-in deny list |
| Job without network targets (repository or filesystem scan, health check, collector, content refresh) | Runs | Runs |
| Custom templates, out-of-band callbacks (interactsh) | Refused (`no_local_policy`) | Allowed (templates still need a signature) |
| `LocalPolicy.CheckTarget` called directly (retests, tool tasks) | Every network target refused | Built-in deny list: loopback, link-local and `169.254.169.254`, multicast, unspecified, CGNAT, reserved, private unless the private-range switch |
| Kill switch | Applies | Applies |
| Report (`local_policy`) | `{"state": "absent", "required": true}` | `{"state": "absent", "required": false}` |

Whether the sensor requires a policy:

1. `SENSOR_REQUIRE_LOCAL_POLICY=true|false`, when set, wins.
2. Otherwise a sensor whose key-bound identity was paired by this SDK
   requires one: pairing writes `"require_local_policy": true` into
   `<state dir>/identity/identity.json` (`identity.Identity.RequireLocalPolicy`).
3. An identity written by an older SDK has no such field, and a bearer-key
   sensor has no identity: both are legacy installs and keep their behavior,
   with a warning at start and `required: false` in the report so the
   platform can flag them.

The start log names the mode (`Local policy mode: fail closed ...` or a
`legacy install` warning), and the config report's `policy.local` check is
`fail` with code `required_absent` while a required policy is missing.

**Upgrade.** Existing paired sensors are unchanged until they set
`SENSOR_REQUIRE_LOCAL_POLICY=true` or pair again (a re-pair writes a new
identity, which requires a policy). Sensors paired from this release on fail
closed without a policy: install the policy file, or set
`SENSOR_ALLOWED_RANGES`, before they run network scans; or set
`SENSOR_REQUIRE_LOCAL_POLICY=false` to keep the legacy behavior on purpose.

#### Posture report

The manifest reports what the platform needs to flag an unhardened sensor
(sent only to a platform that lists the hello feature named in brackets):

| Member | Values | Meaning |
|---|---|---|
| `local_policy.state` (`local_policy`) | `enforced`, `absent` | A policy is loaded or not |
| `local_policy.required` (`local_policy`) | `true`, `false` | Without a policy, network jobs are refused (`true`) or admitted (`false`, legacy). Also on every heartbeat |
| `posture.platform_tls.pin` (`posture`) | `fingerprint`, `ca_file`, `none` | Platform requests over HTTPS trust only a pinned TLS identity (the pin stored at pairing, or `SENSOR_CA_FINGERPRINT`); a private CA file (`SENSOR_CA_CERT_FILE`) besides the system trust store; or the system trust store only |
| `posture.sandbox.mode` (`posture`) | `off`, `auto`, `required` | `SENSOR_SANDBOX` |
| `posture.sandbox.sandboxed` (`posture`) | `true`, `false` | Tool runs go through the sandbox launcher |
| `posture.sandbox.network_enforced` (`posture`) | `true`, `false` | Each tool run's network is confined to its forwarder (`SENSOR_SANDBOX_NETWORK`) |

The gRPC transport always pins its own CA bundle; `platform_tls.pin` is
about the HTTPS requests (pairing, protocol v2, the HTTPS binding, the
certificate requests that fetch that bundle). See
[Platform TLS pin](#platform-tls-pin-stored-at-pairing).

#### Domain patterns in `targets.allow` and `targets.deny`

| Entry | Covers |
|---|---|
| `x` | exactly `x` |
| `*.x` | `x` and every name below it, at any depth |

This is the platform's reading of a scope pattern (api RFC-054 §4.1), so a
sensor allow list and a platform scope entry cover the same names. The deny
list uses the same matcher: `*.x` in `targets.deny` also denies `x`. Names
are compared lower-case, without one trailing dot, in their IDNA ASCII form;
`*.x` never matches a name that only ends with the same letters
(`notx`, `x.evil.net`). A wildcard of a single label (`*.com`) is refused
when the policy loads.

#### Refused targets: per target, never the whole job

A scan job's target that a policy refuses, or that cannot be checked, is
removed from the job; the job runs on the rest. This applies at two points:
the poller's admission against the sensor-local policy
(`LocalPolicy.AdmitCommandTargets`, before any executor sees the command),
and the executor's own check right before the scanner starts.

| Reason (`refused_targets[].reason`) | When |
|---|---|
| `unresolvable` | A dotted host name that does not resolve (NXDOMAIN, resolver failure): its addresses cannot be checked |
| `wildcard_pattern` | A pattern such as `*.example.com`: not a host a policy can check or a tool can reach |
| `denied_by_policy` | Outside `targets.allow`, inside `targets.deny`, a private address without the switch, the built-in deny list, a port outside `ports.allow` |
| `invalid_target` | Not a URL, host, address, range or path, or unsafe to hand to a tool (a leading `-`, control characters) |

- The command completes with `metadata.refused_targets` (at most 100
  entries of `{target, reason, rule, detail}`), `metadata.refused_targets_total`
  and `metadata.partial: true`.
- When every target is refused, or the single target of a single-target job
  (payload `target`), the command fails as before; the error lists the
  targets and reasons.
- A retest or validation command is not rewritten: one refused target
  still refuses it whole.
- A refused target is never handed to an executor or a tool, so a result
  cannot carry data for it. The admission and every refused target are in
  the command's log on the platform (see *Per-command logs* below) and on
  the sensor's standard output.

**DNS rebinding.** Admission resolves a name and checks every address. The
executor resolves and checks again immediately before the scanner starts,
so a name that now resolves to a denied address is refused there. In-process
dials made through `LocalPolicy.DialContext` (and the egress forwarder)
check each connection and connect only to the addresses they checked.
External scanner binaries (nuclei, httpx, ...) resolve the name once more
themselves. The window between the executor's check and the tool's own
lookup is not closed for them. To close it, route the tool through the egress
forwarder, or list addresses instead of names in `targets.allow`.

#### Signed jobs

The platform's job signer is a process apart from the API (api RFC-040
§5.6, `docs/architecture/job-signing.md` in openctemio/openctem): it holds
the signing key, checks every job against its own rules and signs a
statement for each command a claim hands out. A sensor that pins the
signer's key runs only what the signer signed, so whoever can write the
commands table or run code in the API can no longer decide on their own
what the sensor scans.

The claim answer (protocol v2 claim and claim-N, protocol v3
`ClaimCommands`) carries `signed_job`, a DSSE envelope:

```json
{"payloadType": "application/vnd.openctem.job.v1+json",
 "payload": "<standard base64 of the statement bytes>",
 "signatures": [{"keyid": "SHA256:<64 hex>", "sig": "<standard base64 Ed25519>"}]}
```

`pkg/jobsig` verifies it, and the `CommandPoller` (`SetJobGuard`) does so
right after the claim, in claim order, before the command is started and
before the local policy, the command gate or any executor sees it:

1. the payload type is `application/vnd.openctem.job.v1+json`;
2. a signature verifies, with Ed25519 over the DSSE pre-authentication
   encoding of the exact payload bytes, under a pinned key or, when the
   sensor pins a root, a key of the root's current key set (below). The
   keys are indexed by their recomputed id (`SHA256:` + hex SHA-256 of
   the raw key); a signature's `keyid` only selects a key;
3. only then is the statement parsed: one JSON object, no unknown field,
   `kind` `openctem.job/v1`, `signer.keyid` the key that verified;
4. `tenant_id` and `sensor_id` are the sensor's own (from its identity),
   `command_id` and `command_type` those of the command being run;
5. `issued_at` within 2 minutes of the sensor's clock, `expires_at` in the
   future and at most 1 hour after `issued_at`;
6. `lease_epoch` is the epoch of the claim answer;
7. `payload_sha256` is the SHA-256 of the command's `payload` bytes as the
   claim answer carried them (kept as `json.RawMessage`, never
   re-encoded), and the `tool`, `targets` and custom `templates` (their
   SHA-256 digests, in order; absent when there are none) the statement
   names are those that payload names: what the signer checked is what
   runs. A sensor on an older SDK refuses a statement that carries
   `templates` (unknown field): jobs with custom templates fail closed
   there;
8. the nonce was not seen before (kept until its statement expires,
   bounded), and `seq` is above the last one accepted from that key. The
   new `seq` is written to `<state dir>/job-signing-seq.json` (temporary
   file, fsync, rename, directory fsync) before the job is accepted, so a
   restart does not open a replay window. A corrupt file stops the sensor.

A command that fails any check, or comes unsigned to a sensor that
requires signed jobs, is failed from the claimed state with a structured
refusal (layer `builtin`, rule `job_signature`) and the reason, logged
locally and in the command's log, and never started or run. Nothing is
retried on another key or relaxed by anything the platform sends.

| Setting | Effect |
|---|---|
| `SENSOR_JOB_SIGNING_KEYS` | Pins signer keys, comma-separated: key ids (`SHA256:<hex>`, as the platform shows them; the public key then comes from the hello, used only when its recomputed id is pinned) or base64 Ed25519 public keys. Added to the keys pinned at pairing. |
| `identity.json` `job_signing_keys` | Pairing reads the hello right after the confirmation, over the pinned and signed pairing connection, and pins the keys it lists (trust on first use; a listed key whose id is not its own is dropped). |
| `SENSOR_REQUIRE_SIGNED_JOBS` | `true`: every command needs a valid signed job. `false`: unsigned commands run, signed ones are still verified when a key is pinned. Unset: `true` when the identity pinned keys at pairing, else `false`. |

Verification needs the sensor's own organization and id, which a paired
(key-bound) sensor knows: a bearer-key sensor with signer keys or
`SENSOR_REQUIRE_SIGNED_JOBS=true` refuses to start, and so does a sensor
that requires signed jobs without a pinned key. The manifest's posture
reports `jobs.signed`: `required`, `verified_when_present` or `off`.

##### The offline root and the key set

A sensor that pins an online signer key must be paired again when that key
changes. Instead it can pin the installation's **root** (api RFC-040 §5.6
K3): an Ed25519 key kept offline by the installation owner, which signs a
**key set**, the online keys a sensor accepts, with a version that only
goes up and an expiry at most 30 days out. Rotating or revoking a signer
key is then a new key set; no sensor is paired again. The platform serves
the current key set in hello (`signed_jobs.keyset`) and changes the
doorbell's `config_version` when it changes. Format and the operator
ceremony: `docs/architecture/job-signing.md` in openctemio/openctem ("Key
sets and the offline root"); the shared test vector is
`pkg/jobsig/testdata/keyset_vector.json`.

`pkg/jobsig` (`KeySetTrust`, `VerifyKeySet`) accepts a key set only when:

1. the envelope (at most 64 KiB) has payload type
   `application/vnd.openctem.keyset.v1+json` and the payload decodes as
   one object with no unknown field: `kind` `openctem.keyset/v1`,
   `version` ≥ 1, `not_after` after `issued_at` and at most 30 days later,
   1 to 16 keys whose ids are their own, no duplicate, never the root;
2. `root_keyid` is the **pinned** root, `root_public_key` is the key of
   that id, and its Ed25519 signature over the PAE of the exact payload
   bytes verifies;
3. `issued_at` is at most 2 minutes ahead of the sensor's clock and
   `not_after` later than the clock minus 2 minutes;
4. its version is not below the accepted one (rollback), and the same
   version only with the same bytes. A newer key set is written to
   `<state dir>/job-signing-keyset.json` (fsync, rename) before it is used,
   so a restart keeps the version; a corrupt file, or one of another root,
   stops the sensor.

The sensor fetches the key set from hello at start, again before the next
job check when the doorbell's `config_version` moved, and when a job is
signed by a key the current key set does not list (at most every 30
seconds). With a root pinned and no valid key set (none yet, expired, or
the platform's refused), every signed job is refused with rule
`job_keyset`, and a job signed by a key the key set no longer lists with
rule `job_signature`: fail closed. The sensor warns from 7 days before the
key set expires; the posture reports `jobs.root`, `jobs.keyset_version` and
`jobs.keyset_expires_at`.

| Setting | Effect |
|---|---|
| `SENSOR_JOB_SIGNING_ROOT` | Pins the root: its key id (`SHA256:<hex>`, as `openctem-signer root keygen` prints it) or base64 Ed25519 key. Overrides the root pinned at pairing. The strongest pin: the network owner sets it from the installation owner's record, not from the platform. |
| `identity.json` `job_signing_root` | Pairing pins the root of the key set the hello serves (trust on first use over the pinned and signed pairing connection), only when that key set is signed by it and current. |

With a root pinned, the online keys pinned at pairing (`job_signing_keys`)
are not used: the key set decides, so a revoked key is refused. Keys in
`SENSOR_JOB_SIGNING_KEYS` are still accepted next to the key set (an
operator's explicit choice). A root pinned at pairing makes signed jobs
required, as pinned keys do.

The local policy schema has no signer settings: v1 is frozen, so the root
and the keys live in the environment and the identity. Not covered yet:
the signed scope document the sensor would check targets against besides
its local policy.

#### Per-command logs of the poller

With a log sink (`CommandPoller.SetCommandLogSink`; `sensorkit` wires its
log shipper), the poller writes its own lines to the command's log, tagged
`source: sensor`:

- the command was received;
- the local policy check, each refused target with its reason, and a
  refusal before running;
- the platform tool gate's refusal;
- the outcome: completed, completed with skipped targets, failed, timed out,
  or stopped by the kill switch;
- a hand-back to the platform (no free slot, busy hosts, drain), logged once
  per command and reason.

A command refused before any tool started therefore still has a log that
says why. The lines are redacted and bounded like a tool's lines. They are
queued through the outbox ahead of the command's result. Lines for a
hand-back are sent directly before the release, because the platform does
not take this sensor's lines after that.

### 6. Scanner Process Environment

Scanner child processes no longer inherit the sensor's whole environment
(which holds the API key). They get an allowlist: `PATH`, `HOME`, temp and
locale vars, proxy and CA-bundle vars, Docker host vars, `XDG_*`, and the
`TRIVY_*` / `NUCLEI_*` / `SEMGREP_*` / `BETTERLEAKS_*` / `GITLEAKS_*` / `CODEQL_*` and ProjectDiscovery (`SUBFINDER_*`, `HTTPX_*`, `DNSX_*`, `NAABU_*`, `KATANA_*`, `PDCP_*`) namespaces, plus any
variables set explicitly in the scanner config or scan options.

| Variable / API | Effect |
|----------------|--------|
| `OPENCTEM_SDK_SCANNER_ENV_ALLOW=AWS_*,GITHUB_TOKEN` | Pass extra names (`*` suffix = prefix) |
| `core.SetScannerEnvAllowlist([]string{...})` | Same, programmatically |
| `OPENCTEM_SDK_SCANNER_INHERIT_ENV=1` / `core.SetScannerInheritEnv(true)` | Restore full inheritance (not recommended) |

Every process the SDK starts gets it: scanners (`core.ExecuteScanner`,
`core.StreamScanner`, `BaseScanner.Scan`, and the sensor's tool wrappers built on them), version
probes (`core.VersionOutput`, `core.CheckBinaryInstalled`,
`BaseScanner.IsInstalled`), content downloads (`core.ContentEnviron`) and
the `git diff` of the sensor's CI-mode strategy (which also keeps the `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_CEILING_DIRECTORIES` and `GIT_CONFIG_*` variables
that locate the repository). The sensor's key (`API_KEY`, `SENSOR_*`,
`OPENCTEM_*`), the outbox key, tokens and passwords are not on the list.
Two things on it can carry a secret by the operator's choice: the proxy
variables, which may hold `user:password` (scanners stop getting them with
`SENSOR_SCAN_PROXY=direct` / `core.ScannerProxyDirect`; content downloads
follow `SENSOR_CONTENT_PROXY`), and the tools' own namespaces, such as
`TRIVY_PASSWORD` or `PDCP_API_KEY`, which are that tool's credentials.

A task of the tool contract (`toolhost`) gets a namespace only when it is
its own (`core.ScannerEnvironFor`):
- trivy gets `TRIVY_*` and the container runtime variables (`DOCKER_HOST`, `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `CONTAINER_HOST`);
- semgrep gets `SEMGREP_*`;
- betterleaks gets `BETTERLEAKS_*` and `GITLEAKS_*`;
- codeql gets `CODEQL_*`;
- each ProjectDiscovery tool gets its own prefix plus `PDCP_*`.

A tool the operator installed (a manifest with a run section) gets no
vendor namespace: its credentials are the ones its manifest declares,
delivered in the run message. Names the operator allows explicitly
(`OPENCTEM_SDK_SCANNER_ENV_ALLOW`) and variables the caller passes still
reach any tool.

### 7. Per-task tool sandbox (`pkg/sensorkit/executor`)

Every tool run goes through one executor. A backend takes a generic task
(argv, environment, working directory, writable paths, limits, network class)
and runs it; it knows nothing about the tool. The `process` backend re-executes
the program's own binary as a launcher (call `executor.RunLauncherIfRequested()`
first thing in `main`), which confines itself and then becomes the tool:

| Control | What it stops |
|---|---|
| Private task directory (HOME, TMPDIR, XDG_*), removed after the task; the task root (`executor.TaskRoot()` and the backend's `WorkRoot`, 0700, owned by the sensor's user) is hidden from every task but its own directory | leftovers between tasks, writes into the sensor's home, one task (on a shared sensor, one tenant's) reading or listing a concurrent task's files |
| RLIMIT_DATA, RLIMIT_NPROC (the user's current count plus the task's allowance), RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_CORE=0, RLIMIT_CPU when set | memory exhaustion, fork bombs, disk filling, core dumps of secrets |
| no_new_privs | setuid and file-capability escalation |
| Landlock (Linux 5.13+; works under Docker's default seccomp profile) | writes outside the task directory and the declared write paths; reads of the protected paths (credentials file, outbox and its key, local policy, configuration), including through symlinks that lead into them |
| seccomp filter | ptrace, process_vm_*, mount/namespaces (also clone with namespace flags; clone3 answers ENOSYS), kernel modules, kexec, keyrings, bpf, perf, clock changes, file handles, userfaultfd; a syscall from another ABI kills the task |
| Process group, killed whole on timeout or cancel | stray children |
| The sensor is non-dumpable | reading its memory, environment or open files through /proc |
| Network confinement (`Config.ConfineNetwork`, api RFC-060): its own user, network and mount namespaces per task, only loopback, a relay on 127.0.0.1:1080 (proxy) and :53 (DNS) to the task's forwarder (`pkg/sensorkit/egress`); the tool runs as a child of the launcher with no capabilities (`SECBIT_NOROOT` locked, empty bounding set) | any connection or lookup that does not go through the forwarder: a tool that ignores the proxy, raw sockets, DNS exfiltration, the sensor's own loopback services |

**Network confinement requires unprivileged user namespaces.**
- In a container, the seccomp profile must allow `unshare` and `clone` with the user, network and mount flags; the runtime's default profile refuses them.
- On a host with `kernel.apparmor_restrict_unprivileged_userns=1`, an AppArmor profile must grant the sensor binary `userns`.
- Where neither is in place, `Status.NetworkEnforced` is false and `Status.NetworkMissing` says why. With `SENSOR_SANDBOX_NETWORK=auto` (the default) tasks then run unconfined with a warning; with `required` (shared sensors) the sensor refuses to start.

**Content packs (api RFC-061).** A tool's templates, rules and wordlists are packs in the sensor's content cache. That cache is a private root hidden from every task (`executor.Config.Private`). A task gets read-only grants for exactly its own packs (`TaskSpec.ReadPaths`, checked by `tool.CheckTaskContent` against the manifest's slots and against `toolhost.Host.ContentRoot`). One tenant's task cannot read another tenant's packs, and a job cannot point a task at any other path.

**What a confined task may reach (the tool host).** Every task whose manifest network is not `none` gets its own forwarder, and every refused destination is a warning line in the task's command log and an entry in `Outcome.Egress`:

| Manifest `permissions.network` | Forwarder scope |
|---|---|
| `targets` | The admitted targets only. Names are dialed at the addresses the local policy admitted (`core.LocalPolicy.AdmittedAddrs`) and never resolved again; IP and CIDR targets as given |
| `vendor` | The manifest's vendor hosts, at public addresses |
| `egress-proxy` | Any public address. Loopback, private ranges, link-local and cloud metadata addresses are refused |
| `none` | Nothing: no forwarder, no way out |

A tool that dials raw sockets without honouring the proxy variables gets "network unreachable" when confined; it must connect through the proxy (HTTP CONNECT or SOCKS5).
- Where `/etc/resolv.conf` cannot be bind-mounted (a profile that denies `mount`), the relay answers on each address the file names instead.

Modes (`SENSOR_SANDBOX` for sensorkit): `auto` (default) enforces what the
host supports and logs what it cannot; `required` refuses to start unless
every control is enforced; `off` runs tools as plain child processes. Each
`ExecResult.Sandbox` records what the run was under. Residual risks: without a
separate user per task, a task can still send signals to processes of the same
user (Landlock signal scoping needs Linux 6.12), and a task that escapes its
process group with `setsid` is bounded by its rlimits but not killed with the
group. The sandbox never uses a Docker socket; future backends (a Kubernetes
Pod per task, a rootless container) plug in behind the same interface.

### 8. Web scope of a job (`pkg/webscope`)

A job can carry a web scope (`web_scope`): the hosts (`app.example.com`, or
`*.example.com` for the domain and every name under it), the path prefixes
and the methods a web tool may request, and paths it never requests
(`deny_paths`, such as `/logout` or `/admin`). The platform sets it, and the
SDK enforces it:

- `tool.Context.HTTP` refuses every request outside the scope before it is
  sent, and each redirect is checked as a new request. The path is checked as
  the server sees it: percent-decoded, with dot segments resolved and
  backslashes as slashes. A path with an encoded slash, backslash or NUL is
  refused. Deny paths match by prefix, ignoring case, so over-blocking is the
  failure mode. Without `methods`, only GET, HEAD and OPTIONS are allowed.
- A networked tool that does not declare `features.web_scope` is refused a
  job with a web scope, because it would run unrestricted. An invalid scope
  is refused too, never ignored. A scanner that cannot take capability jobs
  fails such a job (`core`).
- An exec-profile tool reads the scope from `{{task.web_scope_file}}` (JSON;
  `null` without one). A sensor wrapper maps it onto its tool's flags.
- The conformance kit's `crawl.web` and `dast.web` suites point the tool at a
  site that links to denied paths (links, a redirect, a form, a script, dot
  segments, upper case). They fail a tool that requests any of them.

### 9. API Client Transport

- API clients (`pkg/client`, `pkg/platform`) refuse HTTP redirects; the API
  never issues them and following one would forward the bearer key.
- They only ever talk to the operator-configured base URL, so they do not
  apply the scan-target IP blocklist: a platform on loopback, RFC1918, ULA
  or CGNAT (Tailscale) addresses works without any opt-in. Link-local
  (including the cloud metadata service), multicast, reserved and
  unspecified addresses are still refused, and `HTTP(S)_PROXY` / `NO_PROXY`
  are honored. `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE` is no longer needed to
  reach the platform; it only widens what scanners and collectors may reach.
- Other `httpsec.SafeHTTPClient` users follow redirects but never downgrade
  https to http, and strip credential headers on any origin change.
- The base URL must be `http`/`https` with a host and no embedded
  credentials; plain `http` to a non-loopback host logs a warning.
- Response bodies are capped (10 MiB success, 64 KiB error) and error text
  is truncated.

#### Platform TLS pin stored at pairing

Pairing records the platform's TLS identity in `identity/identity.json`
(api RFC-040 §11.4 Q10), and every platform client the SDK builds enforces
it from then on: protocol v2, the v3 HTTPS binding, the certificate requests
of the gRPC binding, and the pairing requests themselves.

```json
"platform_tls_pin": "sha256:<64 hex digits>",
"platform_tls_pin_element": "anchor_spki"
```

| `platform_tls_pin_element` | Fingerprint of | Recorded when |
|---|---|---|
| `anchor_spki` | the SubjectPublicKeyInfo of the trust anchor of the chain the pairing connection verified: the root CA the trust store (system roots plus `SENSOR_CA_CERT_FILE`) found, or the platform's self-signed certificate | pairing over HTTPS without `SENSOR_CA_FINGERPRINT` |
| `ca_cert` | a CA certificate in the presented chain (the `SENSOR_CA_FINGERPRINT` semantics) | `SENSOR_CA_FINGERPRINT` was set at pairing |

Why the anchor's key: servers rarely send their root, so the pin must be on
something the sensor builds itself, which the verified chain is. A leaf or
intermediate pin would break on routine renewal (public CAs rotate their
issuing intermediates on their own); the anchor's key survives leaf and
intermediate rotation and a re-issued root certificate with the same key. A
certificate from any other CA, such as a TLS-inspecting proxy whose CA is in
the trust store or a publicly trusted certificate from another CA, leads to
another anchor and is refused. The trust store still checks the chain, name
and validity first: the pin narrows it and never widens it. It does not
stop a mis-issued certificate from the same CA; for that, and for the
first contact itself (the pin is learned on first use, inside the pairing
whose fingerprint an administrator compares), pin with
`SENSOR_CA_FINGERPRINT` from the install snippet.

- Within one pairing, every request must lead to the anchor of the first;
  a change is refused (`httpsec.ErrPlatformChangedDuringPairing`).
- A mismatch afterwards is a hard error on every request, never a fallback
  to the system roots: `platform certificate does not match the pin stored
  at pairing; re-pair or set SENSOR_CA_FINGERPRINT`.
- `SENSOR_CA_FINGERPRINT` always wins over the stored pin (and is what a
  pairing stores when set). Re-pairing records a new pin: that is the way
  to move a sensor to a platform behind another CA.
- An identity without the fields (paired by an older SDK, or over plain
  http) keeps trusting the trust store, reports `pin: none`, and logs a
  start-up warning.
- A malformed pin stops the sensor rather than run unpinned.

**Protocol v3 gRPC CA bundle.** The gRPC binding trusts only the CA bundle
of the platform's certificate service, fetched with the client certificate
(`transport-v3-platform-ca.pem` next to the identity). The bundle is
sticky: a different one replaces it only when it arrives over a pinned
channel (the gRPC binding itself, or the HTTPS binding of a sensor with a
platform TLS pin); a change of the advertised gRPC endpoint alone never
replaces it. A gRPC endpoint whose certificate does not verify against the
bundle is a hard error (`platform_certificate_refused`): the client sends
nothing, on no binding, and negotiates again about every minute. Only
network and protocol-level failures (unreachable, HTTP/2 refused, stream
resets, unimplemented) fall back to the HTTPS binding. With
`SENSOR_TRANSPORT=grpc` the client never uses the HTTPS binding or v2,
even when the platform's hello lists no protocol v3.

---

## Security Best Practices

### 1. Credential Management

```go
// DO: Use encrypted storage in production
store, _ := credentials.NewEncryptedFileStore(path, encryptor)

// DO: Clear credentials when done
defer credentials.SecureClear(cred)

// DON'T: Store credentials in plain files
store := credentials.NewFileStore(path)  // Only for non-sensitive data
```

### 2. Transport Security

- Point `API_URL` (`client.Config.BaseURL`) at an `https://` URL outside a
  private network; plain `http` to a non-loopback host logs a warning.
- Never disable certificate verification. Trust a private CA with
  `SENSOR_CA_CERT_FILE`, and pin it with `SENSOR_CA_FINGERPRINT` (from the
  install snippet). Without it, pairing pins the CA it verified.

### 3. Sensor Configuration

```go
// DO: Restrict allowed job types
config := &platform.PollerConfig{
    AllowedJobTypes:     []string{"scan"},
    RequireAuthToken:    true,
    ValidateTokenClaims: true,
}

// DO: Use secure lease identity (default)
leaseConfig := &platform.LeaseConfig{
    IdentityPrefix: "scanner",  // Identify sensor type
}

// DON'T: Disable security features
useSecure := false
leaseConfig := &platform.LeaseConfig{
    UseSecureIdentity: &useSecure,  // Only for testing
}
```

### 4. Environment Variables

```bash
# DO: Use environment variables for secrets
export API_KEY="<sensor key>"   # or pair the sensor and set no key at all

# DON'T: Commit secrets to version control
# api_key: "<key>"  # Never do this!
```

---

## Security Audit Checklist

### Credentials
- [ ] Using `EncryptedFileStore` for sensitive data
- [ ] Encryption key stored securely (not in config files)
- [ ] `SecureClear()` called after credential use
- [ ] Key validation enabled (automatic)

### Transport
- [ ] `API_URL` uses `https://` in production
- [ ] A private CA is trusted with `SENSOR_CA_CERT_FILE`, never by skipping verification
- [ ] The sensor reports `posture.platform_tls.pin: fingerprint` (paired by this SDK, or `SENSOR_CA_FINGERPRINT`)

### Platform Sensors (`pkg/platform`, platform control plane only)
- [ ] `AllowedJobTypes` configured (whitelist)
- [ ] `RequireAuthToken` enabled
- [ ] `ValidateTokenClaims` enabled
- [ ] Secure lease identity enabled (default)
- [ ] Lease expiry callback handles graceful shutdown

### Signed jobs

- [ ] Paired sensors pin the job-signing root (`SENSOR_JOB_SIGNING_ROOT`, or `identity.json` `job_signing_root`), or the signer itself (`job_signing_keys`, `SENSOR_JOB_SIGNING_KEYS`)
- [ ] `posture.jobs.keyset_expires_at` is more than 7 days away; `<state dir>/job-signing-keyset.json` is on a persistent volume
- [ ] `posture.jobs.signed` is `required` everywhere the platform signs jobs
- [ ] `<state dir>/job-signing-seq.json` is on a persistent volume

### Templates
- [ ] Template validation enabled (automatic)
- [ ] Content hashes verified (if provided)
- [ ] Template directory properly sandboxed

---

## Reporting Security Issues

Report vulnerabilities privately to security@openctem.io. Do not open a public
issue. See [SECURITY.md](../SECURITY.md) for what to include and the response
targets.
