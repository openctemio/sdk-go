# SDK Security Guide

This document describes the security features and best practices for the OpenCTEM SDK.

---

## Security Features

### 1. Credentials

A tool declares the secrets it needs in its tool contract (`pkg/tool`). The
runtime passes a tool only the settings the scanner environment allowlist
names (`pkg/core/scanner_env*.go`) and never writes a secret into a task or a
log. The SDK keeps no credential store of its own.

### 2. Transport

`pkg/client` speaks sensor protocol v2 over HTTPS and, for a key-bound
sensor, sensor protocol v3 (`pkg/sensorproto/v3`, api RFC-059):
gRPC with mutual TLS when the platform advertises it, else the HTTPS binding,
else v2. A network failure of the gRPC binding is remembered in the
certificate directory and retried after a backoff (from 30 minutes, doubling,
at most 4 hours); a platform that offers no gRPC yet is asked again every few
minutes. An identity refusal (the platform refused the key or certificate)
never falls back: the client sends nothing but hello and the heartbeat until
the identity is accepted again.

### 3. Template Security

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

A command's custom templates (a scan's, or a retest's, see below) run only when something the sensor pins
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

After the signature check, every custom template's content is checked on
the sensor (`core.CheckCustomTemplate`): a nuclei template with a `code`,
`javascript`, `flow`, `file` or `headless` block (keys compared without
regard to case), a self-contained template or request (at any depth), a `# !include:` directive, `workflows`, a payload list
loaded from a file, or a second YAML document is refused and the command
fails before anything is written. Because every custom template passes
this check, a scanner may load custom templates together with its own in
one run.

The check is one function for every command type
(`core.DefaultCommandExecutor.VerifyCustomTemplates`). A **retest** command
may carry custom templates too (`custom_templates`, optionally
`custom_templates_envelope`, and items whose `template` names one of them):
the kit refuses it unless the retest's tool opted in
(`Kit.HandleRetestTemplates`, capability `retest-templates:<tool>`), the
local policy allows custom templates, every templated item names a carried
template of that tool's type, and the templates pass the verification and
content check above. Only then are they written (`core.WriteCustomTemplates`:
a new temporary directory, 0700, files 0600, removed when the retest ends)
and the item's file handed to the tool (`tool.RetestItem.TemplatePath`,
set by the sensor, never by the platform). A templated item's `fixed` or
`still_present` verdict stands only under the delivered template's digest;
otherwise it is `unverifiable`.

#### Rule sources

A scan command says which detection rules run (`rule_sources`): `both`
(the default, also when absent), `platform` (the sensor's own rules only)
or `tenant` (the organization's custom templates only). The executor
refuses a command that contradicts itself (`platform` with custom
templates, `tenant` without any, or an unknown value) and hands the choice
to the scanner as `ScanOptions.RuleSources`. A sensor whose scanners honor
it reports `core.CapabilityRuleSources` (`rule.sources@1`); the platform
sends `tenant` jobs only to such sensors, so an older sensor never runs
platform rules for a tenant-only scan. Findings of an organization's own
rules carry rule ids prefixed with `core.TenantRulePrefix` (`tenant:`), so
they never collide with platform rule ids.

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

### 4. Scan Target Validation (command path)

`core.DefaultCommandExecutor` validates every server-supplied scan target
with a `core.ScanTargetPolicy` before a scanner runs:

- Network targets (URLs, hosts, IPs, CIDRs, image refs): only `http`/`https`
  URL schemes; loopback, link-local (incl. `169.254.169.254` IMDS), CGNAT,
  multicast, unspecified and reserved ranges are always blocked; RFC1918/ULA
  are blocked unless private targets are allowed. Hostnames are resolved and
  every address is checked (fail closed for dotted names).
- The deny list is `github.com/openctemio/ctis/addrscope` (`IsInternal`,
  `IsInternalPrefix`), the same definition the platform checks job targets
  with, so the two never disagree. An IPv6 address that carries an IPv4
  address (IPv4-mapped or -compatible, NAT64 `64:ff9b::/96` and
  `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`) is judged by that
  IPv4 address: `64:ff9b::a00:1` is 10.0.0.1 and is refused even where
  private targets are allowed (only private ranges written directly can be
  allowed, and never the metadata addresses inside ULA). The SDK's own
  outbound guard (`pkg/httpsec`) and the egress forwarder's public-only
  check use the same list.
- Filesystem targets: symlinks are resolved first; with allowed roots set the
  path must be inside one of them, otherwise `/`, system directories
  (`/etc`, `/proc`, ...) and home credential dirs (`~/.ssh`, `~/.aws`, ...)
  are refused. The scanner receives the resolved path.
- Targets starting with `-` (flag injection) or containing control
  characters are refused; so are flag-like `exclude` entries.
- With `ByScanner: true` each target is checked by the scanner that receives
  it (`ScanTargetPolicy.ValidateFor`). A code scanner (`core.IsCodeScanner`:
  semgrep, betterleaks, trivy, ...) takes a path, confined to the allowed
  roots (a relative path is taken in the first root), a repository URL
  (network-checked) or, for trivy, an image whose registry host is checked.
  Every other scanner is a network scanner: its target must be a URL, host,
  `host:port` (`203.0.113.7:80`, `[2001:db8::1]:443`, checked on the host),
  address or range, and a name that does not resolve is refused, dotless
  names included. `ScanTargetPolicy.ValidateNetworkTarget` is the same
  network check for callers outside the executor (a validation probe, a
  retest).

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
| `SENSOR_ALLOW_PRIVATE_TARGETS=1` | Allow RFC1918/ULA targets (`SENSOR_ALLOW_PRIVATE_TARGETS=1` — or its pre-rename name `AGENT_ALLOW_PRIVATE_TARGETS=1`, read with a deprecation warning — and `OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE=1` are honored too; setting the sensor and agent names to different values refuses every target) |

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

#### Ranges are cut address by address

A scan job may carry `exclusions` in its payload: the platform's scope
exclusions that touch the job's targets (addresses, CIDR prefixes and
`first-last` ranges), covered by the job signature with the rest of the
payload. Before any other check, the sensor walks each range target (at
most 2^16 addresses) and leaves out every address that the job's
exclusions, `targets.deny` or the built-in deny list (private space
without the switch included) covers. The range is replaced by the
smallest set of prefixes holding exactly the addresses kept; the rest of
the policy (for example `targets.allow`) then checks each prefix. This
also happens on a sensor without a policy file.

- An address target the job excludes is removed (rule `job_exclusions`).
- A range with nothing left is removed; a job with nothing left fails.
- A wider range that something blocks is refused whole, as before.
- A single-target job (payload `target`) whose target would be cut fails:
  it cannot run on part of its target.
- An exclusion the sensor cannot read refuses the job (rule `payload`):
  an exclusion is never dropped silently.
- The exclusions also reach the tool (`ScanOptions.ExcludeHosts`), so a
  tool that can skip hosts itself (naabu `-exclude-hosts`) skips them too.

#### Refused targets: per target, never the whole job

A scan job's target that a policy refuses, or that cannot be checked, is
removed from the job; the job runs on the rest. This applies at two points:
the poller's admission against the sensor-local policy
(`LocalPolicy.AdmitCommandTargets`, before any executor sees the command),
and the executor's own check right before the scanner starts.

| Reason (`refused_targets[].reason`) | When |
|---|---|
| `unresolvable` | A dotted host name (any name for a network scanner under `ByScanner`) that does not resolve (NXDOMAIN, resolver failure): its addresses cannot be checked |
| `wildcard_pattern` | A pattern such as `*.example.com`: not a host a policy can check or a tool can reach |
| `denied_by_policy` | Outside `targets.allow`, inside `targets.deny`, a private address without the switch, the built-in deny list, a port outside `ports.allow` |
| `invalid_target` | Not a URL, host, address, range or path, or unsafe to hand to a tool (a leading `-`, control characters) |

- The command completes with `metadata.refused_targets` (at most 100
  entries of `{target, reason, rule, detail}`), `metadata.refused_targets_total`
  and `metadata.partial: true`. A target the executor's built-in check (the
  scan-target guard, not a local policy rule) refused has rule
  `target_guard` (`core.RefusedTargetRuleGuard`).
- Each refused target's per-target outcome (`target_outcomes`) is
  `skipped` with class `refused`: it is settled, not handed out again.
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

A confined task's forwarder (section 7) dials a name only at the addresses
pinned for the task, and every pinned address has passed a check: the
policy's `AdmittedAddrs`; without it, the policy's target check applied to
each address of the tool host's own lookup (a local policy without a file
applies the built-in deny list). A tool host with no policy at all (a CI
run, whose admission checks no target either) pins a name as it resolves.
A name re-bound to a private, loopback, CGNAT, link-local or
metadata address between admission and task start is therefore never
pinned, and a tool that resolves it again through the forwarder's DNS gets
the pinned addresses back.

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
   `command_id` and `command_type` those of the command being run. A
   statement that carries `sensor_scope` is refused by an organization's
   sensor. A shared sensor (shared mode) instead requires `sensor_scope`
   `instance` and its own `sensor_id`, accepts any `tenant_id`, and binds
   the job's results to it (below);
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

### 5. Scanner Process Environment

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
that locate the repository). The sensor's key (`SENSOR_API_KEY`, `SENSOR_*`,
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

### 6. Per-task tool sandbox (`pkg/sensorkit/executor`)

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
| `targets` | The admitted targets only. Names are dialed at the addresses the local policy admitted (`core.LocalPolicy.AdmittedAddrs`) and never resolved again; those addresses are also admitted when the tool dials them itself (it resolved the name through the forwarder's DNS, which answers with them: a port scanner does), each address alone, with the same ports and limits as its names, never its range; IP and CIDR targets as given |
| `vendor` | The manifest's vendor hosts, at public addresses |
| `resolver` | No connection at all. DNS questions about the admitted targets are answered (A and AAAA from the admitted addresses, other record types from the sensor's resolver); any other name is NXDOMAIN |
| `egress-proxy` | Any public address. Loopback, private ranges, link-local and cloud metadata addresses are refused |
| `none` | Nothing: no forwarder, no way out |

A tool that dials raw sockets without honouring the proxy variables gets "network unreachable" when confined; it must connect through the proxy (HTTP CONNECT or SOCKS5).
- A target the scope refused every connection toward is never reported done: the tool host settles it as failed with class `egress_refused` (ctis outcome), the task is at best partial, and the task log says how many targets the confinement kept the tool from reaching. When the scope refused every connection of the task and allowed none, every target the tool reported done is settled so. `Outcome.EgressTally` has the counts, in all and per target.
- Where `/etc/resolv.conf` cannot be bind-mounted (a profile that denies `mount`), the relay answers on each address the file names instead.
- Target names are looked up exactly as written, never with a search domain appended. The task's `/etc/resolv.conf` names only the relay and has no `search` or `domain` line, and the SDK's own lookups use absolute names (a trailing dot). Where the host's file cannot be replaced, a tool's resolver may still append the host's search domain (`app.example.com.lan`). The forwarder answers such a name NXDOMAIN, never resolves it, and does not record it as a refusal. The doctor notes search domains on the host (`network.dns_search`, information only).
- No forwarded connection outlives its task. The forwarder stopping (the task ended, was canceled or timed out) closes every connection it serves, on both sides, at once; an upstream connection whose host sends nothing for `egress.Limits.UpstreamIdle` (default 2 minutes) is closed even while the task runs, and a tunnel whose host side broke closes its client side too. The tool host waits at most 10 seconds for the forwarder to stop and then finishes the task anyway, with a warning line in its command log. A host that accepts a connection and never answers therefore cannot hold a finished task, or its command, open.

Modes (`SENSOR_SANDBOX` for sensorkit): `auto` (default) enforces what the
host supports and logs what it cannot; `required` refuses to start unless
every control is enforced; `off` runs tools as plain child processes. Each
`ExecResult.Sandbox` records what the run was under. Residual risks: without a
separate user per task, a task can still send signals to processes of the same
user (Landlock signal scoping needs Linux 6.12), and a task that escapes its
process group with `setsid` is bounded by its rlimits but not killed with the
group. The sandbox never uses a Docker socket; future backends (a Kubernetes
Pod per task, a rootless container) plug in behind the same interface.

#### Organization proxy pools (`SENSOR_SCAN_EGRESS`)

A scan or retest command may carry `egress`: the organization's proxy pool
its tools' connections go through (`pkg/sensorkit/egress/upstream`). The
pool is the task forwarder's Dial hook, so it applies to every connection a
confined tool makes, with no tool flag and no credential in a tool's
arguments or environment:

- The forwarder checks each destination against the job's scope, pins its
  address and applies the per-target rate **before** the pool is asked: an
  out-of-scope target never reaches a proxy, and the rate toward a target
  is shared by all endpoints.
- The tunnel is opened to the checked IP address and port, never to a name
  (`socks5h` is treated as `socks5`). DNS stays with the forwarder: names
  are resolved on the sensor, not by the proxy.
- HTTP CONNECT, HTTP CONNECT over TLS to an `https` proxy (certificate
  verified against the system roots, TLS 1.2 or later, never skipped) and
  SOCKS5 with optional username/password. Many HTTP proxies allow CONNECT
  to port 443 only: a port scan or a non-HTTPS service through such a
  proxy needs it to allow CONNECT to the scanned ports; SOCKS5 has no such
  limit.
- Failover only when a proxy is down (TCP/TLS failed or timed out, or a
  reply that is not the protocol), once per endpoint; a proxy that refuses
  the credentials is not used again in the job; an answer about the
  target (CONNECT 403/502/503/504, SOCKS refusal or unreachable) ends that
  connection. No CONNECT reply in time after the proxy took the request is
  about the target once the endpoint has carried a tunnel in the job;
  before that the third such timeout is `proxy_down`, so a proxy that
  accepts connections and never answers is taken out. A pooled connection never falls back to a direct dial. A
  pool sent as the organization's default applies to public targets only:
  private, ULA, CGNAT and loopback targets are dialed directly, as before.
- Each endpoint has a breaker local to the job (3 consecutive proxy
  failures: 30 s, doubling to 10 min, with jitter, then one probe) and
  counters the sensor reports at the end of the job (`egress-report`).
  The platform computes health and the weights; the sensor uses them.
- Endpoint addresses are checked in the job and again at every dial for
  each address a host name resolves to: loopback, link-local, cloud
  metadata, multicast, unspecified, broadcast, 0.0.0.0/8 and 240.0.0.0/4
  are refused, private addresses allowed (segment proxies).
- Not through the pool: DNS (resolved on the sensor, so the sensor's
  resolver sees the names), UDP, the scanner content the sensor manages
  (content path) and a code scan's repository checkout (cloned by the
  sensor from its own network before the tools start).
- An `http` endpoint receives its Basic `Proxy-Authorization` in clear
  text over the network path to the proxy; use an `https` endpoint when
  that path is not trusted.
- Credentials are asked for the command under its lease (v2 HTTPS only,
  never through protocol v3), only when an endpoint has some, and stay in
  the sensor's memory. Records, logs, errors and reports name an endpoint
  as `scheme://host:port` or by its id only.
- A pooled job runs only where every tool task is confined to its
  forwarder: a scanner outside the tool host, a sandbox that does not
  confine the network or a shared sensor refuses it (`egress_unavailable`;
  a shared sensor: `egress_refused_by_host`). Tools with network `none`
  make no connection and run as usual.

The sensor's owner keeps a veto: `SENSOR_SCAN_EGRESS=direct-only` refuses
every pooled job (`egress_refused_by_host`) and the sensor stops reporting
`egress.upstream@1`, so the platform sends it none;
`SENSOR_SCAN_EGRESS_ALLOW=proxy.corp.example:3128,10.0.0.5` accepts only
the named endpoints (a host without a port allows any port). A sensor
reports `egress.upstream@1` only when its tasks run confined
(`net.confined@1`) and the veto is not `direct-only`.

#### Shared mode (`SENSOR_SHARED_MODE=1`, `sensorkit.Options.Shared`)

A sensor that runs jobs of many tenants (an instance's shared sensors, api
RFC-100 §8) switches on one profile. The mechanisms are the SDK's; the
sensor only sets the switch:

| Control | Enforced by | What it stops |
|---|---|---|
| The tool sandbox in `required` mode and network confinement required; `SENSOR_SANDBOX` or `SENSOR_SANDBOX_NETWORK` set to anything else is a configuration error, and a host that cannot give both refuses to start (before pairing) | `sensorkit` (`sandboxModes`, `validateSandboxNetwork`), `executor.Config.Shared`, `toolhost.Host.Shared` (a tool on any other backend is refused) | a shared sensor degrading silently to unconfined tools |
| A fresh private task directory per task, removed after it whatever the outcome; write paths and `HOME`, `TMPDIR`, `TMP`, `TEMP`, `XDG_*` given by the caller must lie beneath the task root | `executor.Config.Shared` (`Prepare` refuses the task) | a writable cache, output or configuration directory shared between jobs: one tenant's job poisoning or reading another's tool state. Read-only signed content packs stay shared |
| Targets: the policy (the built-in deny list without one), then the job's zone rule. A private address (RFC 1918, ULA) passes only when the operator allows private targets (`SENSOR_ALLOW_PRIVATE_TARGETS=1`, and `targets.allow_private` in a local policy) **and** it lies in the job's zone ranges; loopback, link-local, metadata (169.254.169.254, fd00:ec2::254, ...), CGNAT, multicast and reserved addresses never pass | `core.ScanTargetPolicy.Shared`, `toolhost.Host.Shared` (admission, and again for every address pinned for the task's forwarder), `core.CheckSharedAddr` / `CheckSharedPrefix` | a tenant reaching the operator's network or a cloud metadata service through a shared sensor |
| The capability `shared.isolation@1`, advertised from the runtime state only | `sensorkit` | the platform sending shared jobs to a sensor that does not enforce this profile |

**Zone ranges.** A shared sensor's job zone (the instance scan zone
assigned to the job's tenant) is taken only from the job's verified signed
statement, never from an unsigned field of the delivered command: a
compromised API or queue cannot widen the private ranges a shared sensor
reaches. A `zone_ranges` field on a command is ignored. The signed
statement does not carry zone ranges yet, so until it does every shared job
has no zone and reaches public addresses only. When it does, the parsed
ranges go on the job's context (`core.WithJobZone`); entries that are not
wholly private are dropped (`core.ParseZoneRanges`), so the platform can
only narrow what the operator allows.

**DNS rebinding on a shared sensor.** Every address a confined task dials
for a name was checked (policy and zone rule) when the task's scope was
built; the forwarder never resolves an admitted name again, and its DNS
answers with the pinned addresses. A tool cannot bypass the forwarder: its
network namespace has no other way out. Residual risks: a vendor host or
an `egress-proxy` tool resolves at connect time, public addresses only; a
built-in Go probe that dials in the sensor's own process is outside the
task sandbox, so a shared sensor must run its tools out of process.

**Only TCP goes through the pinned-address check.** The forwarder relays
TCP (HTTP CONNECT, absolute-form HTTP, SOCKS5 CONNECT) and answers DNS; it
checks and pins each TCP destination. UDP other than the task's DNS, ICMP
and raw sockets are not relayed at all: the task's network namespace has
only loopback, so such traffic has no route and is dropped there. The
network namespace is what stops them, not the address check, which is why
shared mode refuses to start without network confinement.

**Signed jobs and results bound to the job's organization.** A shared
sensor runs only signed jobs (`core.NewSharedJobGuard`; it refuses to start
without a pinned job-signing key or root) whose statement carries
`sensor_scope: instance` and its own `sensor_id`; an unsigned job, or one
signed for an organization's sensor, is refused before it starts. The
poller holds each command in a `core.JobLedger` while it runs it, with the
organization the verified statement names, and puts it on the job's
context (`core.WithJobTenant`). The client (`Client.SetJobLedger`) asks the
ledger before it stores or sends anything: a report must belong to a held
command with a known organization and is tagged with it in the outbox
(`outbox.Meta.TenantID`, next to `CommandID`); a command result or log
batch must belong to a held command; an unsolicited push or a result for
a command the sensor does not hold (never claimed, or already ended) is
refused locally (`core.ErrJobNotHeld`). The platform still accepts a result
only for a command the sensor holds under its lease.

**A local policy is mandatory.** A shared sensor without a loaded local
policy refuses to start (before pairing): its targets come from many
tenants, and the operator's own target, range, port and tool rules must
bound them.

### 7. Web scope of a job (`pkg/webscope`)

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
- On a sandbox that confines the network, the task's forwarder enforces the
  scope too, whatever the tool does (`egress.Scope.Web`). Every connection of
  such a task is read as HTTP: TLS is terminated with the forwarder's own
  per-task certificate authority (created in memory, valid for a day, never
  written to disk) and opened again to the target, each request is checked
  with `Allows` before it goes upstream, and a refused request gets a
  complete 403 marked `X-Openctem-Egress: refused` and is recorded. Its body
  is discarded, never sent, and the connection stays open for the next
  request, which is checked the same way: a tool must not read a refusal as
  a broken host and give up on the allowed paths. A request for another
  destination (CONNECT, an upgrade, another `Host`), a body over 1 MiB or
  `Expect: 100-continue` closes the connection.
  A redirect is a new request and is checked again. Anything that is not
  HTTP/1.x (raw TCP, an HTTP/2 preface, a protocol upgrade) is refused. A tool
  that keeps to no scope of its own, such as a template scanner whose
  templates request arbitrary paths, can declare `features.web_scope` only
  when it runs confined: the forwarder is then its only way out, and a
  forwarder that is down leaves it no route at all.
- The conformance kit's `crawl.web` and `dast.web` suites point the tool at a
  site that links to denied paths (links, a redirect, a form, a script, dot
  segments, upper case). They fail a tool that requests any of them. The
  `vuln.templates` suite of a tool that declares `features.web_scope` runs it
  again with `/.env` denied: it fails a tool that requests it (directly or
  behind a redirect) and one that no longer finds the exposed `/.git/config`.

#### Job identification on every request

A job can carry the organization's identification (`http_policy`: a
User-Agent and headers, for example the header a bug-bounty program requires
of its researchers). The tool host makes it reach every request of the task,
or the task does not start:

- `Task.Identity` holds it (after the sensor-local policy, whose User-Agent
  wins). `Context.HTTP` sets it on every request, redirects included, over
  any value the tool set itself; the tool's other headers keep their default
  rule.
- An exec-profile tool receives it on its argv: `{{http.user_agent}}` and
  `{{http.headers:-flag}}` (the flag and `Name: value` per header, a whole
  argument).
- The identification is HTTP headers, so it applies to tasks that may send
  HTTP to their targets: a tool whose network class is not `targets`
  (vendor API, resolver, egress proxy, none) or, on a target-reaching
  tool, a task whose capability reaches targets without HTTP by definition
  (`scan.ports`, `discover.hosts`, `resolve.dns`) is not affected. Such a
  task gets none of the organization's User-Agent or headers: `Task.Identity`
  is nil and its http settings (the `Context.HTTP` defaults,
  `{{http.user_agent}}`, `{{http.headers:-flag}}`) are built without them,
  so the tool never refuses for the identification and never sends it to a
  third party (a passive source, a vendor API, a registry). The
  organization's TLS rule still applies. A capability a target-reaching
  tool could serve over HTTP (`discover.subdomains` by virtual-host
  probing, a lookup) is never exempt. `tool.Manifest.SendsHTTPToTargets` is
  the rule, for a sensor that checks the same thing outside the tool host.
- A networked tool that can do neither (an exec tool whose argv lacks the
  placeholders, or a tool that does not declare `features.http_identity`) is
  refused with `refused_by_policy`. A tool that declares
  `features.http_identity` maps the identification onto its own flags or
  requests only through `Context.HTTP`.
- A sensor whose tools all run through the tool host advertises
  `http.identity@1`; the platform gives identification-carrying jobs only to
  such a sensor.

### 8. API Client Transport

- API clients (`pkg/client`, the key renewal client) refuse HTTP redirects; the API
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
| `ca_cert` | a CA certificate of the platform chain (the `SENSOR_CA_FINGERPRINT` semantics): one the platform presents, or a root it does not send that the chain verifies up to in the trust store (system roots plus `SENSOR_CA_CERT_FILE`) | `SENSOR_CA_FINGERPRINT` was set at pairing |

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

- Point `SENSOR_API_URL` (`client.Config.BaseURL`) at an `https://` URL outside a
  private network; plain `http` to a non-loopback host logs a warning.
- Never disable certificate verification. Trust a private CA with
  `SENSOR_CA_CERT_FILE`, and pin it with `SENSOR_CA_FINGERPRINT` (from the
  install snippet). When the platform does not send its root (the built-in
  gateway sends the server certificate and the intermediate), give the root
  in `SENSOR_CA_CERT_FILE`: the pin must match a certificate of the chain
  that verified. Without a pin, pairing pins the CA it verified.

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
export SENSOR_API_KEY="<sensor key>"   # or pair the sensor and set no key at all

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
- [ ] `SENSOR_API_URL` uses `https://` in production
- [ ] A private CA is trusted with `SENSOR_CA_CERT_FILE`, never by skipping verification
- [ ] The sensor reports `posture.platform_tls.pin: fingerprint` (paired by this SDK, or `SENSOR_CA_FINGERPRINT`)

### Signed jobs

- [ ] Paired sensors pin the job-signing root (`SENSOR_JOB_SIGNING_ROOT`, or `identity.json` `job_signing_root`), or the signer itself (`job_signing_keys`, `SENSOR_JOB_SIGNING_KEYS`)
- [ ] `posture.jobs.keyset_expires_at` is more than 7 days away; `<state dir>/job-signing-keyset.json` is on a persistent volume
- [ ] `posture.jobs.signed` is `required` everywhere the platform signs jobs
- [ ] `<state dir>/job-signing-seq.json` is on a persistent volume

### Proxy pools

- [ ] Sensors that must never send scan traffic through a platform-chosen proxy run with `SENSOR_SCAN_EGRESS=direct-only`, or pin the accepted endpoints with `SENSOR_SCAN_EGRESS_ALLOW`
- [ ] HTTP proxies used for port scans allow CONNECT to the scanned ports (or use SOCKS5)

### Templates
- [ ] Template validation enabled (automatic)
- [ ] Content hashes verified (if provided)
- [ ] Template directory properly sandboxed

---

## Reporting Security Issues

Report vulnerabilities privately to security@openctem.io. Do not open a public
issue. See [SECURITY.md](../SECURITY.md) for what to include and the response
targets.
