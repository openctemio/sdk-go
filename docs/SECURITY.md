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

A scan command's custom templates run only with the platform's signed
manifest of them (`ScanCommandPayload.CustomTemplatesEnvelope`), or the
command fails before any template is written or any scanner runs. The
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
  install snippet).

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

### Platform Sensors (`pkg/platform`, platform control plane only)
- [ ] `AllowedJobTypes` configured (whitelist)
- [ ] `RequireAuthToken` enabled
- [ ] `ValidateTokenClaims` enabled
- [ ] Secure lease identity enabled (default)
- [ ] Lease expiry callback handles graceful shutdown

### Templates
- [ ] Template validation enabled (automatic)
- [ ] Content hashes verified (if provided)
- [ ] Template directory properly sandboxed

---

## Reporting Security Issues

Report vulnerabilities privately to security@openctem.io. Do not open a public
issue. See [SECURITY.md](../SECURITY.md) for what to include and the response
targets.
