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

### 2. gRPC Transport Security

The gRPC transport includes multiple security features.

#### TLS Configuration

```go
import "github.com/openctemio/sdk-go/pkg/transport/grpc"

transport := grpc.NewTransport(&grpc.Config{
    Address: "grpc.openctem.io:9090",
    UseTLS:  true,  // Always use TLS in production

    // InsecureSkipVerify should be false in production
    // When true, a warning is logged
    InsecureSkipVerify: false,
})
```

**Security features:**
- Minimum TLS 1.2 enforced
- Proper ServerName validation for certificate verification
- Security warnings logged when using insecure configurations

#### Address Validation

Validate server addresses to prevent SSRF attacks:

```go
import "github.com/openctemio/sdk-go/pkg/transport/grpc"

err := grpc.ValidateAddress("grpc.example.com:9090")  // OK
err := grpc.ValidateAddress("file:///etc/passwd")     // Error: invalid scheme
err := grpc.ValidateAddress("unix:///var/run/sock")   // Error: invalid scheme
err := grpc.ValidateAddress("0.0.0.0:9090")          // Error: binding address
```

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
    TemplateType: "nuclei",              // Must be: nuclei, semgrep, gitleaks
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
- Duplicate filename detection

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

### 6. Scanner Process Environment

Scanner child processes no longer inherit the sensor's whole environment
(which holds the API key). They get an allowlist: `PATH`, `HOME`, temp and
locale vars, proxy and CA-bundle vars, Docker host vars, `XDG_*`, and the
`TRIVY_*` / `NUCLEI_*` / `SEMGREP_*` / `GITLEAKS_*` / `CODEQL_*` and ProjectDiscovery (`SUBFINDER_*`, `HTTPX_*`, `DNSX_*`, `NAABU_*`, `KATANA_*`, `PDCP_*`) namespaces, plus any
variables set explicitly in the scanner config or scan options.

| Variable / API | Effect |
|----------------|--------|
| `OPENCTEM_SDK_SCANNER_ENV_ALLOW=AWS_*,GITHUB_TOKEN` | Pass extra names (`*` suffix = prefix) |
| `core.SetScannerEnvAllowlist([]string{...})` | Same, programmatically |
| `OPENCTEM_SDK_SCANNER_INHERIT_ENV=1` / `core.SetScannerInheritEnv(true)` | Restore full inheritance (not recommended) |

### 7. API Client Transport

- API clients (`pkg/client`, `pkg/platform`) refuse HTTP redirects; the API
  never issues them and following one would forward the bearer key.
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

```go
// DO: Always use TLS in production
transport := grpc.NewTransport(&grpc.Config{
    UseTLS: true,
})

// DO: Validate addresses from external input
if err := grpc.ValidateAddress(userProvidedAddress); err != nil {
    return err
}

// DON'T: Skip TLS verification
transport := grpc.NewTransport(&grpc.Config{
    InsecureSkipVerify: true,  // SECURITY WARNING logged
})
```

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
export OPENCTEMIO_API_KEY="your-api-key"
export OPENCTEMIO_ENCRYPTION_KEY="base64-encoded-key"

# DON'T: Commit secrets to version control
# api_key: "sk_live_xxxxx"  # Never do this!
```

---

## Security Audit Checklist

### Credentials
- [ ] Using `EncryptedFileStore` for sensitive data
- [ ] Encryption key stored securely (not in config files)
- [ ] `SecureClear()` called after credential use
- [ ] Key validation enabled (automatic)

### Transport
- [ ] TLS enabled for production
- [ ] `InsecureSkipVerify` is `false`
- [ ] Server addresses validated before use

### Platform Sensors
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

Please report security vulnerabilities to: security@openctem.io

Do not disclose security issues publicly until a fix is available.
