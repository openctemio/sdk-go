# OpenCTEM Architecture Guide

This document explains the core architecture of the OpenCTEM platform and how the SDK components interact with the backend.

## Overview

OpenCTEM is a security platform that collects, analyzes, and manages security findings from various sources. The architecture follows an **Sensor-Component** model.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            OPENCTEM PLATFORM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         BACKEND API                                  │   │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐            │   │
│  │   │   Sensors   │    │  Findings   │    │   Assets    │            │   │
│  │   │  Registry   │    │   Storage   │    │  Inventory  │            │   │
│  │   └─────────────┘    └─────────────┘    └─────────────┘            │   │
│  │         ▲                   ▲                  ▲                    │   │
│  │         │                   │                  │                    │   │
│  │         └───────────────────┴──────────────────┘                    │   │
│  │                            │                                         │   │
│  │                     HTTP/REST or gRPC                               │   │
│  └─────────────────────────────┬───────────────────────────────────────┘   │
│                                │                                            │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
     ┌──────────────▼──────────────┐  ┌──────▼───────────────────┐
     │       SENSOR (Local)        │  │      CI/CD Pipeline      │
     │                             │  │                          │
     │  ┌────────────────────────┐ │  │  ┌────────────────────┐  │
     │  │    SDK CLIENT          │ │  │  │    SDK CLIENT      │  │
     │  │  (sensor_id: xxx)     │ │  │  │  (sensor_id: yyy) │  │
     │  └────────────────────────┘ │  │  └────────────────────┘  │
     │            │                │  │           │              │
     │  ┌─────────┴─────────┐     │  │  ┌────────┴────────┐     │
     │  │                   │     │  │  │                 │     │
     │  ▼                   ▼     │  │  ▼                 ▼     │
     │ Scanners         Providers │  │ Scanners      Adapters   │
     │ (Semgrep,        (GitHub,  │  │ (Trivy,       (SARIF)    │
     │  Trivy)          AWS)      │  │  Betterleaks)            │
     └────────────────────────────┘  └───────────────────────────┘
```

## Key Concepts

### 1. Sensor

An **Sensor** is the identity registered on the server. Every component that pushes data to OpenCTEM does so through a Sensor.

```go
// Sensor is identified by its sensor id
client := client.New(&client.Config{
    BaseURL:  "https://api.openctem.io",
    APIKey:   "your-api-key",
    SensorID: "sensor-123",  // ← This is the Sensor identity
})
```

**Sensor responsibilities:**
- Registered in the backend database
- Receives commands from the server
- Sends heartbeats to report status
- All pushed data is tagged with the sensor id for audit trail (sent as the protocol v1 `X-Agent-ID` header)

**Sensor types:**

| Type | Description | Execution Mode |
|------|-------------|----------------|
| `runner` | CI/CD one-shot scans | One-shot |
| `worker` | Server-controlled daemon | Daemon |
| `collector` | Data collection sensor | Daemon |
| `sensor` | EASM sensor | Daemon |

### 2. Sensor Process

An **Sensor Process** orchestrates Scanners, Collectors, and Providers. It uses the SDK Client to communicate with the server.

```go
// Sensor process uses SDK Client
sensor := core.NewBaseSensor(&core.BaseSensorConfig{
    Name:    "my-sensor",
    Version: "1.0.0",
}, client)

sensor.AddScanner(scanners.Semgrep())
sensor.AddScanner(scanners.Trivy())
sensor.AddProvider(providers.GitHub())

sensor.Start(ctx)
```

**Sensor execution modes:**
- **One-shot**: Single scan and exit (CI/CD) - for `runner` type
- **Daemon**: Long-running, polls for commands - for `worker`, `collector`, `sensor` types
- **Server-controlled**: Receives commands via heartbeat stream

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
through `GET /api/v1/agent/commands`. There is no free-text or shell action.

### Results delivery: protocol v2 and the durable outbox

**Protocol.** `client.Config.Protocol` is `auto` (default), `v1` or `v2`. In
`auto` the heartbeat announces `X-OpenCTEM-Sensor-Features: results-v2`; a
platform with protocol v2 results (api RFC-026) answers
`X-OpenCTEM-Protocol: 2`, and the client reads `GET /api/v2/sensor/hello` for
the limits. Results then go as
`PUT /api/v2/sensor[/commands/{command_id}]/results/{report_id}` with
`Content-Type: application/vnd.openctem.ctis.v1+json`, a `Content-Digest`
(sha-256 of the bytes as sent) and zstd. Reports over the per-request limits
are sent as segments (each a complete CTIS document with the report's tool,
metadata and the assets its findings reference; `chunk.SplitSegments`) and a
commit. A platform without v2 gets the v1 routes, byte for byte as before.
`v1` never touches v2; `v2` fails against a platform without it.

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
  same bytes: the server answers 200 and stores nothing); on v1 the server's
  finding-fingerprint dedup makes them best effort.
- One file per item (`pending/<id>.item` + `.state`), each written to a
  temporary file, fsynced, renamed and the directory fsynced; mode 0600 in a
  0700 directory; an exclusive `flock` so two processes never share it;
  sealed with AES-256-GCM under `outbox.key` (0600, created on first use;
  `KeyFile` can point at a mounted secret instead). A torn or corrupted file
  fails authentication and is moved to `corrupt/`; it never crashes the
  process.
- Never fills the disk: a byte cap (default 1 GiB, and at most half of the
  space the outbox could use) and an age cap (default 7 days) evict the
  oldest entries first, dead letters before pending results, with a log
  line, the `openctem_sensor_outbox_evicted_total` metric
  (`outbox.NewCollector`) and `evicted_count` on the heartbeat.
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

### 3. Components

Components are the building blocks that perform actual work:

| Component | Purpose | Example |
|-----------|---------|---------|
| **Scanner** | Run security tools | `SemgrepScanner`, `TrivyScanner` |
| **Parser** | Convert tool output to CTIS | `SARIFParser`, `JSONParser` |
| **Connector** | Manage external connections | `GitHubConnector`, `AWSConnector` |
| **Collector** | Pull data from sources | `RepoCollector`, `AlertCollector` |
| **Provider** | Bundle Connector + Collectors | `GitHubProvider`, `AWSProvider` |
| **Adapter** | Format translation | `SARIFAdapter`, `CycloneDXAdapter` |
| **Enricher** | Add threat intel | `EPSSEnricher`, `KEVEnricher` |

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
                                          │  Enricher    │
                                          │  (EPSS/KEV)  │
                                          └──────┬───────┘
                                                  │
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

## Transport Options

The SDK supports two transport layers:

### HTTP/REST (Default)
```go
client := client.New(&client.Config{
    BaseURL: "https://api.openctem.io",
    APIKey:  "xxx",
})
```

### gRPC (High Performance)
```go
grpcTransport := grpc.NewTransport(&grpc.Config{
    Address: "grpc.openctem.io:9090",
    APIKey:  "xxx",
    UseTLS:  true,
})

// Use gRPC for streaming findings
// Bidirectional heartbeat stream for real-time commands
```

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

### Custom Connector
```go
type MyConnector struct {
    *connectors.BaseConnector
}

func NewMyConnector(apiKey string) *MyConnector {
    return &MyConnector{
        BaseConnector: connectors.NewBaseConnector(&connectors.BaseConnectorConfig{
            Name:    "my-service",
            Type:    "api",
            BaseURL: "https://api.myservice.com",
            Config: &core.ConnectorConfig{
                APIKey:    apiKey,
                RateLimit: 1000, // requests per hour
            },
        }),
    }
}
```

### Custom Provider
```go
type MyProvider struct {
    connector  *MyConnector
    collectors map[string]core.Collector
}

func (p *MyProvider) ListCollectors() []core.Collector {
    return []core.Collector{
        NewDataCollector(p.connector),
        NewAlertCollector(p.connector),
    }
}
```

## Best Practices

1. **Always use Sensor ID**: Ensure every SDK client has a unique sensor id for traceability.

2. **Rate limiting**: Use `BaseConnector` for external APIs to avoid rate limit errors.

3. **Use CTIS format**: Always convert outputs to CTIS for consistency.

4. **Enrich with threat intel**: Use `client.EnrichFindings()` to add EPSS/KEV data.

5. **Never lose results**: enable the durable outbox (see "Results delivery"):
   ```go
   c := client.New(cfg)
   if err := c.EnableOutbox(client.OutboxConfig{Dir: "/var/lib/openctem/outbox"}); err != nil {
       log.Fatal(err)
   }
   defer c.Close()
   ```

6. **Use gRPC for streaming**: For large batches, use gRPC streaming instead of REST.

7. **Security best practices**: Follow the SDK security guide for production deployments:
   - Use `EncryptedFileStore` for credentials
   - Enable TLS for gRPC transport
   - Configure job validation for platform sensors
   - Use secure lease identities (default)

## Security Features

The SDK includes comprehensive security controls:

### Credential Security
- **Encrypted storage**: AES-256-GCM encryption at rest
- **Key validation**: Path traversal and injection prevention
- **Secure comparison**: Constant-time credential verification

### Transport Security
- **TLS enforcement**: Minimum TLS 1.2, proper ServerName validation
- **Address validation**: SSRF prevention for server addresses

### Platform Sensor Security
- **Job validation**: Type whitelist, payload limits, auth token verification
- **Lease security**: Cryptographic identity prevents hijacking
- **Lease expiry**: Automatic job cancellation on expiry
- **Template security**: Path traversal prevention, size limits

See [Security Guide](./SECURITY.md) for detailed information.

## See Also

- [SDK README](../README.md) - Quick start guide
- [Security Guide](./SECURITY.md) - Security best practices
- [API Documentation](../../api/docs/API.md) - Backend API reference
- [CTIS Schema](../pkg/ctis/types.go) - Full CTIS type definitions
