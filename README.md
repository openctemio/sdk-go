# OpenCTEM SDK

Go SDK for building integrations with the OpenCTEM security platform.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://golang.org/)
[![Go Reference](https://pkg.go.dev/badge/github.com/openctemio/sdk-go.svg)](https://pkg.go.dev/github.com/openctemio/sdk-go)

## Overview

OpenCTEM SDK provides Go packages for:
- API client for interacting with OpenCTEM API
- Scanner integrations: SAST/SCA/secrets (Semgrep, CodeQL, Trivy, Betterleaks), DAST (Nuclei, including a validation executor), and recon (subfinder, dnsx, naabu, httpx, katana)
- Output formatters (SARIF, JSON)
- Common utilities and helpers

## Installation

```bash
go get github.com/openctemio/sdk-go
```

## Upgrading from v0.6 (agent → sensor)

v0.7.0 renames the *agent* vocabulary to *sensor* (`core.BaseAgent` →
`core.BaseSensor`, `client.WithAgentID` → `client.WithSensorID`, …). Upgrade
your module with the codemod, which rewrites only SDK identifiers, type-safely,
then moves you to the new SDK:

```bash
go run github.com/openctemio/sdk-go/cmd/sensor-migrate@v0.7.0 -dry-run   # review
go run github.com/openctemio/sdk-go/cmd/sensor-migrate@v0.7.0            # apply
```

The wire to the platform (protocol v1) is unchanged, and the SDK migrates a
sensor's saved credentials and old `AGENT_*` settings by itself. See
[CHANGELOG.md](CHANGELOG.md) for the full list.

## Quick Start

### API Client

```go
package main

import (
    "context"
    "github.com/openctemio/sdk-go/pkg/client"
)

func main() {
    // Create client
    c := client.New(
        client.WithBaseURL("http://localhost:8080"),
        client.WithAPIKey("your-api-key"),
    )

    // List assets
    assets, err := c.Assets().List(context.Background())
    if err != nil {
        panic(err)
    }

    // Create finding
    finding := &client.Finding{
        Title:    "SQL Injection",
        Severity: "HIGH",
        // ...
    }
    err = c.Findings().Create(context.Background(), finding)
}
```

### Scanner Integration

```go
package main

import (
    "github.com/openctemio/sdk-go/pkg/scanners/semgrep"
    "github.com/openctemio/sdk-go/pkg/handler"
)

func main() {
    // Create scanner
    scanner := semgrep.New(
        semgrep.WithConfig("p/security-audit"),
    )

    // Run scan
    results, err := scanner.Scan(context.Background(), "./src")
    if err != nil {
        panic(err)
    }

    // Handle results
    h := handler.New(
        handler.WithAPIClient(client),
        handler.WithOutputFile("results.sarif"),
    )
    h.Handle(results)
}
```

## Build a sensor in 30 lines

`pkg/sensorkit` is the whole sensor runtime in one call. A sensor implements
its tools; the kit reads the settings, connects (protocol v2 negotiated on
hello, v1 for what an older platform lacks), reports the tools on every
heartbeat, waits while the key is rejected, follows the heartbeat doorbell,
claims commands into resource-sized slots, delivers results through the
durable outbox, renews the API key and drains on SIGTERM.

```go
package main

import (
	"context"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

var version = "dev"

func main() {
	tool := core.NewBaseScanner(&core.BaseScannerConfig{ // your tool's binary
		Name: "mytool", Binary: "mytool", Capabilities: []string{"sast"},
		DefaultArgs: []string{"scan", "--sarif", "{target}"}, Timeout: 30 * time.Minute,
	})
	kit, err := sensorkit.New(sensorkit.Options{Name: "my-sensor", Version: version})
	sensorkit.Exit(err)    // a clear message and exit code for a bad setting
	kit.AddScanner(tool)   // reported (installed? version?), dispatched, scheduled
	sensorkit.Exit(kit.Run(context.Background())) // blocks; SIGINT/SIGTERM drain
}
```

Run it with `API_URL` and `API_KEY` (a sensor key from Settings > Sensors).
[examples/minimal-sensor](examples/minimal-sensor) is a complete one with an
in-process tool.

**Keep the state directory.** A key renewal retires the key the sensor was
started with; the renewed key is saved in `sensor-credentials.json` in the
state directory (0600) and used on the next start instead of `API_KEY`. In a
container, mount a volume at `/var/lib/openctem/state` (`-v
my-sensor-state:/var/lib/openctem/state`): without one the kit does not
renew, because a recreated container would come back with the retired key.
When an administrator regenerates the key and `API_KEY` is set to the new
one, the new key wins. Every heartbeat also carries the process's
`instance_id`, so the platform flags one key running in two places.

| Setting | Environment (an `Options` field wins) | Default |
|---|---|---|
| Platform | `API_URL`, `API_KEY`, `SENSOR_ID` | required to run commands (exit 2 with what is missing) |
| Name | `SENSOR_NAME` | `sensor-<hostname>` |
| Protocol | `SENSOR_PROTOCOL` = `auto`, `v1`, `v2` | `auto` |
| Concurrency cap | `SENSOR_MAX_JOBS` (1-100) | none: slots follow CPU, memory and tool cost |
| Tool allowlist | `SENSOR_TOOLS` (comma-separated) | none |
| Drain grace | `SENSOR_DRAIN_GRACE` (1s-1h) | 30s |
| Scanner priority | `SENSOR_SCANNER_PRIORITY` = `low`, `normal` | `low`: scanners at nice +10, lowest best-effort I/O, `oom_score_adj` 500 (Linux) |
| Sensor OOM protection | `SENSOR_PROTECT_FROM_OOM=true\|false`: the sensor sets its own `oom_score_adj` to -500 (Linux; needs `CAP_SYS_RESOURCE`, e.g. `docker run --cap-add SYS_RESOURCE`; without it, one warning and the sensor runs unprotected). Scanners never inherit it | off |
| Outbox | `SENSOR_OUTBOX`, `SENSOR_OUTBOX_DIR`, `_MAX_BYTES`, `_MAX_AGE`, `_KEY_FILE` | on, `/var/lib/openctem/outbox` |
| State (the renewed API key, tool cost history) | `SENSOR_STATE_DIR` | `/var/lib/openctem/state` when writable, else `~/.openctem`: **mount a persistent volume there** |
| Private CA | `SENSOR_CA_CERT_FILE` (PEM, added to the system roots; trusted for the platform and content downloads, so a TLS-inspecting proxy works) | system roots |
| Proxy to the platform | `SENSOR_CONTROL_PROXY` (URL or `direct`), else `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | none |
| Proxy for content and feeds | `SENSOR_CONTENT_PROXY` (URL or `direct`), else the platform setting | the platform setting |
| Proxy variables for scanners | `SENSOR_SCAN_PROXY`: `inherit` (scanners get the sensor's `HTTP(S)_PROXY`; warned at start) or `direct` | `inherit` |
| Key renewal | `PLATFORM_KEY_AUTORENEW=true\|false`, `Options.KeyAutoRenew` / `NoKeyAutoRenew`, `Options.CredentialsFile` | on when the state directory persists (outside a container; inside one, a mounted, non-tmpfs volume), else off |
| Pre-rename names | `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS`, `-agent-id` | applied with a warning; both names set differently: exit 2 |

Plug your own parts in: `kit.AddCollector`, `kit.AddParser` (your tool's
output format), `kit.HandleCommand("type", executor)`,
`kit.UseCommandMiddleware(mw, "type")` (wrap every command),
`Options.Content` (managed scanner content on the heartbeat),
`Options.ScanTargetPolicy`, `Options.AssetResolver`, `kit.Tools()` (more
tools or capabilities). The resolvers (`ResolveMaxJobs`, `ResolveOutbox`,
`ResolveProtocol`, `CheckCredentials`, `MigrateSettings`) are exported for a
sensor with its own flags or configuration file. `pkg/core` stays available
for anything the kit does not cover; the sections below describe it.

## Writing a sensor: you implement executors; the SDK owns queue, slots, leases and reporting

The platform's queue is authoritative (api RFC-030). A sensor only says what
it can run; `core.CommandPoller` does the rest:

| The SDK does | How |
|---|---|
| **Slots** | `resource.Manager` sizes them from what the sensor may use: CPU cores and memory read from cgroup v2/v1 (quota, cpuset, memory limit) or the host, divided by the learned per-job cost of the sensor's tools (defaults per tool, refined from finished jobs, saved to a small JSON file). An AIMD window halves them after an OOM kill, a timeout or CPU throttling and grows back one slot per window of successes. A configured cap (`ManagerConfig.Cap`) is an upper bound, never a fixed number. |
| **Claiming** | Takes a free slot first, polls with `limit` = free slots, claims nothing while all are busy: no prefetch, so the platform keeps work for sensors that can run it now. |
| **Local queue** | Orders a batch by class (`verify > interactive > scheduled > background`) then priority (`critical > high > normal > low`); at most `limits.per_host_concurrency` (default 1) held commands touch one host (`core.HostKey`); a command over it is left pending, not claimed. |
| **Leases** | Every heartbeat lists the held command ids (`running`) for the platform to renew. |
| **Cancel** | A heartbeat's `cancel_command_ids` cancels those commands' contexts; they are released, not reported. |
| **Drain** | `Stop` or a canceled context stops claiming, gives running commands `DrainGrace` (30 s) and then cancels them; unstarted and aborted commands are **released** (`POST …/commands/{id}/release`; failed with "released: …" on a platform without it) so the platform re-queues them at once. A refused `start` is never executed. |
| **Reporting** | The heartbeat carries `active_jobs`, `max_concurrent_jobs` (the cap), `resources`, `capacity` (slots and per-tool cost) and `queue`. |

```go
poller := core.NewCommandPoller(apiClient, executor, &core.CommandPollerConfig{PollInterval: 30 * time.Second})
poller.SetResourceManager(resource.NewManager(resource.ManagerConfig{
	Cap:       0, // no operator cap: slots follow the resources (up to 64)
	Tools:     []string{"nuclei", "trivy"},
	StateFile: "/var/lib/openctem/tool-costs.json",
	Prober:    &resource.Prober{WorkDir: "/var/lib/openctem"},
}))
poller.SetDoorbell(doorbell)
sensor.SetLoadReporter(poller) // heartbeat: load, resources, capacity, queue, running
go poller.Start(ctx)
```

An executor that starts processes itself calls `core.RecordProcessState(ctx,
cmd.ProcessState)` after `Wait` so its CPU time and peak memory teach the
cost history (the SDK's exec helpers already do).

### Tools: register them, the SDK reports them

The platform does not need to know a sensor's tools: the sensor registers
what it runs when it starts, and every heartbeat reports it (api RFC-029
§4.3.1). The platform dispatches by that report, and its administrator can
only narrow it.

```go
s := core.NewBaseSensor(cfg, apiClient)
s.AddScanner(myScanner)                 // registered: probed with IsInstalled
executor.SetToolRegistry(s.Tools())     // the executor's scanners and collectors too
s.Tools().Register(core.ToolSpec{       // any other tool, with an optional probe
	Name: "zap", Version: "2.15.0", Capabilities: []string{"dast"},
	Probe: func(ctx context.Context) (bool, string, error) { return zapVersion(ctx) },
	Cost:  &resource.ToolCostHint{Cores: 2, MemBytes: 2 << 30, SecondsPerTarget: 60},
})
s.Tools().AddCapabilities("validate")   // served whatever the tools
s.Tools().Limit(strings.Split(os.Getenv("MY_TOOLS"), ",")...) // optional operator allowlist
```

- A tool whose probe fails is reported as not installed and gets no jobs.
  Installed tools report their version.
- Probes are cached for 10 minutes (`SetProbeTTL`, `Refresh`).
- Feed the slot sizer the same list:
  `resource.ManagerConfig{Tools: s.Tools().Names(), CostHints: s.Tools().CostHints()}`.
- `SetCapabilityReporter` replaces the registry with your own reporter.

## Packages

What the SDK promises, what is stable, what is moving to the sensor, and how
it grows without breaking sensors: [docs/STABILITY.md](docs/STABILITY.md).

| Package | Description |
|---------|-------------|
| `pkg/client` | API client for OpenCTEM API |
| `pkg/scanners` | Scanner integrations: SAST/SCA/secrets (Semgrep, CodeQL, Trivy, Betterleaks), DAST (Nuclei + validation executor), recon (subfinder, dnsx, naabu, httpx, katana) |
| `pkg/handler` | Result handlers and output formatters |
| `pkg/sensorkit` | The sensor runtime in one call: settings, connection, heartbeat, commands, outbox, key renewal, drain |
| `pkg/core` | Core types and interfaces |
| `pkg/errors` | Error types and handling |
| `pkg/retry` | Retry utilities |
| `pkg/metrics` | Prometheus metrics |
| `pkg/health` | Health check utilities |
| `pkg/transport` | HTTP/gRPC transport |
| `pkg/httpsec` | Hardened HTTP client (SafeHTTPClient) with SSRF protection |
| `pkg/credentials` | Credential management |
| `pkg/connectors` | SCM connectors (GitHub, GitLab) |
| `pkg/enrichers` | Data enrichment (CVE, NVD) |
| `pkg/audit` | Structured audit logging for sensor operations |
| `pkg/platform` | Components for running sensors in platform mode |
| `pkg/sensorproto/legacyv1` | Protocol v1 wire vocabulary (frozen) and migration of pre-sensor settings |
| `pkg/ctis` | Common Threat Intelligence Schema (CTIS) types |

## Examples

See [examples/](examples/) for complete examples:
- A complete sensor on `pkg/sensorkit` ([minimal-sensor](examples/minimal-sensor))
- Basic API client usage
- Scanner integration
- CI/CD pipeline integration
- Custom scanner development

## Building

```bash
# Run tests
go test ./...

# Generate proto files
make proto

# Lint
make lint
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Related Projects

- [openctemio/openctem](https://github.com/openctemio/openctem) - the platform: API (`api/`) and web console (`web/`), formerly openctemio/api and openctemio/ui
- [openctemio/sensor](https://github.com/openctemio/sensor) - the OpenCTEM sensor (binary `openctemio-sensor`, image `ghcr.io/openctemio/sensor`)

## Enterprise Edition

For advanced features and enterprise support, see [OpenCTEM Enterprise](https://openctem.io).

## License

Apache License 2.0 - see [LICENSE](LICENSE).
