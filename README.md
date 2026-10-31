# OpenCTEM SDK

Go SDK for building sensors, tools and integrations for the OpenCTEM
platform. Product documentation: https://docs.openctem.io.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://golang.org/)
[![Go Reference](https://pkg.go.dev/badge/github.com/openctemio/sdk-go.svg)](https://pkg.go.dev/github.com/openctemio/sdk-go)

## Overview

OpenCTEM SDK provides Go packages for:
- `pkg/sensorkit`: the sensor runtime in one call (identity, connection, heartbeat, commands, durable outbox, per-task tool sandbox, local policy, preflight checks and the config report)
- `pkg/client`: the platform protocol client
- `pkg/ctis`: the CTIS result types
- `pkg/httpsec`: SSRF-safe HTTP clients
- `pkg/conformance`: a fake platform and the sensor conformance suite
- `cmd/openctem`: `openctem tool init|validate|run|test|diff|describe` and `openctem version`, to scaffold a tool from a capability and check it with the conformance kit; signed prebuilt binaries ship with each release, no Go toolchain needed ([docs/tools/cli.md](docs/tools/cli.md#install))

The scanner wrappers (Semgrep, CodeQL, Trivy, Betterleaks, Nuclei and the recon
tools) live in the sensor (`github.com/openctemio/sensor`), not in the SDK.
What each package promises is in [docs/STABILITY.md](docs/STABILITY.md); where
the SDK is going is in [docs/rfcs/sensor-sdk-v2.md](docs/rfcs/sensor-sdk-v2.md).

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

The SDK migrates a sensor's saved credentials by itself. The old setting
names (`AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS`, `API_URL`,
`API_KEY`, `REGION`, `PLATFORM_KEY_AUTORENEW`,
`OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS`) are no longer read: a sensor refuses to
start (exit 2) while one is set and names its replacement. Current SDK
releases speak sensor protocol v3 (gRPC over mutual TLS, or HTTPS) and fall
back to v2 on a platform without v3; protocol v1 is retired, so they need an
OpenCTEM platform from 2026-10 on. See
[CHANGELOG.md](CHANGELOG.md) for the full list.

## Quick Start

### Push a report

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func main() {
	c := client.New(&client.Config{
		BaseURL: "https://openctem.example.com", // the API base URL, not the web UI
		APIKey:  os.Getenv("SENSOR_API_KEY"),           // a sensor key from Settings > Sensors
	})
	defer c.Close()

	report := ctis.NewReport()
	report.Tool = &ctis.Tool{Name: "my-scanner", Version: "1.0.0"}
	report.Findings = append(report.Findings, ctis.Finding{
		ID:       "finding-001",
		Type:     ctis.FindingTypeVulnerability,
		Title:    "SQL Injection",
		Severity: ctis.SeverityHigh,
		Location: &ctis.FindingLocation{Path: "src/db.go", StartLine: 42},
	})

	res, err := c.PushFindings(context.Background(), report)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", res)
}
```

## Build a sensor in 30 lines

`pkg/sensorkit` is the whole sensor runtime in one call. A sensor implements
its tools; the kit reads the settings, connects (sensor protocol v2, features
negotiated on hello), reports the tools on every
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

Run it with `SENSOR_API_URL`. Without `SENSOR_API_KEY` the sensor pairs on first start
(an administrator approves it under Sensors > Pair a sensor); with `SENSOR_API_KEY`
(a sensor key from Settings > Sensors) it uses that key.
[examples/minimal-sensor](examples/minimal-sensor) is a complete one with an
in-process tool.

**Keep the state directory.** A key renewal retires the key the sensor was
started with; the renewed key is saved in `sensor-credentials.json` in the
state directory (0600) and used on the next start instead of `SENSOR_API_KEY`. In a
container, mount one data volume at `/var/lib/openctem` (`-v
my-sensor-data:/var/lib/openctem`; it holds `state/`, `outbox/`, `store/`,
`workspaces/` and `content/`, which the kit creates 0700 when missing): without one the kit
does not renew, because a recreated container would come back with the
retired key. A volume on `/var/lib/openctem/state` itself works too: a
directory counts as persistent when its nearest mount is a real volume.
When an administrator regenerates the key and `SENSOR_API_KEY` is set to the new
one, the new key wins. Every heartbeat also carries the process's
`instance_id`, so the platform flags one key running in two places.

| Setting | Environment (an `Options` field wins) | Default |
|---|---|---|
| Platform | `SENSOR_API_URL`, `SENSOR_API_KEY`, `SENSOR_ID` | required to run commands (exit 2 with what is missing) |
| Pairing code | `SENSOR_PAIRING_CODE` (`XXXX-XXXX`, from "expect a sensor"): a sensor with no identity attaches to it on first start; ignored once paired; never logged | none: the sensor prints a code to enter in the console |
| Instance enrollment token | `SENSOR_INSTANCE_ENROLLMENT_TOKEN` (`octe_...`, a single-use token a super administrator issued): a sensor with no identity enrolls with it as a shared sensor of the instance; not combinable with `SENSOR_PAIRING_CODE`; never logged | none |
| Name | `SENSOR_NAME` | `sensor-<hostname>` |
| Protocol | `SENSOR_PROTOCOL` = `auto`, `v2` (same; `v1` is retired and refused) | `auto` |
| Transport (protocol v3) | `SENSOR_TRANSPORT` = `auto` (gRPC over mutual TLS, then HTTPS, then protocol v2), `grpc`, `https`, `v2` | `auto` |
| Tool confinement | `SENSOR_SANDBOX` = `auto`, `required`, `off`; `SENSOR_SANDBOX_NETWORK` = `auto` (each task in its own network namespace where the host allows user namespaces), `required` (refuse to start without it), `off` | `auto` |
| Shared mode | `SENSOR_SHARED_MODE=1` for a sensor that runs jobs of many tenants: sandbox and network confinement required, no writable state shared between jobs, private targets only inside the job's zone ([docs/SECURITY.md](docs/SECURITY.md)) | `0` |
| Key binding | `SENSOR_KEY_BIND` = `auto` (an API key is replaced by a signing key the sensor makes), `off` | `auto` |
| Local policy | `SENSOR_LOCAL_POLICY` (file), `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` (shorthand), `SENSOR_REQUIRE_LOCAL_POLICY`, `SENSOR_KILL_SWITCH_FILE` | `/etc/openctem/sensor-policy.yaml` |
| Concurrency cap | `SENSOR_MAX_JOBS` (1-100) | none: slots follow CPU, memory and tool cost |
| Tool allowlist (deprecated) | `SENSOR_TOOLS` (comma-separated): only narrows the installed tools; built-ins (`sensorkit.Builtin()`) are kept. Use the local policy's `tools.allow` instead | none |
| Drain grace | `SENSOR_DRAIN_GRACE` (1s-1h) | 30s |
| Scanner priority | `SENSOR_SCANNER_PRIORITY` = `low`, `normal` | `low`: scanners at nice +10, lowest best-effort I/O, `oom_score_adj` 500 (Linux) |
| Tool envelope | `SENSOR_TOOL_CGROUPS` = `auto`, `off` | `auto`: a cgroup per tool task (CPU, memory, processes from the tool's `resources`) where the sensor's cgroup is delegated; rlimits elsewhere. Launches wait while the host is overloaded ([resource governance](docs/resource-governance.md)) |
| Sensor OOM protection | `SENSOR_PROTECT_FROM_OOM=true\|false`: the sensor sets its own `oom_score_adj` to -500 (Linux; needs `CAP_SYS_RESOURCE`, e.g. `docker run --cap-add SYS_RESOURCE`; without it, one warning and the sensor runs unprotected). Scanners never inherit it | off |
| Outbox | `SENSOR_OUTBOX`, `SENSOR_OUTBOX_DIR`, `_MAX_BYTES`, `_MAX_AGE`, `_KEY_FILE` | on, `/var/lib/openctem/outbox` |
| Local store (sealed outbox items, job journal, janitor) | `SENSOR_STORE_DIR`, `SENSOR_STORE_KEY_FILE` (a mounted secret kept off the data volume; 0600), `SENSOR_WORKSPACE_DIR` | `store/` and `workspaces/` next to the outbox directory; `master.key` (0600) created in the store directory |
| State (the renewed API key, tool cost history) | `SENSOR_STATE_DIR` | `/var/lib/openctem/state` when writable, else `~/.openctem`: **mount a persistent volume at `/var/lib/openctem`** |
| Private CA | `SENSOR_CA_CERT_FILE` (PEM, added to the system roots; trusted for the platform and content downloads, so a TLS-inspecting proxy works) | system roots |
| Template-signing keys | `SENSOR_TEMPLATE_SIGNING_KEYS` (base64 Ed25519 public keys, comma-separated, the tenant's keys from the platform's `GET /api/v1/scanner-templates/signing-key`): custom templates in a scan run only with a signature one of them verifies | none: commands carrying custom templates fail |
| Proxy to the platform | `SENSOR_CONTROL_PROXY` (URL or `direct`), else `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | none |
| Proxy for content and feeds | `SENSOR_CONTENT_PROXY` (URL or `direct`), else the platform setting | the platform setting |
| Proxy variables for scanners | `SENSOR_SCAN_PROXY`: `inherit` (scanners get the sensor's `HTTP(S)_PROXY`; warned at start) or `direct` | `inherit` |
| Organization proxy pools for scan traffic | `SENSOR_SCAN_EGRESS`: `platform` (a job's pool carries its confined tools' connections; never direct) or `direct-only` (every pooled job refused, `egress_refused_by_host`); `SENSOR_SCAN_EGRESS_ALLOW`: comma list of accepted `host:port` or `host` endpoints. See [docs/SECURITY.md](docs/SECURITY.md#organization-proxy-pools-sensor_scan_egress) | `platform`, any valid endpoint |
| Key renewal | `SENSOR_KEY_AUTORENEW=true\|false`, `Options.KeyAutoRenew` / `NoKeyAutoRenew`, `Options.CredentialsFile` | on when the state directory persists (outside a container; inside one, a mounted, non-tmpfs volume), else off |
| Pre-rename names | `AGENT_ID`, `AGENT_NAME`, `AGENT_ALLOW_PRIVATE_TARGETS` and the other removed names | refused: the sensor exits 2 and names the replacement; only the `-agent-id` flag is still applied, with a warning |

**Pairing is restartable and does not storm the platform.** While a sensor waits for approval it keeps the request in `identity/pairing.json` (0600, nothing secret): after a restart it asks the platform about that request first, confirms it when an administrator already approved it, and otherwise shows the fingerprint again; only an expired, refused or unknown request is replaced by a new one. A pairing code is single use: when the request that carried it expires or is refused, the sensor never sends that code again. The daemon prints why and continues with a request without a code (it shows a code to enter under Sensors > Add sensor > Pair a sensor that shows a code); `pair` exits with the same explanation. A re-pair (`pair -repair`) stages its new key in `identity/signing.key.next` and replaces `signing.key` and `identity.json` only after the platform confirmed, so an interrupted or refused re-pair leaves the working identity alone; running it again reuses the staged key. Retries use full jitter (a delay between half of the backoff and all of it, 5 seconds doubling to 5 minutes) for network errors, HTTP 408, 425, 429, 500, 502, 503, 504, a clock skew and a key another request still holds (`Retry-After` is honoured, 1 to 300 seconds). Any other refusal is printed once with the platform's title and detail, and the daemon waits at least 5 minutes before asking again instead of exiting into a restart loop; `pair` exits. A key the platform reports as already registered, with no identity ever confirmed on this host, was never active: it is replaced once. With an identity present, the sensor stops and says to restore the identity or ask an administrator to Re-pair it.

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
| **Local queue** | Orders a batch by class (`verify > interactive > scheduled > background`) then priority (`critical > high > normal > low`); at most `limits.per_host_concurrency` (default 1) held commands touch one host, under the politeness keys the platform sent with the command (`host_keys`) or, from an older platform, the same keys computed by `github.com/openctemio/ctis/politeness`; a command over it is left pending, not claimed. |
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

## Write a tool

A tool is a manifest plus a run function (`pkg/tool`); the sensor runs it out
of process, admits its targets against the local policy and checks every
record it emits. A simple tool is declared with the builder:

```go
var Dotenv = tool.Define("dotenv", "1.0.0").
	Targets("http_service").
	Produces("finding:misconfiguration").
	Params(tool.StringParam("path").Label("Path").Default("/.env").Pattern("^/")).
	Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
		for _, t := range job.Targets() {
			// probe t.URL(job.Param("path").String()) with ctx.HTTP()
			_ = emit.Misconfiguration(t, tool.Issue{RuleID: "dotenv-exposed", Title: ".env is readable", Severity: "high"})
			ctx.TargetDone(t)
		}
		return nil
	}).
	MustBuild()
```

Add it to a sensor with `kit.AddTool(Dotenv)` (and `adapter.Dispatch(Dotenv)`
at the top of `main`) and test it with `testkit.Run`. The design:
[docs/rfcs/sensor-sdk-v2.md](docs/rfcs/sensor-sdk-v2.md).

A tool outside the sensor binary is a directory with its `tool.yaml`
descriptor and program, scaffolded and checked with the `openctem tool` CLI
([docs/tools/cli.md](docs/tools/cli.md)) and installed in a directory listed
in `SENSOR_ADAPTER_DIRS`. A tool directory must hold only what the tool needs:
the sensor refuses it when any file or directory in it (to 4 levels, 1024
entries) is a symbolic link, writable by group or others, or owned by someone
other than root or the sensor user. Either way:

- The descriptor's `config` is the tool's settings schema, in the closed
  subset of JSON Schema defined by
  [`github.com/openctemio/ctis/settings`](https://github.com/openctemio/ctis#tool-settings)
  (`Params` of the builder write it). The platform validates administrators'
  values with the same package, sends them inside the signed job
  (`settings_layers`), and the sensor resolves them against the schema before
  every task.
- The sensor manifest reports each tool's contract with its full descriptor
  (`core.ToolContract`, `tool.Manifest.Contract`). A tool reported with a
  valid contract joins the organization's tool catalog on the platform, with
  no platform change.
- The platform assigns tier and trust: a tool it does not know as built into
  the released sensor runs as unverified, T2.

The full guide: [Writing a tool](https://docs.openctem.io/developers/tool-authoring/).

## Packages

What the SDK promises, what is stable, what is moving to the sensor, and how
it grows without breaking sensors: [docs/STABILITY.md](docs/STABILITY.md).

| Package | Description |
|---------|-------------|
| `pkg/client` | API client for OpenCTEM API |
| `pkg/sensorkit` | The sensor runtime in one call: settings, connection, heartbeat, commands, outbox, key renewal, drain |
| `pkg/core` | Core types and interfaces |
| `pkg/tool` | The tool contract: manifest, run function, emitter, `Define` builder |
| `pkg/testkit` | Run a tool in-process with the runtime's rules |
| `pkg/conformance` | Fake platform and the sensor and tool conformance suites |
| `pkg/retry` | Retry utilities |
| `pkg/httpsec` | Hardened HTTP client (SafeHTTPClient) with SSRF protection |
| `pkg/sensorproto/legacyv1` | Migration of pre-sensor settings and credentials (frozen) |
| `pkg/ctis` | CTIS (CTEM Ingest Schema) types, re-exported from `github.com/openctemio/ctis` |

## Examples

See [examples/](examples/) for complete examples:
- A tool in Go in one file, and the 15-minute walk-through for writing one ([hello-tool](examples/hello-tool), [docs/tool-quickstart.md](docs/tool-quickstart.md))
- A tool in Python with no SDK, and how to check it with the conformance kit ([python-adapter](examples/python-adapter), [docs/adapter-protocol.md](docs/adapter-protocol.md))
- A complete sensor on `pkg/sensorkit` ([minimal-sensor](examples/minimal-sensor))
- A custom scanner and adapter ([custom-scanner](examples/custom-scanner), [custom-adapter](examples/custom-adapter))
- An integration test against a platform ([integration-test](examples/integration-test))
- CI scanning that reports to OpenCTEM lives in [openctemio/ci](https://github.com/openctemio/ci) (GitHub Action, GitLab templates, `openctem-ci`)

## Building

```bash
# Run tests
make test        # or: go test ./...

# Lint
make lint
```

## Documentation

- Product documentation: https://docs.openctem.io
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the SDK's parts fit together
- [docs/SECURITY.md](docs/SECURITY.md): the SDK's security controls
- [docs/SETTINGS.md](docs/SETTINGS.md): every sensor setting the SDK reads
- [docs/STABILITY.md](docs/STABILITY.md): stability tiers and versioning
- [docs/tools/cli.md](docs/tools/cli.md): the `openctem tool` CLI

## Contributing

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Related Projects

- [openctemio/openctem](https://github.com/openctemio/openctem) - the platform: API (`api/`) and web console (`web/`), formerly openctemio/api and openctemio/ui
- [openctemio/sensor](https://github.com/openctemio/sensor) - the OpenCTEM sensor (binary `openctemio-sensor`, image `ghcr.io/openctemio/sensor`)

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 The OpenCTEM Authors ([AUTHORS](AUTHORS)).

Third-party and commercial sensors, tools and adapters may import and link the SDK under the Apache License 2.0. Releases before the change to the Apache License 2.0 stay available under the GNU General Public License v3.0 they were published with; every later release is Apache License 2.0 only.
