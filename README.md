# OpenCTEM SDK

Go SDK for building integrations with the OpenCTEM security platform.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-blue?logo=go)](https://golang.org/)
[![Go Reference](https://pkg.go.dev/badge/github.com/openctemio/sdk-go.svg)](https://pkg.go.dev/github.com/openctemio/sdk-go)

## Overview

OpenCTEM SDK provides Go packages for:
- API client for interacting with OpenCTEM API
- Scanner integrations: SAST/SCA/secrets (Semgrep, CodeQL, Trivy, Gitleaks), DAST (Nuclei, including a validation executor), and recon (subfinder, dnsx, naabu, httpx, katana)
- Output formatters (SARIF, JSON)
- Common utilities and helpers

## Installation

```bash
go get github.com/openctemio/sdk-go
```

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

## Packages

| Package | Description |
|---------|-------------|
| `pkg/client` | API client for OpenCTEM API |
| `pkg/scanners` | Scanner integrations: SAST/SCA/secrets (Semgrep, CodeQL, Trivy, Gitleaks), DAST (Nuclei + validation executor), recon (subfinder, dnsx, naabu, httpx, katana) |
| `pkg/handler` | Result handlers and output formatters |
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
| `pkg/audit` | Structured audit logging for agent operations |
| `pkg/platform` | Components for running agents in platform mode |
| `pkg/ctis` | Common Threat Intelligence Schema (CTIS) types |

## Examples

See [examples/](examples/) for complete examples:
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

- [openctemio/api](https://github.com/openctemio/api) - Backend API
- [openctemio/ui](https://github.com/openctemio/ui) - Web UI
- [openctemio/agent](https://github.com/openctemio/agent) - Scanning Agent

## Enterprise Edition

For advanced features and enterprise support, see [OpenCTEM Enterprise](https://openctem.io).

## License

Apache License 2.0 - see [LICENSE](LICENSE).
