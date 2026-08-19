# gRPC Configuration Guide

This guide explains how to use gRPC transport with the OpenCTEM SDK.

## Overview

The SDK supports both HTTP/REST and gRPC transports. gRPC offers:

- **Higher performance**: Binary protocol over HTTP/2
- **Bidirectional streaming**: Real-time command delivery
- **Strong typing**: Auto-generated from Protocol Buffers
- **Lower latency**: Persistent connections with keepalive

## Quick Start

### Basic gRPC Connection

```go
import (
    "github.com/openctemio/sdk-go/pkg/transport/grpc"
)

// Create gRPC transport
transport := grpc.NewTransport(&grpc.Config{
    Address:  "grpc.openctem.io:9090",
    APIKey:   os.Getenv("API_KEY"),
    WorkerID: os.Getenv("WORKER_ID"),
    UseTLS:   true,
})

// Connect
if err := transport.Connect(ctx); err != nil {
    log.Fatal(err)
}
defer transport.Close()
```

## Configuration Options

```go
type Config struct {
    // Server address (host:port)
    Address string

    // Authentication
    APIKey   string   // Bearer token
    WorkerID string   // Worker ID for tracking

    // TLS
    UseTLS             bool    // Enable TLS (default: true)
    InsecureSkipVerify bool    // Skip cert verification (dev only)
    CertFile           string  // Custom CA certificate

    // Connection
    Timeout           time.Duration  // Connection timeout (default: 30s)
    KeepAliveTime     time.Duration  // Keepalive ping interval (default: 30s)
    KeepAliveTimeout  time.Duration  // Keepalive timeout (default: 10s)
    MaxRecvMsgSize    int            // Max receive message size (default: 50MB)
    MaxSendMsgSize    int            // Max send message size (default: 50MB)

    // Debug
    Verbose bool
}
```

## Services

### AgentService

For worker registration, heartbeat, and command polling.

```protobuf
service AgentService {
    // Register a new worker
    rpc Register(RegisterRequest) returns (RegisterResponse);

    // Bidirectional heartbeat stream for real-time commands
    rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);

    // Poll commands (non-streaming alternative)
    rpc PollCommands(PollCommandsRequest) returns (PollCommandsResponse);
}
```

### IngestService

For pushing findings, assets, and exposures.

```protobuf
service IngestService {
    // Push findings (unary)
    rpc PushFindings(PushFindingsRequest) returns (PushFindingsResponse);

    // Stream findings (for large batches)
    rpc StreamFindings(stream Finding) returns (PushFindingsResponse);

    // Push assets
    rpc PushAssets(PushAssetsRequest) returns (PushAssetsResponse);

    // Push exposure events
    rpc PushExposures(PushExposuresRequest) returns (PushExposuresResponse);
}
```

### ThreatIntelService

For threat intelligence queries.

```protobuf
service ThreatIntelService {
    rpc GetEPSSScores(GetEPSSScoresRequest) returns (GetEPSSScoresResponse);
    rpc GetKEVEntries(GetKEVEntriesRequest) returns (GetKEVEntriesResponse);
}
```

## Streaming Examples

### Bidirectional Heartbeat

```go
// Start heartbeat stream
stream, err := agentClient.Heartbeat(ctx)
if err != nil {
    log.Fatal(err)
}

// Send heartbeats in background
go func() {
    for {
        stream.Send(&v1.HeartbeatRequest{
            WorkerId: workerID,
            Status: &v1.WorkerStatus{
                State: v1.WorkerStatus_STATE_IDLE,
            },
        })
        time.Sleep(30 * time.Second)
    }
}()

// Receive commands
for {
    resp, err := stream.Recv()
    if err != nil {
        break
    }
    for _, cmd := range resp.Commands {
        handleCommand(cmd)
    }
}
```

### Stream Findings

```go
// For large batches, use streaming
stream, err := ingestClient.StreamFindings(ctx)
if err != nil {
    log.Fatal(err)
}

// Send findings one by one
for _, finding := range findings {
    if err := stream.Send(finding); err != nil {
        log.Printf("Failed to send: %v", err)
        continue
    }
}

// Close and get response
resp, err := stream.CloseAndRecv()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created: %d, Updated: %d\n", resp.FindingsCreated, resp.FindingsUpdated)
```

## Generating Go Code from Proto

```bash
# Install buf
brew install bufbuild/buf/buf

# Install protoc plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code
cd proto
buf generate
```

## Error Handling

```go
import "google.golang.org/grpc/status"

resp, err := client.PushFindings(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.Unauthenticated:
            log.Fatal("Invalid API key")
        case codes.ResourceExhausted:
            log.Println("Rate limited, retrying...")
            time.Sleep(time.Minute)
        case codes.Unavailable:
            log.Println("Server unavailable, retry later")
        default:
            log.Printf("gRPC error: %v", st.Message())
        }
    }
}
```

## TLS Configuration

### Production (Default)
```go
transport := grpc.NewTransport(&grpc.Config{
    Address: "grpc.openctem.io:9090",
    UseTLS:  true,
})
```

### Development (Self-signed)
```go
transport := grpc.NewTransport(&grpc.Config{
    Address:            "localhost:9090",
    UseTLS:             true,
    InsecureSkipVerify: true,
})
```

### Custom CA Certificate
```go
transport := grpc.NewTransport(&grpc.Config{
    Address:  "grpc.openctem.io:9090",
    UseTLS:   true,
    CertFile: "/path/to/ca.crt",
})
```

## See Also

- [Architecture Guide](./ARCHITECTURE.md)
- [Proto Definitions](../proto/openctemio/v1/)
- [gRPC Go Documentation](https://grpc.io/docs/languages/go/)
