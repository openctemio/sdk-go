package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

// The gRPC metadata keys are protocol v1 and must not change with the
// agent -> sensor rename (RFC-023 §9.5).
func TestAuthMetadataProtocolV1(t *testing.T) {
	tr := &Transport{config: &Config{APIKey: "k", SensorID: "s-1"}}
	md, ok := metadata.FromOutgoingContext(tr.addAuthMetadata(context.Background()))
	if !ok {
		t.Fatal("no outgoing metadata")
	}
	if got := md.Get("x-agent-id"); len(got) != 1 || got[0] != "s-1" {
		t.Fatalf("x-agent-id = %v, want [s-1]", got)
	}
	if got := md.Get("authorization"); len(got) != 1 || got[0] != "Bearer k" {
		t.Fatalf("authorization = %v", got)
	}
}
