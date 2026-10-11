package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
)

// A gRPC network failure is remembered in CertDir: a restart within the
// backoff goes straight to the HTTPS binding with the same reason, without
// dialing gRPC again.
func TestTransportV3_RemembersAGRPCFailureAcrossARestart(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.StopV3GRPC()
	dir := t.TempDir()
	var logs []string
	start := func() *client.Client {
		c := client.New(&client.Config{BaseURL: f.URL(), Signer: signer, MaxRetries: 3, RetryDelay: 10 * time.Millisecond})
		t.Cleanup(func() { _ = c.Close() })
		logs = nil
		c.EnableTransportV3(client.TransportOptions{Mode: client.TransportAuto, CertDir: dir, ReprobeInterval: time.Hour,
			Logf: func(format string, args ...any) { logs = append(logs, format); t.Logf(format, args...) }})
		if err := c.StartTransport(context.Background()); err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := start()
	if st := first.TransportStatus(); st.Binding != client.BindingHTTPS || st.FallbackReason != client.ReasonGRPCUnreachable {
		t.Fatalf("first start: %+v", st)
	}
	if skipped(logs) {
		t.Fatal("the first start must try gRPC")
	}
	second := start()
	st := second.TransportStatus()
	if st.Binding != client.BindingHTTPS || st.FallbackReason != client.ReasonGRPCUnreachable {
		t.Fatalf("restart within the backoff: %+v", st)
	}
	if !skipped(logs) {
		t.Fatal("the restart tried gRPC again within the backoff")
	}
	lifecycle(t, f, second)
}

func skipped(logs []string) bool {
	for _, l := range logs {
		if strings.Contains(l, "skipped until its backoff") {
			return true
		}
	}
	return false
}

// An identity refusal sends nothing but hello and the heartbeat (which tells
// a paused sensor it is paused): no downgrade to v2 for jobs or results.
func TestTransportV3_IdentityRefusalStopsEverythingButTheHeartbeat(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.RefuseV3Identity(true)
	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); !errors.Is(err, client.ErrIdentityRefused) {
		t.Fatalf("err %v", err)
	}
	before := len(f.Requests())
	if _, err := c.GetCommands(context.Background()); err == nil {
		t.Fatal("a poll went out after an identity refusal")
	}
	for _, r := range f.Requests()[before:] {
		if r.Path == "/api/v2/sensor/commands" {
			t.Fatal("the poll reached the platform over v2")
		}
	}
	if _, err := c.SendHeartbeatWithHints(context.Background(), status()); err != nil {
		t.Fatalf("the heartbeat must still go out: %v", err)
	}
}
