package conformance

// api RFC-035 D6: the client echoes the lease epoch of its claim in
// X-OpenCTEM-Lease-Epoch on complete and fail (protocol v2 only), and a
// complete or fail under an epoch the command no longer has is refused.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func claimAndStart(t *testing.T, c *client.Client, id string) {
	t.Helper()
	ctx := context.Background()
	if err := c.AcknowledgeCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.StartCommand(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func leaseHeaders(f *FakePlatform, id, action string) []string {
	var out []string
	for _, r := range f.RequestsTo(http.MethodPost, protov2.CommandActionPath(id, action)) {
		out = append(out, r.Header.Get(protov2.HeaderLeaseEpoch))
	}
	return out
}

func TestLease_PollCarriesEpoch(t *testing.T) {
	f := newControlFake(t)
	id := "0192a3b4-0000-7000-8000-000000000101"
	f.QueueCommand(id)
	f.ReclaimCommand(id) // claimed once before, released back to pending
	c := newClient(t, f, client.ProtocolAuto)
	resp, err := c.GetCommands(context.Background())
	if err != nil || len(resp.Commands) != 1 || resp.Commands[0].LeaseEpoch != 1 {
		t.Fatalf("poll %+v %v", resp, err)
	}
}

func TestLease_CompleteEchoesClaimEpoch(t *testing.T) {
	f := newControlFake(t)
	id := "0192a3b4-0000-7000-8000-000000000102"
	f.QueueCommand(id)
	f.ReclaimCommand(id)
	f.ReclaimCommand(id) // two earlier claims: this one is epoch 3
	c := newClient(t, f, client.ProtocolAuto)
	claimAndStart(t, c, id)
	if err := c.CompleteCommand(context.Background(), id, json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if got := leaseHeaders(f, id, protov2.CompleteAction); len(got) != 1 || got[0] != "3" {
		t.Fatalf("complete lease headers %q", got)
	}
	for _, a := range []string{protov2.ClaimAction, protov2.StartAction} {
		if got := leaseHeaders(f, id, a); len(got) != 1 || got[0] != "" {
			t.Fatalf("%s lease headers %q", a, got)
		}
	}
	if st, _ := f.CommandState(id); st != "completed" {
		t.Fatalf("state %q", st)
	}
}

func TestLease_FailEchoesClaimEpoch(t *testing.T) {
	f := newControlFake(t)
	id := "0192a3b4-0000-7000-8000-000000000103"
	f.QueueCommand(id)
	c := newClient(t, f, client.ProtocolAuto)
	claimAndStart(t, c, id)
	err := c.ReportCommandResult(context.Background(), id, &core.CommandResult{Status: "failed", Error: "boom"})
	if err != nil {
		t.Fatal(err)
	}
	if got := leaseHeaders(f, id, protov2.FailAction); len(got) != 1 || got[0] != "1" {
		t.Fatalf("fail lease headers %q", got)
	}
}

// A command claimed again since (the lease ran out) refuses the old
// holder's complete and fail; the error says so and is a gone command.
func TestLease_LostLeaseIsRefused(t *testing.T) {
	for _, action := range []string{protov2.CompleteAction, protov2.FailAction} {
		t.Run(action, func(t *testing.T) {
			f := newControlFake(t)
			id := "0192a3b4-0000-7000-8000-000000000104"
			f.QueueCommand(id)
			c := newClient(t, f, client.ProtocolAuto)
			claimAndStart(t, c, id)
			f.ReclaimCommand(id)
			ctx := context.Background()
			var err error
			if action == protov2.CompleteAction {
				err = c.CompleteCommand(ctx, id, nil)
			} else {
				err = c.FailCommand(ctx, id, "boom")
			}
			var ve *client.V2Error
			if !client.IsCommandGone(err) || !errors.As(err, &ve) || ve.ProblemName() != protov2.ProblemInvalidTransition {
				t.Fatalf("%s under a lost lease: %v", action, err)
			}
			if !strings.Contains(err.Error(), "lease lost") {
				t.Fatalf("error does not name the lease loss: %v", err)
			}
			if st, _ := f.CommandState(id); st != "running" {
				t.Fatalf("state %q", st)
			}
		})
	}
}

// A command the client holds no epoch for is completed without the
// header (a claim answer without an epoch: pkg/client lease_test.go).
func TestLease_NoEpochNoHeader(t *testing.T) {
	f := newControlFake(t)
	id := "0192a3b4-0000-7000-8000-000000000105"
	f.OpenCommand(id) // running, never claimed through the client
	c := newClient(t, f, client.ProtocolAuto)
	if err := c.CompleteCommand(context.Background(), id, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.Requests() {
		if v := r.Header.Values(protov2.HeaderLeaseEpoch); len(v) > 0 {
			t.Fatalf("%s %s sent %s %q", r.Method, r.Path, protov2.HeaderLeaseEpoch, v)
		}
	}
}
