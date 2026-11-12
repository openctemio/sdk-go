package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

// A command's typed output reaches the platform byte for byte: sent
// directly, and from the outbox after the platform was unreachable and the
// sensor restarted.
func TestCommandOutput_ByteForByteDirectAndAfterOutboxReplay(t *testing.T) {
	// Key order and number formats encoding/json would change.
	out := json.RawMessage(`{"z":1.50,"a":[1e3,-0.0],"m":{"y":"café","x":null}}`)
	stored := func(t *testing.T, f *FakePlatform, cmd string) json.RawMessage {
		t.Helper()
		var res struct {
			Output json.RawMessage `json:"output"`
		}
		if err := json.Unmarshal(f.CommandResult(cmd), &res); err != nil {
			t.Fatalf("stored result %s: %v", f.CommandResult(cmd), err)
		}
		return res.Output
	}

	t.Run("direct", func(t *testing.T) {
		f := NewFakePlatform(true)
		defer f.Close()
		cmd := "0192a3b4-0000-7000-8000-0000000000b1"
		f.OpenCommand(cmd)
		c := newClient(t, f, client.ProtocolV2)
		if err := c.ReportCommandResult(context.Background(), cmd, &core.CommandResult{Status: "completed", Output: out}); err != nil {
			t.Fatal(err)
		}
		if got := stored(t, f, cmd); !bytes.Equal(got, out) {
			t.Fatalf("stored output %s, want %s", got, out)
		}
	})

	t.Run("outbox replay", func(t *testing.T) {
		f := NewFakePlatform(true)
		defer f.Close()
		cmd := "0192a3b4-0000-7000-8000-0000000000b2"
		f.OpenCommand(cmd)
		var down atomic.Bool
		down.Store(true)
		f.SetFault(func(*http.Request, int) *FaultAnswer {
			if down.Load() {
				return &FaultAnswer{Status: http.StatusServiceUnavailable}
			}
			return nil
		})
		dir := t.TempDir()
		c := newClient(t, f, client.ProtocolV2)
		if err := c.EnableOutbox(client.OutboxConfig{Dir: dir, SyncWait: -1, LegacyRetryQueueDir: "-",
			Logf: func(format string, args ...any) { t.Logf("[outbox] "+format, args...) }}); err != nil {
			t.Fatal(err)
		}
		ctx := core.WithCommandID(context.Background(), cmd)
		if err := c.ReportCommandResult(ctx, cmd, &core.CommandResult{Status: "completed", Output: out}); err != nil {
			t.Fatal(err)
		}
		if s, _ := f.CommandState(cmd); s != "running" {
			t.Fatalf("command %s while the platform is down", s)
		}
		_ = c.Close()

		// The sensor restarts and the platform is back: the stored result
		// is replayed from disk.
		down.Store(false)
		c2 := newClient(t, f, client.ProtocolV2)
		enableOutbox(t, c2, dir)
		c2.Outbox().Wake()
		waitUntil(t, 10*time.Second, func() bool { s, _ := f.CommandState(cmd); return s == "completed" })
		if got := stored(t, f, cmd); !bytes.Equal(got, out) {
			t.Fatalf("replayed output %s, want %s", got, out)
		}
	})
}
