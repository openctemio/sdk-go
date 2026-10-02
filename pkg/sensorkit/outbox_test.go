package sensorkit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/outbox"
)

func TestResolveOutbox_Defaults(t *testing.T) {
	clearEnv(t)
	// One-shot: off.
	p, err := ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, false)
	if err != nil || p.Enabled {
		t.Fatalf("one-shot = %+v, %v", p, err)
	}
	// Daemon: on, in an explicit dir.
	dir := t.TempDir()
	t.Setenv(EnvOutboxDir, dir)
	p, err = ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, true)
	if err != nil || !p.Enabled || p.Config.Dir != dir {
		t.Fatalf("daemon = %+v, %v", p, err)
	}
	// An explicit directory beats the environment.
	other := t.TempDir()
	if p, _ := ResolveOutbox(OutboxSettings{Dir: "/cfg"}, OutboxOverrides{Dir: other}, true); p.Config.Dir != other {
		t.Fatalf("override dir = %q", p.Config.Dir)
	}
}

func TestResolveOutbox_FallsBackToHomeWhenDefaultIsNotWritable(t *testing.T) {
	clearEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	p, err := ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.Dir == DefaultOutboxDir {
		t.Skip("this machine can write " + DefaultOutboxDir)
	}
	if p.Config.Dir != filepath.Join(home, ".openctem", "outbox") || !strings.Contains(p.Note, DefaultOutboxDir) {
		t.Fatalf("fallback = %+v", p)
	}
}

func TestResolveOutbox_Overrides(t *testing.T) {
	clearEnv(t)
	off := false
	t.Setenv(EnvOutboxDir, t.TempDir())
	if p, _ := ResolveOutbox(OutboxSettings{Enabled: &off}, OutboxOverrides{}, true); p.Enabled {
		t.Fatal("config enabled:false ignored")
	}
	// The pre-outbox opt-in turns it on for a one-shot run.
	if p, _ := ResolveOutbox(OutboxSettings{}, OutboxOverrides{LegacyRetryQueue: true}, false); !p.Enabled {
		t.Fatal("legacy retry queue ignored")
	}
	t.Setenv(EnvOutbox, "off")
	if p, _ := ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, true); p.Enabled {
		t.Fatal("SENSOR_OUTBOX=off ignored")
	}
	t.Setenv(EnvOutbox, "maybe")
	if _, err := ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, true); err == nil {
		t.Fatal("SENSOR_OUTBOX=maybe accepted")
	}
	t.Setenv(EnvOutbox, "on")
	t.Setenv(EnvOutboxMaxBytes, "512MiB")
	t.Setenv(EnvOutboxMaxAge, "72h")
	t.Setenv("RETRY_DIR", "/old/queue")
	p, err := ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, false)
	if err != nil || p.Config.MaxBytes != 512<<20 || p.Config.MaxAge != 72*time.Hour || p.Config.LegacyRetryQueueDir != "/old/queue" {
		t.Fatalf("overrides = %+v, %v", p.Config, err)
	}
	t.Setenv(EnvOutboxMaxAge, "-1h")
	if _, err := ResolveOutbox(OutboxSettings{}, OutboxOverrides{}, true); err == nil {
		t.Fatal("negative max age accepted")
	}
}

func TestParseByteSize(t *testing.T) {
	cases := map[string]int64{"": 0, "1GiB": 1 << 30, "512MiB": 512 << 20, "100MB": 100_000_000, "2g": 2 << 30, "1048576": 1 << 20, "1.5GiB": 3 << 29}
	for in, want := range cases {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"lots", "-1GiB", "0"} {
		if _, err := ParseByteSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOutboxCommand(t *testing.T) {
	clearEnv(t)
	var out, errw bytes.Buffer
	if code := OutboxCommand(OutboxPlan{}, false, &out, &errw); code != ExitError || !strings.Contains(errw.String(), "the outbox is off") {
		t.Fatalf("off: %d %q", code, errw.String())
	}
	// A fresh directory: reported empty, and no key is written.
	dir := t.TempDir()
	out.Reset()
	if code := OutboxCommand(OutboxPlan{Enabled: true, Config: clientOutbox(dir)}, true, &out, &errw); code != 0 {
		t.Fatalf("fresh: %d %s", code, errw.String())
	}
	if !strings.Contains(out.String(), "empty") {
		t.Errorf("fresh output %q", out.String())
	}
	if _, err := os.Stat(outbox.DefaultKeyFile(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the status command wrote a key: %v", err)
	}

	// An outbox with its key: the full status.
	ob, err := outbox.Open(outbox.Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.Enqueue(outbox.Meta{Kind: outbox.KindReport}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = ob.Close()
	out.Reset()
	if code := OutboxCommand(OutboxPlan{Enabled: true, Config: clientOutbox(dir)}, true, &out, &errw); code != 0 {
		t.Fatalf("status: %d %s", code, errw.String())
	}
	for _, want := range []string{"Requeued 0 dead letter(s)", "Outbox " + dir, "pending:      1", "dead letters: 0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q lacks %q", out.String(), want)
		}
	}
}

// The key is gone while a sealed item waits (a secret that failed to
// mount): the status command says so and never writes a new key.
func TestOutboxCommandMissingKey(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	keyFile := filepath.Join(t.TempDir(), "outbox.key")
	ob, err := outbox.Open(outbox.Config{Dir: dir, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ob.Enqueue(outbox.Meta{Kind: outbox.KindReport}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = ob.Close()
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	cfg := clientOutbox(dir)
	cfg.KeyFile = keyFile
	if code := OutboxCommand(OutboxPlan{Enabled: true, Config: cfg}, false, &out, &errw); code != ExitError {
		t.Fatalf("code = %d, out %q", code, out.String())
	}
	for _, want := range []string{keyFile, "1 sealed item", "Restore the key file"} {
		if !strings.Contains(errw.String(), want) {
			t.Errorf("error %q lacks %q", errw.String(), want)
		}
	}
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the status command wrote a key: %v", err)
	}
	if outbox.SealedItems(dir) != 1 {
		t.Fatal("the sealed item was touched")
	}
}
