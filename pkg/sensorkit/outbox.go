package sensorkit

// Results delivery: the durable outbox (SENSOR_OUTBOX_*). The SDK does the
// work (pkg/outbox and the protocol v2 client, api RFC-026 and RFC-029);
// this file turns the settings into an outbox.Config and tells the operator
// where undelivered results are.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/outbox"
)

// DefaultOutboxDir is where a daemon keeps undelivered results. Sensor
// images declare it as a VOLUME; mount a persistent volume there.
const DefaultOutboxDir = "/var/lib/openctem/outbox"

// OutboxSettings are the outbox settings of a configuration file (the
// sensor's outbox: block). The environment overrides each of them.
type OutboxSettings struct {
	// Enabled: default on for a daemon, off for a one-shot run.
	Enabled *bool `yaml:"enabled" json:"enabled,omitempty"`
	// Dir: default DefaultOutboxDir, else ~/.openctem/outbox when that is
	// not writable.
	Dir string `yaml:"dir" json:"dir,omitempty"`
	// KeyFile is the encryption key (default <dir>/outbox.key). Point it at
	// a mounted secret to keep the key off the data volume.
	KeyFile string `yaml:"key_file" json:"key_file,omitempty"`
	// MaxBytes caps the disk use ("1GiB", "512MiB" or bytes).
	MaxBytes string `yaml:"max_bytes" json:"max_bytes,omitempty"`
	// MaxAge drops results older than this (default 168h).
	MaxAge time.Duration `yaml:"max_age" json:"max_age,omitempty"`
}

// OutboxOverrides are command-line settings that beat the environment.
type OutboxOverrides struct {
	// Dir beats SENSOR_OUTBOX_DIR and OutboxSettings.Dir.
	Dir string
	// LegacyRetryQueue turns the outbox on (the pre-outbox opt-in, also
	// RETRY_QUEUE=true); LegacyRetryDir (or RETRY_DIR) is an old
	// retry-queue directory imported once.
	LegacyRetryQueue bool
	LegacyRetryDir   string
}

// OutboxPlan is what ResolveOutbox decided.
type OutboxPlan struct {
	Enabled bool
	Config  client.OutboxConfig
	// Note explains a fall-back the operator should know about.
	Note string
}

// ResolveOutbox decides whether and where the outbox runs. daemon is the
// default of Enabled. SENSOR_OUTBOX beats everything; the directory is
// o.Dir, else SENSOR_OUTBOX_DIR, else s.Dir, else DefaultOutboxDir when it
// is writable, else ~/.openctem/outbox (with a Note).
func ResolveOutbox(s OutboxSettings, o OutboxOverrides, daemon bool) (OutboxPlan, error) {
	var p OutboxPlan
	enabled := daemon
	if s.Enabled != nil {
		enabled = *s.Enabled
	}
	if o.LegacyRetryQueue || strings.EqualFold(os.Getenv("RETRY_QUEUE"), "true") {
		enabled = true // the pre-outbox opt-in still works
	}
	if v := strings.TrimSpace(os.Getenv(EnvOutbox)); v != "" {
		on, err := parseOnOff(v)
		if err != nil {
			return p, fmt.Errorf("%s: %w", EnvOutbox, err)
		}
		enabled = on
	}
	p.Enabled = enabled

	maxBytes, err := ParseByteSize(firstNonEmpty(os.Getenv(EnvOutboxMaxBytes), s.MaxBytes))
	if err != nil {
		return p, fmt.Errorf("%s: %w", EnvOutboxMaxBytes, err)
	}
	maxAge := s.MaxAge
	if v := strings.TrimSpace(os.Getenv(EnvOutboxMaxAge)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return p, fmt.Errorf("%s: %q is not a positive duration (e.g. 72h)", EnvOutboxMaxAge, v)
		}
		maxAge = d
	}
	p.Config = client.OutboxConfig{
		KeyFile:             firstNonEmpty(os.Getenv(EnvOutboxKeyFile), s.KeyFile),
		MaxBytes:            maxBytes,
		MaxAge:              maxAge,
		LegacyRetryQueueDir: firstNonEmpty(o.LegacyRetryDir, os.Getenv("RETRY_DIR")),
	}
	if !enabled {
		return p, nil
	}

	if explicit := firstNonEmpty(o.Dir, os.Getenv(EnvOutboxDir), s.Dir); explicit != "" {
		p.Config.Dir = explicit
		return p, nil
	}
	err = usableDir(DefaultOutboxDir)
	if err == nil {
		p.Config.Dir = DefaultOutboxDir
		return p, nil
	}
	home, herr := os.UserHomeDir()
	if herr != nil {
		return p, fmt.Errorf("no outbox directory: %s is not usable (%v) and there is no home directory; set %s", DefaultOutboxDir, err, EnvOutboxDir)
	}
	p.Config.Dir = filepath.Join(home, ".openctem", "outbox")
	p.Note = fmt.Sprintf("%s is not usable (%v); undelivered results are kept in %s instead. In a container, mount a volume at %s (or set %s)",
		DefaultOutboxDir, err, p.Config.Dir, DefaultOutboxDir, EnvOutboxDir)
	return p, nil
}

// usableDir creates dir (0700) if needed and checks a file can be written.
func usableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func parseOnOff(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes", "enabled":
		return true, nil
	case "0", "off", "false", "no", "disabled":
		return false, nil
	}
	return false, fmt.Errorf("%q is not on or off", v)
}

// ParseByteSize reads "1GiB", "512MiB", "100MB", "1048576" (0 for "").
func ParseByteSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		mult   int64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40},
		{"kb", 1000}, {"mb", 1000 * 1000}, {"gb", 1000 * 1000 * 1000}, {"tb", 1000 * 1000 * 1000 * 1000},
		{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"t", 1 << 40}, {"b", 1},
	}
	lower := strings.ToLower(v)
	mult := int64(1)
	num := lower
	for _, u := range units {
		if strings.HasSuffix(lower, u.suffix) {
			mult, num = u.mult, strings.TrimSpace(strings.TrimSuffix(lower, u.suffix))
			break
		}
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a size (e.g. 1GiB, 512MiB)", v)
	}
	return int64(n * float64(mult)), nil
}

// EnableOutbox opens the outbox on the client (when p.Enabled) and logs
// where it is to w, a fall-back Note to errw. A directory another process
// holds is an error that says so.
func EnableOutbox(c *client.Client, p OutboxPlan, verbose bool, w, errw io.Writer) error {
	if !p.Enabled {
		return nil
	}
	w, errw = orStdout(w), orStderr(errw)
	if p.Note != "" {
		_, _ = fmt.Fprintf(errw, "Warning: %s\n", p.Note)
	}
	cfg := p.Config
	if err := c.EnableOutbox(cfg); err != nil {
		if errors.Is(err, outbox.ErrLocked) {
			return fmt.Errorf("%w: another sensor process uses this outbox directory; give each sensor its own volume", err)
		}
		return err
	}
	st, _ := c.OutboxStats()
	_, _ = fmt.Fprintf(w, "  Outbox: %s (%d pending, %d dead letters)\n", cfg.Dir, st.PendingCount, st.DeadLetterCount)
	if verbose && st.PendingCount > 0 {
		_, _ = fmt.Fprintf(w, "  Outbox: delivering %d result(s) left by an earlier run\n", st.PendingCount)
	}
	return nil
}

// FlushOutbox delivers what it can (for up to timeout) before a one-shot
// run exits and says on errw what is left for the next run.
func FlushOutbox(c *client.Client, timeout time.Duration, errw io.Writer) {
	st, ok := c.OutboxStats()
	if !ok {
		return
	}
	errw = orStderr(errw)
	if st.PendingCount > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = c.FlushOutbox(ctx)
		cancel()
		st, _ = c.OutboxStats()
	}
	if st.PendingCount > 0 {
		_, _ = fmt.Fprintf(errw, "Warning: %d result(s) could not be delivered yet; they stay in the outbox (%s) and the next run delivers them\n",
			st.PendingCount, c.Outbox().Dir())
	}
	if st.DeadLetterCount > 0 {
		_, _ = fmt.Fprintf(errw, "Warning: the platform refused %d result(s); see %s\n", st.DeadLetterCount, filepath.Join(c.Outbox().Dir(), "dead"))
	}
}

// OutboxCommand prints the outbox state (pending results, dead letters) to
// w, after moving the dead letters back to pending when requeueDead, without
// contacting the platform. It returns the process exit code.
func OutboxCommand(p OutboxPlan, requeueDead bool, w, errw io.Writer) int {
	w, errw = orStdout(w), orStderr(errw)
	if p.Config.Dir == "" {
		_, _ = fmt.Fprintf(errw, "Error: the outbox is off; set %s=on or %s\n", EnvOutbox, EnvOutboxDir)
		return ExitError
	}
	ob, err := outbox.Open(outbox.Config{Dir: p.Config.Dir, KeyFile: p.Config.KeyFile, MaxBytes: p.Config.MaxBytes, MaxAge: p.Config.MaxAge})
	if errors.Is(err, outbox.ErrLocked) {
		_, _ = fmt.Fprintf(errw, "Error: %v.\nA running sensor holds the outbox: stop it first, or read its outbox state on the platform (the sensor's heartbeat reports it).\n", err)
		return ExitError
	}
	if err != nil {
		_, _ = fmt.Fprintf(errw, "Error: %v\n", err)
		return ExitError
	}
	defer func() { _ = ob.Close() }()
	if requeueDead {
		n := 0
		for _, d := range ob.DeadLetters() {
			if err := ob.RequeueDead(d.Meta.ID); err != nil {
				_, _ = fmt.Fprintf(errw, "Error: %s: %v\n", d.Meta.ID, err)
				continue
			}
			n++
		}
		_, _ = fmt.Fprintf(w, "Requeued %d dead letter(s); the daemon delivers them on its next attempt.\n", n)
	}
	st := ob.Stats()
	_, _ = fmt.Fprintf(w, "Outbox %s\n", ob.Dir())
	_, _ = fmt.Fprintf(w, "  pending:      %d (%d bytes), oldest %s\n", st.PendingCount, st.PendingBytes, st.OldestAge(time.Now()).Round(time.Second))
	_, _ = fmt.Fprintf(w, "  dead letters: %d (%d bytes)\n", st.DeadLetterCount, st.DeadLetterBytes)
	_, _ = fmt.Fprintf(w, "  byte cap:     %d\n", st.CapBytes)
	for _, d := range ob.DeadLetters() {
		_, _ = fmt.Fprintf(w, "  dead %s %s report=%s command=%s at %s: HTTP %d %s\n",
			d.Meta.ID, d.Meta.Kind, d.Meta.ReportID, d.Meta.CommandID, d.DeadAt.Format(time.RFC3339), d.Status, d.Reason)
	}
	return 0
}

func orStdout(w io.Writer) io.Writer {
	if w == nil {
		return os.Stdout
	}
	return w
}

func orStderr(w io.Writer) io.Writer {
	if w == nil {
		return os.Stderr
	}
	return w
}
