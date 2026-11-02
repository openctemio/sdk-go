package sensorkit

// Feed relay (api RFC-142): a platform-owned shared sensor with internet
// access downloads signed feed files the platform asks for and streams them
// back, so the platform needs no outbound access. A shared sensor with a
// pinned job-signing key relays by default; the host operator turns it off
// with SENSOR_FEED_RELAY=0. The platform offers rounds only to the sensors
// its super administrator designated. The sensor fetches only from the
// official feed origins and the extra origins the operator lists in
// SENSOR_FEED_RELAY_ORIGINS. The platform verifies every file against the
// feed's own pinned root, so the relay adds no trust.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/feedrelay"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Environment of the feed relay.
const (
	// EnvFeedRelay: unset or "auto" relays on a shared sensor with a pinned
	// job-signing key (and stays off on any other sensor); "0" turns it
	// off; "1" requires it (a usage error on a sensor that cannot relay).
	EnvFeedRelay = "SENSOR_FEED_RELAY"
	// EnvFeedRelayOrigins lists extra feed origins (comma-separated https
	// URLs, a mirror for example) on top of the official ones. The platform's
	// job signer must allow them too (SIGNER_FEED_ORIGINS).
	EnvFeedRelayOrigins = "SENSOR_FEED_RELAY_ORIGINS"
)

// feedRelayDownloadTimeout bounds one file download.
const feedRelayDownloadTimeout = 10 * time.Minute

// ServeFeedRelay makes the kit relay feeds and report feedrelay.Capability
// when it can: a shared sensor connected to a platform whose job-signing
// key or root is pinned. It reports whether the relay is on. With
// SENSOR_FEED_RELAY unset (or auto) a sensor that cannot relay simply does
// not; SENSOR_FEED_RELAY=1 on such a sensor is a usage error (fail loudly,
// not silently idle); SENSOR_FEED_RELAY=0 turns it off. Call before Run.
func (k *Kit) ServeFeedRelay() (bool, error) {
	required := false
	switch v := strings.TrimSpace(os.Getenv(EnvFeedRelay)); v {
	case "0":
		return false, nil
	case "", "auto":
	case "1":
		required = true
	default:
		return false, usageError(fmt.Errorf("%s=%q is not recognized: leave it unset (a shared sensor relays signed feeds to the platform), 0 to turn it off, or 1 to require it", EnvFeedRelay, v))
	}
	if why := k.feedRelayBlocker(); why != "" {
		if required {
			return false, usageError(fmt.Errorf("%s=1: %s", EnvFeedRelay, why))
		}
		return false, nil
	}
	origins, err := feedrelay.ParseOrigins(os.Getenv(EnvFeedRelayOrigins))
	if err != nil {
		return false, usageError(fmt.Errorf("%s: %w", EnvFeedRelayOrigins, err))
	}
	k.feedRelayOrigins = origins
	k.Tools().AddCapabilities(feedrelay.Capability)
	return true, nil
}

// feedRelayBlocker says why this sensor cannot relay ("" when it can).
func (k *Kit) feedRelayBlocker() string {
	switch {
	case !k.s.shared:
		return "only a shared (platform) sensor relays feeds; an organization's sensor never does"
	case k.client == nil:
		return "the feed relay needs a connection to the platform"
	case k.s.jobs == nil || k.s.jobs.Posture() == core.JobsSignedOff:
		return "the feed relay needs a pinned job-signing key or root (SENSOR_JOB_SIGNING_ROOT or SENSOR_JOB_SIGNING_KEYS)"
	}
	return ""
}

// startFeedRelay runs the relay until ctx ends (no-op when it is off).
func (k *Kit) startFeedRelay(ctx context.Context) {
	if len(k.feedRelayOrigins) == 0 {
		return
	}
	dir := filepath.Join(firstNonEmpty(k.s.stateDir, os.TempDir()), "feed-relay")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		_, _ = fmt.Fprintf(k.errw, "Feed relay off: %v\n", err)
		return
	}
	r, err := feedrelay.New(feedrelay.Config{
		Platform: k.client, Verifier: k.s.jobs, Origins: k.feedRelayOrigins,
		HTTP: httpsec.SafeHTTPClient(feedRelayDownloadTimeout), Dir: dir,
		Logf: func(format string, args ...any) { _, _ = fmt.Fprintf(k.errw, format+"\n", args...) },
	})
	if err != nil {
		_, _ = fmt.Fprintf(k.errw, "Feed relay off: %v\n", err)
		return
	}
	_, _ = fmt.Fprintf(k.out, "  Feed relay: on, origins %s\n", strings.Join(k.feedRelayOrigins, ", "))
	go r.Run(ctx)
}
