package sensorkit

// Feed relay (api RFC-142): a platform-owned shared sensor with internet
// access downloads signed feed files the platform asks for and streams them
// back, so the platform needs no outbound access. The host operator opts in
// with SENSOR_FEED_RELAY=1; only a shared sensor may relay; the sensor
// fetches only from the official feed origins and the extra origins the
// operator lists in SENSOR_FEED_RELAY_ORIGINS. The platform verifies every
// file against the feed's own pinned root, so the relay adds no trust.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/feedrelay"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Environment of the feed relay.
const (
	// EnvFeedRelay turns the relay on ("1"); off by default.
	EnvFeedRelay = "SENSOR_FEED_RELAY"
	// EnvFeedRelayOrigins lists extra feed origins (comma-separated https
	// URLs, a mirror for example) on top of the official ones. The platform's
	// job signer must allow them too (SIGNER_FEED_ORIGINS).
	EnvFeedRelayOrigins = "SENSOR_FEED_RELAY_ORIGINS"
)

// feedRelayDownloadTimeout bounds one file download.
const feedRelayDownloadTimeout = 10 * time.Minute

// ServeFeedRelay makes the kit relay feeds when the host operator set
// SENSOR_FEED_RELAY=1, and report feedrelay.Capability. It reports whether
// the relay is on. Only a shared sensor connected to a platform relays;
// SENSOR_FEED_RELAY=1 on any other sensor is a usage error (fail loudly, not
// silently idle). Call before Run.
func (k *Kit) ServeFeedRelay() (bool, error) {
	switch v := strings.TrimSpace(os.Getenv(EnvFeedRelay)); v {
	case "", "0":
		return false, nil
	case "1":
	default:
		return false, usageError(fmt.Errorf("%s=%q is not recognized: set it to 1 to relay signed feeds to the platform, or 0 (or unset)", EnvFeedRelay, v))
	}
	if !k.s.shared {
		return false, usageError(fmt.Errorf("%s=1: only a shared (platform) sensor relays feeds; enroll this sensor as a shared sensor or unset it", EnvFeedRelay))
	}
	if k.client == nil {
		return false, usageError(fmt.Errorf("%s=1 needs a connection to the platform", EnvFeedRelay))
	}
	origins, err := feedrelay.ParseOrigins(os.Getenv(EnvFeedRelayOrigins))
	if err != nil {
		return false, usageError(fmt.Errorf("%s: %w", EnvFeedRelayOrigins, err))
	}
	k.feedRelayOrigins = origins
	k.Tools().AddCapabilities(feedrelay.Capability)
	return true, nil
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
