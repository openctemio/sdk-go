### Added: feed relay (`feed.relay@1`) for a platform with no outbound access

- New package `pkg/feedrelay` and `Kit.ServeFeedRelay()`: a shared (platform) sensor with internet access downloads the signed feed files the platform asks for (api RFC-142) and streams them back, so the platform needs no outbound access. The platform verifies every file against the feed's own pinned root; the relay adds no trust.
- On by default on a shared (platform) sensor with a pinned job-signing key; the host turns it off with `SENSOR_FEED_RELAY=0` (`1` requires it and is a usage error on a sensor that cannot relay). An organization's sensor never relays. The platform offers rounds only to the relay sensors its super administrator designated. Rounds are signed by the platform's job signer (`command_type` `feed_relay`, the platform tenant id, instance scope) and verified with the pinned job-signing keys (`JobGuard.VerifyFeedRelay`); downloads only from the official origins plus `SENSOR_FEED_RELAY_ORIGINS`, through the SSRF-guarded client, with per-file and per-round caps; a pinned file whose digest differs is never uploaded.
- New client methods `NextFeedRelay` (returns the platform's `Retry-After` with an empty answer), `UploadFeedRelayFile`, `FeedRelayDone` (`/api/v2/sensor/feed-relay/...`); `HTTPError.RetryAfterHint`. The relay honours the platform's `Retry-After` (bounded to 1 s - 30 min) and waits 15 minutes after a 403.

### Security: the platform tenant id and the feed relay command type are bound together

- `jobsig` refuses a statement carrying the platform tenant id (nil UUID) unless it is a `feed_relay` on a shared sensor, and a `feed_relay` naming an organization or reaching an organization's sensor. `JobGuard.Check` never admits a `feed_relay` command.
