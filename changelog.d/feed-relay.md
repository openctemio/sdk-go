### Added: feed relay (`feed.relay@1`) for a platform with no outbound access

- New package `pkg/feedrelay` and `Kit.ServeFeedRelay()`: a shared (platform) sensor with internet access downloads the signed feed files the platform asks for (api RFC-142) and streams them back, so the platform needs no outbound access. The platform verifies every file against the feed's own pinned root; the relay adds no trust.
- Off unless the host operator sets `SENSOR_FEED_RELAY=1`; only on a shared sensor (a usage error elsewhere). Rounds are signed by the platform's job signer (`command_type` `feed_relay`, the platform tenant id, instance scope) and verified with the pinned job-signing keys (`JobGuard.VerifyFeedRelay`); downloads only from the official origins plus `SENSOR_FEED_RELAY_ORIGINS`, through the SSRF-guarded client, with per-file and per-round caps; a pinned file whose digest differs is never uploaded.
- New client methods `NextFeedRelay`, `UploadFeedRelayFile`, `FeedRelayDone` (`/api/v2/sensor/feed-relay/...`).

### Security: the platform tenant id and the feed relay command type are bound together

- `jobsig` refuses a statement carrying the platform tenant id (nil UUID) unless it is a `feed_relay` on a shared sensor, and a `feed_relay` naming an organization or reaching an organization's sensor. `JobGuard.Check` never admits a `feed_relay` command.
