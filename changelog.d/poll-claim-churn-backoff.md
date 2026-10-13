### Fixed: a command handed back is no longer claimed again in a tight loop

- A command the sensor handed back (its hosts busy here, no free slot, a type it does not serve) became claimable again, the platform rang the doorbell and the same command was claimed and released about twice a second. After a poll that only hands commands back, `CommandPoller` now waits 1 s, doubling to at most 1 min (`core.MinClaimBackoff`, `core.MaxClaimBackoff`) with jitter, before polling again; doorbell rings in that time poll once it is over. A command that ends on the sensor, or a poll that starts one, ends the wait, so a command waiting for a busy host still runs as soon as the host is free.
- A poll the platform refuses with `Retry-After` (429/503) is not repeated before it, whatever wakes the poller, capped at 5 min (`core.MaxPollRetryAfter`).

### Added: `core.RetryAfterHinter`

- An error that carries the platform's advised wait. `client.V2Error` (the error of every protocol v2 call, the command poll included) implements it (`RetryAfterHint`).
