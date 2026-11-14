### Added: pacing levels and a throttle tally for scan tools

- `adapt.Pacing` writes the scan pacing levels down once: `PacingGentle`, `PacingStandard` (the default: 20 requests per second and 8 in flight per host, start at 5, host error budget 15) and `PacingFast`. Tool adapters map a level to their own flags; `JobRate` and `BulkHosts` give the process-wide rate and hosts per template of a tool whose rate flag is global.
- `adapt.ThrottleTally` counts 429, 503 and Retry-After answers per target in a tool's own output, for a tool that runs a whole list in one process. Each throttled target becomes a coverage gap with the new reason `adapt.GapThrottled` (`throttled`), with only the counts as detail; `RetryAfter` is the longest wait any target asked for.
- `core.LiveHost.RetryAfter` carries an HTTP probe's Retry-After to that tally; it is never serialised.
- `core.ScanOptions.ChosenSettings` lists the settings keys a person set (tenant, sensor or scan layer), also when the job's or the local policy's caps lowered the value afterwards, so a tool replaces only defaults with its pacing level and keeps every value a person chose.
