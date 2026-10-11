### Behaviour change: a confined task's rate toward each target host adapts

- The task forwarder paces each destination host with an additive-increase,
  multiplicative-decrease controller (`pkg/adapt.HostRate`): a host starts at
  a quarter of the ceiling, doubles per clean 2-second window up to it, then
  grows by a tenth of the ceiling per clean window; 429 and 503 halve it (at
  most once per window) and `Retry-After` is honored per host (connections are
  held up to 10 s, refused for longer waits); resets, timeouts, refused
  connections on a port that answered before, failed TLS handshakes and a run
  of 20 consecutive 403s after other answers count as failures or a block.
- The ceiling is the lowest of every limit: the tool's rate param (the scan's
  `rate_limit`, already lowered by scan windows, program rules and the local
  policy), `RunOptions.TargetRate`, and the local policy's `rate.max_rps`,
  which now also caps the connection rate of tools without a rate param. The
  rate never goes above the ceiling and never below 1 request per second.
- Five consecutive failures open a host's breaker for 15 s (doubling, ±20 %
  jitter), then one probe is let through; after three trips the host is given
  up for the task. Closed or filtered ports never count, so port scans are
  not slowed.
- Hosts the task could not fully cover (`breaker_open`, `rate_floor`,
  `blocked`) do not fail the task: they are listed in `Outcome.TargetRate`,
  `ScanResult.CoverageGaps` and the command result metadata
  (`coverage_gaps`, `coverage_gaps_total`, `target_rate`), and the scan's
  report declares partial coverage, so findings on those hosts are not
  auto-resolved. Every rate change and its reason is logged to the task.
- All bounds live in one table, `adapt.TargetRate`.
