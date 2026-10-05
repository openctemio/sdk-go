### Added

- **Claim-N** (api RFC-046 §11, RFC-030 §5.9). Against a platform whose
  hello lists `capacity`, `GET /api/v2/sensor/commands` sends
  `X-OpenCTEM-Sensor-Features: capacity` and the platform answers with the
  commands already claimed for this sensor (acknowledged, lease set), at
  most its free slots of scans, in its fair order. `core.Command.Claimed`
  says so; the poller still acknowledges each one it runs (a replay) and
  now **releases** at once any claimed command it does not run (no free
  slot, type not allowed, expired, hosts busy, sensor paused), instead of
  leaving it to its lease. Older platforms and v1 are unchanged.
  `client.WithoutClaimOnPoll()` opts a client out (a caller that polls
  without running what it gets).
