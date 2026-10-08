### Added: tool.Dial and a default User-Agent; ctx.HTTP() works on a confined sensor

- `ctx.HTTP()` goes through the task's forwarder when the sensor confines the task's network (`OPENCTEM_EGRESS_PROXY`, api RFC-060); before, it dialed directly and had no route there. Its host check still refuses other hosts before anything is sent.
- Its requests carry the User-Agent `openctem-<tool>/<version>` unless the tool sets its own per request (`req.Header.Set("User-Agent", ...)`). Before, they carried Go's default.
- `tool.Dial(ctx, "tcp", addr)` is for tools that speak TCP themselves (port scanners, TLS and protocol probes). It connects through the task's forwarder with HTTP CONNECT on a confined sensor, where a destination that is not a target fails with `tool.ErrEgressRefused`, and directly elsewhere. `tool.EgressProxy()` returns the forwarder, or nil.
