### Added: sticky slots, connection bound and remote DNS for proxy pools

- A job's first connection to a target host draws its proxy endpoint with
  weight `weight × (0.05 + score²)`, `score` being the job-local EWMA of the
  endpoint's tunnels and handshake time. The host keeps that endpoint for the
  job; it moves only when the endpoint fails as a proxy, never because of a
  target's answer.
- Endpoints take an optional `max_conns` (0: no bound): the job keeps at most
  that many connections open through the endpoint; a connection that finds it
  full waits within its dial timeout.
- `socks5h` endpoints resolve a target the job scoped by name at the proxy
  (remote DNS) after the forwarder checked the name's addresses; address and
  range targets, vendor hosts and every other scheme still go by the checked
  address. New: `egress.WithScopedName` / `egress.TargetScopedByName`.
