### Changed: protocol v3 remembers a failing gRPC binding and never downgrades on an identity refusal

- A gRPC network failure (unreachable, handshake, HTTP/2 refused, stream reset, unimplemented) is kept in the certificate directory (`transport-v3-state.json`, 0600): negotiations and restarts within the backoff go straight to the HTTPS binding with the same reason, and gRPC is tried again after 30 minutes, doubling per consecutive failure up to 4 hours (from `ReprobeInterval`). A success clears it.
- A platform that does not offer gRPC (or v3) yet, a certificate or HTTPS-binding failure is asked again within 10 minutes instead of 30, so sensors move up soon after the platform's path is fixed.
- An identity refusal no longer leaves the client on v2: it sends nothing but hello and the heartbeat (a paused sensor still learns it is paused) until a later negotiation is accepted.
