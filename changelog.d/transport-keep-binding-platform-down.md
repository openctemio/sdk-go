### Fixed: a platform restart no longer drops a sensor from protocol v3 to v2

- A negotiation whose hello gets no answer (a platform restart, a gateway
  502, a network error) used to be read as "the platform has no v3": the
  sensor moved to v2 and stayed there until the next recheck. Now a working
  v3 binding is kept, and the negotiation is retried after about 30 seconds.
  An HTTPS-binding hello answered `unavailable` is treated the same way.
- A sensor with no binding yet that gets no answer stays on v2 with the new
  reason `platform_unreachable` (instead of `platform_without_v3`) and asks
  again after about 30 seconds.
