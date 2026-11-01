### Changed: `http.identity@1` covers the whole identification feature (no `http.identity@2`)

- v0.45.0 introduced `toolhost.CapabilityHTTPIdentityV2` (`http.identity@2`); it is removed before any sensor advertised it.
  A sensor advertises only `http.identity@1` for locked headers and `user_agent_locked`, the sensor-local `http.headers`,
  the query parameter and the reported identity. An older sensor on `@1` ignores the fields it does not know.
